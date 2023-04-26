import datetime
import json
import os
import uuid

import requests
from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.exceptions import HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from firebase_admin import auth, credentials, storage, initialize_app
from google.cloud import firestore

load_dotenv()
IMAGES_ENPOINT = "https://i.danielalas.com/"
env_creds = {
    "type": os.getenv("TYPE"),
    "project_id": os.getenv("PROJECT_ID"),
    "private_key_id": os.getenv("PRIVATE_KEY_ID"),
    "private_key": os.getenv("PRIVATE_KEY").replace("\\n", "\n"),
    "client_email": os.getenv("CLIENT_EMAIL"),
    "client_id": os.getenv("CLIENT_ID"),
    "auth_uri": os.getenv("AUTH_URI"),
    "token_uri": os.getenv("TOKEN_URI"),
    "auth_provider_x509_cert_url": os.getenv("AUTH_PROVIDER_X509_CERT_URL"),
    "client_x509_cert_url": os.getenv("CLIENT_X509_CERT_URL"),
}

cred = credentials.Certificate(env_creds)
firebase = initialize_app(cred)
db = firestore.Client.from_service_account_info(env_creds)
bucket = storage.bucket(name=os.getenv("STORAGEBUCKET"))
app = FastAPI()
allow_all = ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_all,
    allow_credentials=True,
    allow_methods=allow_all,
    allow_headers=allow_all,
)


@app.get("/ui", include_in_schema=False)
async def root(request: Request):
    # return static html file
    return HTMLResponse(content=open("./static/index.html", "r").read())


@app.get("/ui/login", include_in_schema=False)
async def login(request: Request):
    cookie = request.cookies.get("session")
    if cookie is not None:
        try:
            auth.verify_session_cookie(cookie, check_revoked=True)
            return HTMLResponse(content=open("./static/index.html", "r").read())
        except:
            pass
    return HTMLResponse(content=open("./static/login.html", "r").read())


@app.post("/login", include_in_schema=False)
async def login(request: Request):
    req_json = await request.json()
    email = req_json["email"]
    password = req_json["password"]

    try:
        # sign in user with email and password
        user = auth.get_user_by_email(email)
        user = auth.get_user(user.uid)
        payload = json.dumps(
            {"email": email, "password": password, "return_secure_token": True}
        )
        FIREBASE_WEB_API_KEY = os.getenv("APIKEY")
        rest_api_url = (
            "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword"
        )
        r = requests.post(
            rest_api_url, params={"key": FIREBASE_WEB_API_KEY}, data=payload
        )
        token = json.loads(r.text)["idToken"]
        # create session cookie
        cookie = auth.create_session_cookie(
            token, expires_in=datetime.timedelta(days=5)
        )
        # return session cookie
        response = JSONResponse(
            content={"message": "Successfully logged in"}, status_code=200
        )
        response.set_cookie(key="session", value=cookie)
        return response

    except Exception as e:
        print(e)
        return HTTPException(
            detail={"message": "There was an error logging in"}, status_code=400
        )


@app.get("/ping", include_in_schema=False)
async def validate(request: Request):
    try:
        cookie = request.cookies.get("session")
        decoded_claims = auth.verify_session_cookie(cookie, check_revoked=True)
        print(f"decoded_claims: {decoded_claims}")
        return JSONResponse(
            content={"message": "Successfully logged in"}, status_code=200
        )
    except Exception as e:
        print(e)
        return HTTPException(
            detail={"message": "There was an error logging in"}, status_code=400
        )


@app.post("/upload")
async def upload(request: Request):
    file = await request.form()

    if file is None:
        return HTTPException(detail={"message": "Error! Missing File"}, status_code=400)
    try:
        cookie = request.cookies.get("session")
        auth.verify_session_cookie(cookie, check_revoked=True)
        # upload file to firebase storage
        id = str(uuid.uuid4())[:8]
        blob = bucket.blob(id)
        blob.upload_from_string(
            file["file"].file.read(), content_type=file["file"].content_type
        )
        db.collection("files").add({"name": id, "url": f"{IMAGES_ENPOINT}{blob.name}"})
        return JSONResponse(
            content={
                "message": "Successfully uploaded file",
                "url": f"{IMAGES_ENPOINT}{blob.name}",
            },
            status_code=200,
        )

    except:
        # get the ip address of the request
        ip = request.client.host
        if ip is None:
            return JSONResponse(
                content={"message": "There was an error uploading the file"},
                status_code=400,
            )
        # check if the ip address is in the database
        doc = db.collection("user").document(ip).get()
        if doc.exists:
            # get the number of attempts
            attempts = doc.to_dict()["attempts"]
            if attempts >= 10:
                return JSONResponse(
                    content={"message": "Too many attempts"}, status_code=400
                )
            # increment the number of attempts
            db.collection("user").document(ip).update({"attempts": attempts + 1})
        else:
            # create a document for the ip address
            db.collection("user").document(ip).set({"attempts": 1})

        # get the file size
        file_size = len(file["file"].file.read())
        if file_size > 10000000:
            return JSONResponse(
                content={"message": "File is too large"}, status_code=400
            )

        id = str(uuid.uuid4())[:8]
        blob = bucket.blob(id)
        blob.upload_from_string(
            file["file"].file.read(), content_type=file["file"].content_type
        )
        db.collection("files").add(
            {"user": ip, "name": id, "url": f"{IMAGES_ENPOINT}{blob.name}"}
        )

        return JSONResponse(
            content={
                "message": "Successfully uploaded file",
                "url": f"{IMAGES_ENPOINT}{blob.name}",
            },
            status_code=200,
        )


# delete file
@app.delete("/delete/{filename}")
async def delete_file(filename: str, request: Request):
    print(filename)
    try:
        cookie = request.cookies.get("session")
        auth.verify_session_cookie(cookie, check_revoked=True)
        blob = bucket.blob(filename)
        blob.delete()
        return JSONResponse(
            content={"message": "Successfully deleted file"}, status_code=200
        )
    except Exception as e:
        print(e)
        return JSONResponse(
            content={"message": "There was an error deleting the file"}, status_code=400
        )


@app.get("/all")
async def get_all(request: Request):
    try:
        cookie = request.cookies.get("session")
        auth.verify_session_cookie(cookie, check_revoked=True)
        urls = []
        blobs = bucket.list_blobs()
        for blob in blobs:
            urls.append(f"{IMAGES_ENPOINT}{blob.name}")
            print(blob.name)
        print(urls)
        return JSONResponse(content={"urls": urls}, status_code=200)
    except:
        return HTTPException(detail={"message": "Not authorized"}, status_code=401)


@app.get("/random")
async def get_random():
    import random

    blobs = bucket.list_blobs()
    urls = []
    for blob in blobs:
        urls.append(f"{IMAGES_ENPOINT}{blob.name}")
    return JSONResponse(content={"url": random.choice(urls)}, status_code=200)
