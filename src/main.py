from asyncio import futures
import datetime
import json
import os
import uuid
import asyncio
from PIL import Image
import fastapi
import requests
from dotenv import load_dotenv
from fastapi import FastAPI, Request, BackgroundTasks
from fastapi.exceptions import HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from firebase_admin import auth, credentials, storage, initialize_app
from google.cloud import firestore
from PIL import Image
import io

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
backgound_tasks = BackgroundTasks()
allow_all = ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_all,
    allow_credentials=True,
    allow_methods=allow_all,
    allow_headers=allow_all,
)
app.mount("/public", StaticFiles(directory="./src/public"), name="public")


# on the root endpoint, return the ui if there is nothing after the slash
@app.get("/")
async def root(request: Request):
    return RedirectResponse(url="/ui")

@app.get("/ui", include_in_schema=False)
async def root(request: Request):
    # return static html file
    return HTMLResponse(content=open("./src/static/index.html", "r").read())

@app.get("/ui/all", include_in_schema=False)
async def root(request: Request):
    # return static html file
    return HTMLResponse(content=open("./src/static/all.html", "r").read())

@app.get("/ui/login", include_in_schema=False)
async def login(request: Request):
    cookie = request.cookies.get("session")
    if cookie is not None:
        try:
            auth.verify_session_cookie(cookie, check_revoked=True)
            return RedirectResponse(url="/ui")
        except:
            pass
    return HTMLResponse(content=open("./src/static/login.html", "r").read())


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
        print(r.text)
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
        return JSONResponse(
            content={"message": "healthy and logged in"}, status_code=200
        )
    except Exception as e:
        print(e)
        return HTTPException(
            detail={"message": "helathy but not logging in"}, status_code=400
        )


@app.post("/upload")
async def upload(request: Request):
    file = await request.form()
    if file is None or file["file"].size <= 0:
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
        db.collection("files").add({
            "name": id, 
            "url": f"{IMAGES_ENPOINT}{blob.name}",
            "extenstion": file["file"].filename.split(".")[-1],
            "optimized": False,
            "uploaded": firestore.SERVER_TIMESTAMP
            }, document_id=id)
        return JSONResponse(
            content={
                "message": "Successfully uploaded file",
                "url": f"{IMAGES_ENPOINT}{blob.name}",
            },
            status_code=200,
        )

    except:
        # get the ip address of the user
        ip = request.client.host
        if ip is None:
            return JSONResponse(
                content={"message": "There was an error uploading the file"},
                status_code=400,
            )
        # get the number of attempts in the last 5 minutes
        attempts = db.collection("files").where(
            "uploaded", ">", datetime.datetime.now() - datetime.timedelta(minutes=10)
        ).stream()
        print(list(attempts))
        # if there are more than 10 attempts, return an error
        if len(list(attempts)) > 10:
            return JSONResponse(
                content={"message": "Sorry I've recived to manny uploads recently, try again later"}, status_code=400
            )
        
        # get the file size
        if file["file"].size > 10000000:
            return JSONResponse(
                content={"message": "File is too large"}, status_code=400
            )

        id = str(uuid.uuid4())[:8]
        blob = bucket.blob(id)
        blob.upload_from_string(
            file["file"].file.read(), content_type=file["file"].content_type
        )
        db.collection("files").add({
            "name": id, 
            "url": f"{IMAGES_ENPOINT}{blob.name}",
            "extenstion": file["file"].filename.split(".")[-1],
            "optimized": False,
            "uploaded": firestore.SERVER_TIMESTAMP
            }, document_id=id)

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
    try:
        cookie = request.cookies.get("session")
        auth.verify_session_cookie(cookie, check_revoked=True)
        print(filename)
        blob = bucket.blob(filename)
        blob.delete()
        if blob is None:
            return JSONResponse(
                content={"message": "File does not exist"}, status_code=400
            )

        db_file = db.collection("files").document(filename).get()
        if db_file is None:
            return JSONResponse(
                content={"message": "File does not exist"}, status_code=400
            )
        # delete file from database
        db.collection("files").document(filename).delete()
        

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
        urls = []
        file = db.collection("files").get()
        if len(file) > 100:
            # crash the server, just in case spam uploads
            file = fil # type: ignore
        # sort files by upload date
        file = sorted(file, key=lambda x: x.to_dict()["uploaded"], reverse=False)
        for f in file:
            urls.append(f.to_dict()["url"])

        return JSONResponse(content={"urls": urls}, status_code=200)
    except:
        return HTTPException(detail={"message": "Not authorized"}, status_code=401)


# create a background task to compress images every 5 minutes
async def compress_images():
    if not os.path.exists("tmp"):
        os.mkdir("tmp")
    while True:
        try:
            images = db.collection("files").get()

            for image in images:
                if image.to_dict().get("optimized") or image.to_dict().get("extenstion") not in ["jpg", "jpeg", "png"]:
                    continue
                # check if the image link is valid
                try:

                    name = f"tmp/{image.to_dict()['name']}.{image.to_dict()['extenstion']}"
                    # download the image
                    with requests.get(image.to_dict()["url"], stream=True) as r:
                        r.raise_for_status()
                        with open(name, "wb") as f:
                            for chunk in r.iter_content(chunk_size=8192):
                                f.write(chunk)

                    # open the image
                    img = Image.open(name)
                    # save the image
                    img.save(name, optimize=True, quality=50)
                    # upload the image
                    blob = bucket.blob(image.to_dict()["name"])
                    blob.upload_from_filename(name)
                    # update the database
                    db.collection("files").document(image.id).update({"optimized": True})
                    # delete the image
                    os.remove(name)
                except Exception as e:
                    print(e)
                    continue
            await asyncio.sleep(1800)
        except Exception as e:
            print(e)
            await asyncio.sleep(1800)

async def sync_st_db():
    """
    Syncs the firestore database with the storage bucket once a day
    """
    while True:
        blobs = bucket.list_blobs()
        files = db.collection("files").get()
        for blob in blobs:
            if blob.name not in [file.id for file in files]:
                db.collection("files").add({
                    "name": blob.name, 
                    "url": f"{IMAGES_ENPOINT}{blob.name}",
                    "extenstion": blob.to_dict()["contentType"].split("/")[-1],
                    "optimized": False,
                    "uploaded": firestore.SERVER_TIMESTAMP
                    }, document_id=blob.name)

        for file in files:
            if file.to_dict()["name"] not in [blob.name for blob in blobs]:
                file.delete()

        
        await asyncio.sleep(86400)

@app.on_event("startup")
async def startup_event():
    # create a background task to compress images every 5 minutes
    futures = [compress_images(), sync_st_db()]
    asyncio.ensure_future(asyncio.gather(*futures))

    
        

