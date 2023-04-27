import datetime
import json
import os
import uuid

import requests
from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, Request
from fastapi.exceptions import HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from firebase_admin import auth, credentials, initialize_app, storage
from google.cloud import firestore
from PIL import Image

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


class ImageModel:
    def __init__(
        self,
        name,
        extenstion,
        url,
        user_ip,
        user_uid,
        optimized,
        uploaded_at,
        last_seen,
    ):
        self.name = name
        self.extenstion = extenstion
        self.url = url
        self.user_ip = user_ip
        self.user_uid = user_uid
        self.optimized = optimized
        self.uploaded_at = uploaded_at
        self.last_seen = last_seen

    def to_encodable_dict(self):
        """Return the dict representation of the image replacing sentinel values with strings"""
        return {
            "name": self.name,
            "extenstion": self.extenstion,
            "url": self.url,
            "user_ip": self.user_ip,
            "user_uid": self.user_uid,
            "optimized": self.optimized,
            "uploaded_at": "Sentinel value, not used",
            "last_seen": "Sentinel value, not used",
        }

    def to_dict(self):
        return {
            "name": self.name,
            "extenstion": self.extenstion,
            "url": self.url,
            "user_ip": self.user_ip,
            "user_uid": self.user_uid,
            "optimized": self.optimized,
            "uploaded_at": self.uploaded_at,
            "last_seen": self.last_seen,
        }


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
    print(request.headers)
    should_optimize = True
    file = await request.form()
    if file is None or file["file"].size <= 0:
        return HTTPException(detail={"message": "Error! Missing File"}, status_code=400)
    user_ip = request.headers.get("cf-connecting-ip")
    if user_ip is None:
        return HTTPException(
            detail={"message": "Error! Missing User IP", "headers": request.headers},
            status_code=400,
        )
    if not os.path.exists(f"./tmp"):
        os.makedirs(f"./tmp")
    name = str(uuid.uuid4())[:8]
    image = ImageModel(
        name=name,
        extenstion=file["file"].filename.split(".")[-1],
        url=f"{IMAGES_ENPOINT}{name}",
        user_ip=user_ip,
        user_uid=None,
        optimized=False,
        uploaded_at=firestore.SERVER_TIMESTAMP,
        last_seen=firestore.SERVER_TIMESTAMP,
    )
    # if we verify_session_cookie does not throw an error, we are logged in, add the user id to the image object
    try:
        cookie = request.cookies.get("session")
        decoded_claims = auth.verify_session_cookie(cookie, check_revoked=True)
        image.user_uid = decoded_claims["uid"]
        # if the request contains an optimize key, set the optimize flag to true
        if request.headers.get("optimize") is not None:
            should_optimize = [
                True
                if request.headers.get("optimize") in ["true", "True", "TRUE"]
                else False
            ][0]
    except:
        # limit the user to 10MB file uploads
        if file["file"].size > 10000000:
            return JSONResponse(
                content={"message": "File is too large"}, status_code=400
            )
        # if not check that the user has not uploaded more than 10 images in the last hour
        query = (
            db.collection("files")
            .where("user_ip", "==", user_ip)
            .where(
                "uploaded", ">", datetime.datetime.now() - datetime.timedelta(hours=1)
            )
            .stream()
        )
        if len(list(query)) >= 10:
            return HTTPException(
                detail={"message": "Error! Too many uploads"}, status_code=400
            )

    if image.extenstion in ["png", "jpg", "jpeg"] and should_optimize:
        # save the image
        img = Image.open(file["file"].file)
        img.save(f"tmp/{image.name}.{image.extenstion}", optimize=True, quality=50)
        # upload the image
        blob = bucket.blob(image.name)
        blob.upload_from_filename(f"tmp/{image.name}.{image.extenstion}")
        image.optimized = True
        # update the database
        db.collection("files").document(image.name).set(image.to_dict())
        # vercel should remove these automatiaclly, save io ops
        # os.remove(f"tmp/{image.name}.{image.extenstion}")
        return JSONResponse(
            content={
                "message": "Successfully uploaded file",
                "url": image.url,
                "image_params": image.to_encodable_dict(),
            },
            status_code=200,
        )
    else:
        # upload the image
        blob = bucket.blob(image.name)
        blob.upload_from_string(
            file["file"].file.read(), content_type=file["file"].content_type
        )
        # update the database
        db.collection("files").document(image.name).set(image.to_dict())
        return JSONResponse(
            content={
                "message": "Successfully uploaded file",
                "url": image.url,
                "image_params": image.to_encodable_dict(),
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
        files = db.collection("files").get()

        if len(files) > 100:
            # crash the server, just in case spam uploads
            files = fil  # type: ignore

        # sort files by upload date
        try:
            files = sorted(
                files, key=lambda x: x.to_dict()["uploaded_at"], reverse=True
            )
        except:
            pass
        for f in files:
            urls.append(f.to_dict()["url"])

        return JSONResponse(content={"urls": urls}, status_code=200)
    except Exception as e:
        return HTTPException(detail={"message": str(e)}, status_code=401)


# create a background task to compress images every 5 minutes
# async def compress_images():
#     if not os.path.exists("tmp"):
#         os.mkdir("tmp")
#     while True:
#         try:
#             images = db.collection("files").get()

#             for image in images:
#                 if image.to_dict().get("optimized") or image.to_dict().get("extenstion") not in ["jpg", "jpeg", "png"]:
#                     continue
#                 # check if the image link is valid
#                 try:

#                     name = f"tmp/{image.to_dict()['name']}.{image.to_dict()['extenstion']}"
#                     # download the image
#                     with requests.get(image.to_dict()["url"], stream=True) as r:
#                         r.raise_for_status()
#                         with open(name, "wb") as f:
#                             for chunk in r.iter_content(chunk_size=8192):
#                                 f.write(chunk)

#                     # open the image
#                     img = Image.open(name)
#                     # save the image
#                     img.save(name, optimize=True, quality=50)
#                     # upload the image
#                     blob = bucket.blob(image.to_dict()["name"])
#                     blob.upload_from_filename(name)
#                     # update the database
#                     db.collection("files").document(image.id).update({"optimized": True})
#                     # delete the image
#                     os.remove(name)
#                 except Exception as e:
#                     print(e)
#                     continue
#             await asyncio.sleep(1800)
#         except Exception as e:
#             print(e)
#             await asyncio.sleep(1800)

# async def sync_st_db():
#     """
#     Syncs the firestore database with the storage bucket once a day
#     """
#     while True:

#         blobs = bucket.list_blobs()
#         files = db.collection("files").get()
#         print("Syncing database with storage bucket")
#         for blob in blobs:
#             if blob.name not in [file.id for file in files]:
#                 db.collection("files").add({
#                     "name": blob.name,
#                     "url": f"{IMAGES_ENPOINT}{blob.name}",
#                     "extenstion": blob.content_type.split("/")[1],
#                     "optimized": False,
#                     "uploaded": firestore.SERVER_TIMESTAMP
#                     }, document_id=blob.name)

#         for file in files:
#             print(file.to_dict())
#             # if the file doesn't have the same attributes as ImageModel print it
#             if not all([key in file.to_dict() for key in ImageModel.__dict__.keys()]):
#                 fdict = file.to_dict()
#                 try:
#                     new = ImageModel(name=fdict["name"], url=fdict["url"], extenstion=fdict["extenstion"], optimized=fdict["optimized"], uploaded_at=fdict["uploaded"], last_seen=fdict["uploaded"], user_ip="", user_uid="")
#                     db.collection("files").document(file.id).set(new.to_dict())
#                 except Exception as e:
#                     print(e)
#                     continue


#         await asyncio.sleep(100)

# @app.on_event("startup")
# async def startup_event():
#     # create a background task to compress images every 5 minutes
#     futures = [sync_st_db()]
#     asyncio.ensure_future(asyncio.gather(*futures))
