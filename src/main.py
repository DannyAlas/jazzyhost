import datetime
import io
import json
import logging
import os
import sys
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
# from google.cloud import logging as google_cloud_logging
from PIL import Image

logging.basicConfig(
    level=logging.DEBUG, format="\n%(asctime)s - %(levelname)s: \n%(message)s \n"
)
log = logging.getLogger(__name__)


def exception_handler(exeption_type, exception, traceback):
    # set the message to me the last lines of the traceback
    log.error(
        f"\tUncaught exception: {exception} \n",
        exc_info=(exeption_type, exception, traceback),
    )


sys.excepthook = exception_handler
# client = google_cloud_logging.Client()
# client.setup_logging()


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
    log.info(f"ui request: {request}")
    # return static html file
    return HTMLResponse(content=open("./src/static/index.html", "r").read())


@app.get("/ui/all", include_in_schema=False)
async def root(request: Request):
    log.info(f"all ui request: {request}")
    # return static html file
    return HTMLResponse(content=open("./src/static/all.html", "r").read())


@app.get("/ui/login", include_in_schema=False)
async def login(request: Request):
    log.info(f"login ui request: {request}")
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
    log.info(f"login request: {request}")
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
        log.info(f"login attempt: {r.text}")
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
        log.warning(f"login attempt failed: {e}")
        return HTTPException(
            detail={"message": "There was an error logging in"}, status_code=400
        )


@app.get("/ping", include_in_schema=False)
async def validate(request: Request):
    log.info(f"ping request: {request}")
    try:
        cookie = request.cookies.get("session")
        decoded_claims = auth.verify_session_cookie(cookie, check_revoked=True)
        log.info(f"ping request: Valid session cookie: {decoded_claims}")
        return JSONResponse(
            content={"message": "healthy and logged in"}, status_code=200
        )
    except Exception as e:
        log.warning(f"ping request: Invalid session cookie")
        return HTTPException(
            detail={"message": "helathy but not logging in"}, status_code=400
        )


@app.post("/upload")
async def upload(request: Request):
    log.info(f"upload request: {request}")
    should_optimize = True
    file = await request.form()
    if file is None or file["file"].size <= 0:
        log.warning(f"upload request: Missing file")
        return HTTPException(detail={"message": "Error! Missing File"}, status_code=400)
    user_ip = request.headers.get("cf-connecting-ip")
    if user_ip is None:
        log.warning(f"upload request: Missing user ip")
        return HTTPException(
            detail={"message": "Error! Missing User IP", "headers": request.headers},
            status_code=400,
        )
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
    log.info(f"upload image: {image.to_dict()}")
    # if we verify_session_cookie does not throw an error, we are logged in, add the user id to the image object
    try:
        cookie = request.cookies.get("session")
        decoded_claims = auth.verify_session_cookie(cookie, check_revoked=True)
        image.user_uid = decoded_claims["uid"]
        log.info(f"upload request: Valid session cookie: {decoded_claims}")
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
            log.warning(f"upload request: File too large")
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
            log.warning(
                f"upload request: Too many uploads, {user_ip} requests = {len(list(query))}"
            )
            return HTTPException(
                detail={"message": "Error! Too many uploads"}, status_code=400
            )

    if image.extenstion in ["png", "jpg", "jpeg"] and should_optimize:
        # save the image
        img = Image.open(file["file"].file)
        log.info(f"upload request: Image size: {img.size}")
        img_byte_arr = io.BytesIO()
        img.save(img_byte_arr, optimize=True, quality=50, format=str(image.extenstion).lower())
        log.info(
            f"upload request: Optimized image size: {img_byte_arr.getbuffer().nbytes}"
        )
        # upload the image
        blob = bucket.blob(image.name)
        blob.upload_from_string(
            img_byte_arr.getvalue(), content_type=file["file"].content_type
        )
        log.info(f"upload request: Uploaded image to bucket")
        image.optimized = True
        # update the database
        db.collection("files").document(image.name).set(image.to_dict())
        log.info(f"upload request: Updated database")
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
        log.info(f"upload request: Not optimizing file")
        blob = bucket.blob(image.name)
        blob.upload_from_string(
            file["file"].file.read(), content_type=file["file"].content_type
        )
        log.info(f"upload request: Uploaded image to bucket")
        # update the database
        db.collection("files").document(image.name).set(image.to_dict())
        log.info(f"upload request: Updated database")
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
    log.info(f"delete request: {request}")
    try:
        cookie = request.cookies.get("session")
        decoded_claims = auth.verify_session_cookie(cookie, check_revoked=True)
        log.info(f"delete request: Valid session cookie: {decoded_claims}")
        blob = bucket.blob(filename)
        if blob is None:
            log.warning(f"delete request: File does not exist IN STORAGE, {filename}")
            return JSONResponse(
                content={"message": "File does not exist"}, status_code=400
            )
        blob.delete()
        log.info(f"delete request: Deleted file from bucket")

        db_file = db.collection("files").document(filename).get()
        if db_file is None:
            log.warning(f"delete request: File does not exist IN DB, {filename}")
            return JSONResponse(
                content={"message": "File does not exist"}, status_code=400
            )
        # delete file from database
        db.collection("files").document(filename).delete()

        return JSONResponse(
            content={"message": "Successfully deleted file"}, status_code=200
        )
    except Exception as e:
        log.warning(f"delete request: {e}")
        return JSONResponse(
            content={"message": "There was an error deleting the file"}, status_code=400
        )


@app.get("/all")
async def get_all(request: Request):
    log.info(f"get all request: {request}")
    try:
        urls = []
        files = db.collection("files").get()
        if len(files) > 100:
            log.error(f"!!!!!!!!!!Too many file - {len(files)} !!!!!!!!!!!")

        # sort files by upload date
        try:
            files = sorted(
                files, key=lambda x: x.to_dict()["uploaded_at"], reverse=True
            )
        except:
            log.warning(f"Failed to sort files: \n{[f.to_dict() for f in files]}\n")
            pass
        for f in files:
            urls.append(f.to_dict()["url"])

        return JSONResponse(content={"urls": urls}, status_code=200)
    except Exception as e:
        return HTTPException(detail={"message": str(e)}, status_code=401)
