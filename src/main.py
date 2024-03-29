import datetime
import io
import json
import logging
import os
import re
import sys
import uuid

import axiom
import requests
from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, Request
from fastapi.exceptions import HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from firebase_admin import auth, credentials, initialize_app, storage
from google.cloud import firestore
from PIL import Image

from .logging import AxiomHandler

load_dotenv()

logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s - %(levelname)s: %(message)s"
)

log = logging.getLogger(__name__)

# set the handler to send logs to axiom
axiom_token = os.getenv("AXIOM_API_TOKEN")
if axiom_token is None:
    raise ValueError("AXIOM_API_TOKEN not set")
ax_client = axiom.Client(
    token=os.getenv("AXIOM_API_TOKEN"), org_id=os.getenv("AXIOM_ORG_ID")
)
axiom_handler = AxiomHandler(ax_client, "logs", level=logging.DEBUG, interval=1)
log.addHandler(axiom_handler)


def exception_handler(exeption_type, exception, traceback):
    # set the message to me the last lines of the traceback
    log.error(
        f"Uncaught exception: {exception}",
        exc_info=(exeption_type, exception, traceback),
    )


sys.excepthook = exception_handler
STORAGE_FOLDER = os.getenv("STORAGE_FOLDER")
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
# bucket = storage.bucket(name=os.getenv("STORAGEBUCKET"))
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
        extension,
        url,
        user_ip,
        user_uid,
        optimized,
        uploaded_at,
        last_seen,
        confirmed,
    ):
        self.name = name
        self.extension = extension
        self.url = url
        self.user_ip = user_ip
        self.user_uid = user_uid
        self.optimized = optimized
        self.uploaded_at = uploaded_at
        self.last_seen = last_seen
        self.confirmed = confirmed

    def to_encodable_dict(self):
        """Return the dict representation of the image replacing sentinel values with strings"""
        return {
            "name": self.name,
            "extension": self.extension,
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
            "extension": self.extension,
            "url": self.url,
            "user_ip": self.user_ip,
            "user_uid": self.user_uid,
            "optimized": self.optimized,
            "uploaded_at": self.uploaded_at,
            "last_seen": self.last_seen,
        }


# on the root endpoint, return the ui if there is nothing after the slash else return the static file
@app.get("/{filename}")
async def media(request: Request, filename: str):
    log.info(f"root request {request.headers}")
    # if the filename contains a dot, it is a file, return the file
    if "." in filename:
        try:
            if os.path.exists(f"{STORAGE_FOLDER}{filename}"):
                # update the last seen time and increment the view count in the database
                db_file = db.collection("files").document(filename).get().to_dict()
                db_file["last_seen"] = firestore.SERVER_TIMESTAMP
                db_file["views"] = db_file["views"] + 1
                return FileResponse(f"{STORAGE_FOLDER}{filename}")
            else:
                return RedirectResponse(url=f"/ui/{filename}")
        except:
            return RedirectResponse(url="/ui/home")
    else:
        return RedirectResponse(url=f"/ui/{filename}")

@app.get("/ui/home", include_in_schema=False)
async def home(request: Request):
    log.info(f"home request {request.headers}")
    # return static html file
    return HTMLResponse(content=open("./src/static/index.html", "r").read())


@app.get("/ui/all", include_in_schema=False)
async def all(request: Request):
    log.info(f"all page request {request.headers}")
    # return static html file
    return HTMLResponse(content=open("./src/static/all.html", "r").read())


@app.get("/ui/login", include_in_schema=False)
async def login(request: Request):
    log.info(f"login request {request.headers}")
    cookie = request.cookies.get("session")
    if cookie is not None:
        try:
            auth.verify_session_cookie(cookie, check_revoked=True)
            return RedirectResponse(url="/home")
        except:
            pass
    return HTMLResponse(content=open("./src/static/login.html", "r").read())


@app.post("/api/login", include_in_schema=False)
async def login(request: Request):
    log.info(f"login request {request.headers}")
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


@app.get("/api/ping", include_in_schema=False)
async def validate(request: Request):
    log.info(f"ping request {request.headers}")
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


@app.post("/api/upload")
async def upload(request: Request):
    log.info(f"upload request {request.headers}")
    should_optimize = True
    _file = await request.form()
    # unpack file from form
    file = {}
    for key in _file.keys():
        if key == "size":
            file[key] = int(_file[key])
        if key == "file":
            file[key] = _file[key]
        if key == "lastModified":
            file[key] = int(_file[key])
        if key == "name":
            file[key] = _file[key]
        if key == "type":
            file[key] = _file[key]
        if key == "webkitRelativePath":
            file[key] = _file[key]
        if key == "lastModifiedDate":
            file[key] = datetime.datetime.strptime(
                _file[key], "%a %b %d %Y %H:%M:%S GMT%z (%Z)"
            )
    if file is None or file["size"] == 0:
        log.warning(f"upload request: Missing file")
        return HTTPException(detail={"message": "Error! Missing File"}, status_code=400)
    user_ip = request.headers.get("cf-connecting-ip")
    if user_ip is None:
        log.warning(f"upload request: Missing user ip")
    name = str(uuid.uuid4())[:8]
    ext = file["name"].split(".")[-1]
    image = ImageModel(
        name=name + "." + ext,
        extension=ext,
        url=f"{IMAGES_ENPOINT}{name}",
        user_ip=user_ip,
        user_uid=None,
        optimized=False,
        uploaded_at=firestore.SERVER_TIMESTAMP,
        last_seen=firestore.SERVER_TIMESTAMP,
        confirmed=False,
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
        if file["size"] > 10000000:
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

    if image.extension in ["png", "jpg", "jpeg"] and should_optimize:
        # save the image
        # img = Image.open(file["file"].file).convert("RGB")
        # log.info(f"upload request: Image size: {img.size}")
        # img_byte_arr = io.BytesIO()
        # img.save(img_byte_arr, optimize=True, quality=50, format="jpeg")
        # log.info(
        #     f"upload request: Optimized image size: {img_byte_arr.getbuffer().nbytes}"
        # )
        # upload the image
        with open(f"{STORAGE_FOLDER}{image.name}", "wb") as f:
            f.write(file["file"].file.read())
        signed_url = IMAGES_ENPOINT + image.name
        image.optimized = True
        # update the database
        db.collection("files").document(image.name).set(image.to_dict())
        log.info(f"upload request: Updated database")
        return JSONResponse(
            content={
                "message": "Successfully uploaded file",
                "signed_url": signed_url,
                "image_params": image.to_encodable_dict(),
            },
            status_code=200,
        )
    else:
        # upload the image
        log.info(f"upload request: Not optimizing file")
        with open(f"{STORAGE_FOLDER}{image.name}", "wb") as f:
            f.write(file["file"].file.read())
        signed_url = IMAGES_ENPOINT + image.name
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


app.post("/api/confirm/{filename}")
async def confirm_file(filename: str, request: Request):
    log.info(f"confirm request {request.headers}")
    try:
        db_file = db.collection("files").document(filename).get()
        if db_file is None:
            log.warning(f"confirm request: File does not exist IN DATABASE, {filename}")
            return JSONResponse(
                content={"message": "File does not exist"}, status_code=400
            )
        db.collection("files").document(filename).update({"confirmed": True})
        log.info(f"confirm request: Updated database")
        return JSONResponse(
            content={"message": "Successfully confirmed file"}, status_code=200
        )
    except:
        log.warning(f"confirm request: Server Error")
        return JSONResponse(content={"message": "Server Error"}, status_code=400)


# delete file
@app.delete("/api/delete/{filename}")
async def delete_file(filename: str, request: Request):
    log.info(f"delete request {request.headers}")
    try:
        cookie = request.cookies.get("session")
        decoded_claims = auth.verify_session_cookie(cookie, check_revoked=True)
        log.info(f"delete request: Valid session cookie: {decoded_claims}")
        blob = os.path.abspath(f"{STORAGE_FOLDER}{filename}")
        
        if not os.path.exists(blob):
            log.warning(f"delete request: File does not exist IN STORAGE, {filename}")
            return JSONResponse(
                content={"message": "File does not exist"}, status_code=400
            )
        # delete file from storage
        os.remove(blob)
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


@app.get("/api/all")
async def get_all(request: Request):
    log.info(f"get all request {request.headers}")
    try:
        files_list = []
        files = db.collection("files").get()

        if len(files) > 100:
            log.error(f"!!!!!!!!!!Too many files - {len(files)} !!!!!!!!!!!")

        # sort files by upload date
        try:
            files = sorted(
                files, key=lambda x: x.to_dict()["uploaded_at"], reverse=True
            )

        except:
            log.warning(f"Failed to sort files: \n{[f.to_dict() for f in files]}\n")
            pass
        for f in files:
            try:
                # serialize the file object DateTime object
                f_dict = f.to_dict()
                for key, value in f_dict.items():
                    if isinstance(value, datetime.datetime):
                        f_dict[key] = value.isoformat()
                files_list.append(f_dict)
            except:
                log.warning(f"Failed to get url for file: {f.to_dict()}")

        return JSONResponse(content={"files": files_list}, status_code=200)
    except Exception as e:
        return HTTPException(detail={"message": str(e)}, status_code=401)


@app.get("/api/random")
def get_random_image(request: Request):
    import random

    log.info(f"get random request {request.headers}")
    try:
        files = db.collection("files").get()
        files = [f.to_dict() for f in files]
        random_file = random.choice(files)
        return RedirectResponse(url=random_file["url"], status_code=302)
    except Exception as e:
        return HTTPException(detail={"message": str(e)}, status_code=401)
