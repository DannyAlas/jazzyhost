import datetime
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
from minio import Minio
from minio.error import S3Error


from .logging import AxiomHandler

load_dotenv()


class ImageModel:
    """
    Image model class to represent an image in the database
    """
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


################################### LOGGING ###################################
logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s - %(levelname)s: %(message)s"
)
log = logging.getLogger(__name__)


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

###############################################################################


################################## APP INITS ##################################
MinioClient = Minio(
        "s3.danielalas.com",
        access_key= os.getenv("MINIO_ACCESS_KEY"),
        secret_key= os.getenv("MINIO_SECRET_KEY"),
    )
bucket = "public"

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

app = FastAPI()
allow_all = ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_all,
    allow_credentials=True,
    allow_methods=allow_all,
    allow_headers=allow_all,
)
app.mount("/public", StaticFiles(directory="./src/public"), name="public")

###############################################################################


def logged_in(request: Request) -> bool:
    """Helper function to check if user is logged in

    Parameters
    ----------
        request : Request
            FastAPI request object

    Returns
    -------
        bool
            True if user is logged in, False otherwise
    """
    try:
        session_cookie = request.cookies.get("session")
        decoded_claims = auth.verify_session_cookie(session_cookie)
        return True
    except Exception as e:
        log.warning(f"logged_in failed: {e}")
        return False

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

@app.get("/home", include_in_schema=False)
async def home(request: Request):
    log.info(f"home request {request.headers}")
    # return static html file
    return HTMLResponse(content=open("./src/static/index.html", "r").read())


@app.get("/all", include_in_schema=False)
async def all(request: Request):
    log.info(f"all page request {request.headers}")
    # return static html file
    return HTMLResponse(content=open("./src/static/all.html", "r").read())


@app.get("/login", include_in_schema=False)
async def login(request: Request):
    log.info(f"login request {request.headers}")
    cookie = request.cookies.get("session")
    if cookie is not None:
        try:
            auth.verify_session_cookie(cookie, check_revoked=True)
            return RedirectResponse(url="/ui/home")
        except:
            pass
    return HTMLResponse(content=open("./src/static/login.html", "r").read())

@app.post("/api/upload")
async def upload(request: Request):
    log.info(f"upload request {request.headers}")
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
            file[key] = str(_file[key])
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
    if not logged_in(request):
        if file["size"] > 10000000:
            log.warning(f"upload request: File too large")
            return JSONResponse(
                content={"message": "File is too large"}, status_code=400
            )
        if user_ip is not None:
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
        if ext not in ["png", "jpg", "jpeg", "gif", "webp", "mp4", "webm", "mp3", "wav"]:
            return HTTPException(
                detail={"message": "Error! Invalid file type"}, status_code=400
            )

    signed_url = MinioClient.presigned_put_object(bucket_name=bucket, object_name="host/"+image.name, expires=datetime.timedelta(hours=1))
    return JSONResponse(
        content={
            "message": "Successfully uploaded file",
            "signed_url": signed_url,
            "image_params": image.to_encodable_dict(),
        },
        status_code=200,
    )


app.post("/api/confirm/{filename}")
async def confirm_file(filename: str, request: Request):
    log.info(f"confirm request {request.headers}")
    for file in MinioClient.list_objects(bucket, prefix="host/"):
        if file.object_name == "host/" + filename:
            print("public link", MinioClient.presigned_get_object(bucket, file.object_name, expires=datetime.timedelta(days=1)))
            # check that the metadata is public
            if not file.metadata["x-amz-meta-public"] == "true":
                file.metadata["x-amz-meta-public"] = "true"
                MinioClient.copy_object(
                    bucket,
                    file.object_name,
                    bucket,
                    file.object_name,
                    metadata=file.metadata,
                )

            log.info(f"confirm request: {filename} confirmed")
            return JSONResponse(
                content={"message": "Successfully confirmed file"}, status_code=200
            )


    