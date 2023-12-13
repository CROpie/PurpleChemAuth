from datetime import datetime, timedelta
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, status, Form
from fastapi.security import (
    OAuth2PasswordBearer,
    OAuth2PasswordRequestForm,
    HTTPBearer,
    HTTPAuthorizationCredentials,
)
from fastapi.middleware.cors import CORSMiddleware

from jose import JWTError, jwt
from passlib.context import CryptContext

import json

from sqlalchemy.orm import Session
from . import models, schemas

from .database import SessionLocal, engine

models.Base.metadata.create_all(bind=engine)

from dotenv import load_dotenv
import os

app = FastAPI()


# Dependencies
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


http_bearer = HTTPBearer()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

### ENV ###

load_dotenv()

SECRET_KEY = os.environ.get("SECRET_KEY")
SECRET_REFRESH_KEY = os.environ.get("SECRET_REFRESH_KEY")
ALGORITHM = os.environ.get("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = 45
REFRESH_TOKEN_EXPIRE_HOURS = 24


origins = [
    "http://localhost:5173",
    "https://purple-chem.vercel.app/",
    "https://purple-chem-updated.vercel.app/",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)


### AUTHENTICATE A USER ###
async def validate_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(http_bearer),
    db: Session = Depends(get_db),
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id_role = payload.get("sub")
        user_id_role_dict = json.loads(user_id_role)
        id = user_id_role_dict["id"]
        role = user_id_role_dict["role"]
        if id is None:
            raise credentials_exception
        token_data = schemas.TokenData(id=id)
    except JWTError:
        raise credentials_exception
    user = db.query(models.User).filter(models.User.id == token_data.id).first()
    if user is None:
        raise credentials_exception
    return user


### AUTHENTICATE AN ADMIN ###
async def validate_current_admin(
    credentials: HTTPAuthorizationCredentials = Depends(http_bearer),
    db: Session = Depends(get_db),
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id_role = payload.get("sub")
        user_id_role_dict = json.loads(user_id_role)
        id = user_id_role_dict["id"]
        role = user_id_role_dict["role"]
        if id is None:
            raise credentials_exception
        if role != "admin":
            raise credentials_exception
        token_data = schemas.TokenData(id=id)
    except JWTError:
        raise credentials_exception
    user = db.query(models.User).filter(models.User.id == token_data.id).first()
    if user is None:
        raise credentials_exception
    return user


### CREATE A NEW USER ###


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user_by_username(db: Session, username: str):
    return db.query(models.User).filter(models.User.username == username).first()


@app.post("/newuser", response_model=schemas.User)
async def create_user(
    username: Annotated[str, Form()],
    password: Annotated[str, Form()],
    role: Annotated[str, Form()],
    current_user: Annotated[models.User, Depends(validate_current_admin)],
    db: Session = Depends(get_db),
):
    db_user = get_user_by_username(db, username)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = get_password_hash(password)
    db_user = models.User(username=username, hashed_password=hashed_password, role=role)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


### Need to make a way to add someone without being authorized! ###
@app.post("/seedauthadmin", response_model=schemas.User)
async def create_user(
    username: Annotated[str, Form()],
    password: Annotated[str, Form()],
    db: Session = Depends(get_db),
):
    db_user = get_user_by_username(db, username)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = get_password_hash(password)
    db_user = models.User(
        username=username, hashed_password=hashed_password, role="admin"
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


### AUTHENTICATE AND RETURN TOKEN ###


def create_access_token(data: dict, KEY: str, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_user(db: Session, username: str):
    return db.query(models.User).filter(models.User.username == username).first()


def authenticate_user(db: Session, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


# * the value of "sub" needs to be a string, or jwt.decode will fail
@app.post("/token", response_model=schemas.Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Session = Depends(get_db),
):
    print(form_data.username, form_data.password)
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user_id_role = {"id": user.id, "role": user.role}
    sub_json = json.dumps(user_id_role)
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": sub_json}, KEY=SECRET_KEY, expires_delta=access_token_expires
    )

    ## REFRESH TOKEN

    refresh_token_expires = timedelta(hours=REFRESH_TOKEN_EXPIRE_HOURS)
    refresh_token = create_access_token(
        data={"sub": str(user.id)},
        KEY=SECRET_REFRESH_KEY,
        expires_delta=refresh_token_expires,
    )
    user.user_auth_token = access_token
    user.user_refresh_token = refresh_token
    db.commit()

    ## UPDATE USER WITH ACCESS TOKEN, THEN RETURN THE USER AND INCLUDE IN THE REUTURN OBJECT
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "role": user.role,
        "token_type": "bearer",
    }


def get_user_by_refresh_token(db: Session, refresh_token: str):
    user = (
        db.query(models.User)
        .filter(models.User.user_refresh_token == refresh_token)
        .first()
    )
    print(user)
    return user


@app.post("/refreshtoken", response_model=schemas.ReturnToken)
async def use_refresh_token(
    refresh_token: Annotated[str, Form()], db: Session = Depends(get_db)
):
    user = get_user_by_refresh_token(db=db, refresh_token=refresh_token)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token didn't match",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user_id_role = {"id": user.id, "role": user.role}
    sub_json = json.dumps(user_id_role)
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": sub_json}, KEY=SECRET_KEY, expires_delta=access_token_expires
    )
    return {
        "access_token": access_token,
        "token_type": "bearer",
    }


@app.post("/logout")
async def logout(refresh_token: Annotated[str, Form()], db: Session = Depends(get_db)):
    user = get_user_by_refresh_token(db=db, refresh_token=refresh_token)
    user.user_auth_token = None
    user.user_refresh_token = None
    db.commit()


@app.post("/csvusers/", response_model=list[schemas.ReturnCSVUser])
async def create_csv_users(
    userAuthList: list[schemas.CSVUser],
    current_user: Annotated[models.User, Depends(validate_current_admin)],
    db: Session = Depends(get_db),
):
    for user in userAuthList:
        db_user = get_user_by_username(db, user.username)
        if db_user:
            user.id = db_user.id
        else:
            user.hashed_password = get_password_hash(user.password)
            newUser = models.User(
                username=user.username,
                hashed_password=user.hashed_password,
                role=user.role,
            )
            db.add(newUser)
            db.commit()
            db.refresh(newUser)
            user.id = newUser.id

    return userAuthList


@app.get("/getusers/", response_model=list[schemas.ReturnCSVUser])
def get_users(
    current_user: Annotated[models.User, Depends(validate_current_admin)],
    db: Session = Depends(get_db),
):
    usersList = db.query(models.User).all()
    data = usersList
    return data
