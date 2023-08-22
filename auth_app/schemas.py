from pydantic import BaseModel


class User(BaseModel):
    id: int
    username: str

    class Config:
        orm_mode = True


class UserInDB(User):
    hashed_password: str
    user_auth_token: str | None = None
    user_refresh_token: str | None = None


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class TokenData(BaseModel):
    id: int | None = None


class InRefreshToken(BaseModel):
    refresh_token: str


class ReturnToken(BaseModel):
    access_token: str
    token_type: str
