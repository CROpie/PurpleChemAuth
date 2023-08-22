from sqlalchemy import Column, Integer, String, Enum

from .database import Base


## Will switch to UUID when moving to postgres DB
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    role = Column(Enum("admin", "user"))
    hashed_password = Column(String)
    user_auth_token = Column(String)
    user_refresh_token = Column(String)
