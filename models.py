from pydantic import BaseModel
class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


class User(BaseModel):
    username: str
    email: str | None = None
    full_name: str | None = None
    disabled: bool | None = None
    hashed_password: str | None = None

class Login(BaseModel):
    username: str
    password: str


class Chat(BaseModel):
    usernameFrom: str | None = None
    usernameTo: str | None = None
    key: int | None = None

class ChatMessage(BaseModel):
    username: str | None = None
    message: str
    timestamp: str | None = None



class UserInDB(User):
    hashed_password: str