import uuid
import uvicorn
import asyncio
from datetime import datetime, timedelta
from typing import Annotated
from fastapi import Depends, FastAPI, HTTPException, status, WebSocket, WebSocketDisconnect
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pymongo import MongoClient
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import RedirectResponse

from models import Token, TokenData, User, UserInDB, Chat, ChatMessage
from functions import *
from constants import *

client = MongoClient(MONGO_URI)
db = client["securityChat"]
users = db["users"]
chats = db["chats"]

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_userData(users, username: str):
    pipeline = [
        {"$match": {"username": username}},
        {"$project": {"_id": 0}}
    ]

    result = list(users.aggregate(pipeline))

    if result:
        user = result[0]
        user["hashed_password"] = None
        return user
    else:
        return None


def get_user(users, username: str):
    # email or username $or=[{"email": username}, {"username": username}]
    pipeline = [
        {"$match": {"$or": [{"email": username}, {"username": username}]}},
        {"$project": {"_id": 0}}
    ]

    result = list(users.aggregate(pipeline))

    if result:
        return UserInDB(**result[0])
    else:
        return None


def authenticate_user(users, username: str, password: str):
    user = get_user(users, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(hours=12)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(users, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


def existChatBetween(chats, usernameFrom: str, usernameTo: str):
    pipeline = [
        {"$match": {"$or": [{"usernameFrom": usernameFrom, "usernameTo": usernameTo},
                            {"usernameFrom": usernameTo, "usernameTo": usernameFrom}]}},
        {"$project": {"_id": 0}}
    ]

    result = list(chats.aggregate(pipeline))

    if result:
        return True
    else:
        return False


async def get_current_active_user(
        current_user: Annotated[User, Depends(get_current_user)]
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


async def getUserByToken(token: str):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_userData(users, username=username)
    if user is None:
        raise credentials_exception
    return user


async def getKey(chats, _id: str):
    result = chats.find_one({"_id": _id}, {"key": 1})
    if result:
        return int(result["key"])
    else:
        return None


@app.post("/auth/login", response_model=Token)
async def login_for_access_token(
        form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
):
    user = authenticate_user(users, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me/", response_model=User)
async def read_users_me(
        current_user: Annotated[User, Depends(get_current_active_user)]
):
    return current_user


@app.post("/auth/register", response_model=User)
async def create_user(user: User):
    if get_user(users, user.username) is not None or get_user(users, user.email) is not None:
        raise HTTPException(status_code=400, detail="Username already registered")
    user = user.dict()
    user["disabled"] = False
    user["hashed_password"] = get_password_hash(user["hashed_password"])
    user["_id"] = str(uuid.uuid4())
    users.insert_one(user)
    user.pop("hashed_password")
    return user


@app.get("/users/")
async def read_users():
    list_users = list(users.find({"disabled": False}, {"hashed_password": 0}))
    return list_users

@app.put("/users/")
async def update_user(user: User):
    if get_user(users, user.username) is None:
        raise HTTPException(status_code=404, detail="User not found")
    user = user.dict()
    users.update_one({"username": user["username"]}, {"$set": user})
    user.pop("hashed_password")
    return user

@app.delete("/users/{username}")
async def delete_user(username: str):
    if get_user(users, username) is None:
        raise HTTPException(status_code=404, detail="User not found")
    users.delete_one({"username": username})
    return {"message": "User deleted successfully"}

@app.delete("/users/block/{username}")
async def block_user(username: str):
    if get_user(users, username) is None:
        raise HTTPException(status_code=404, detail="User not found")
    users.update_one({"username": username}, {"$set": {"disabled": True}})
    return {"message": "User blocked successfully"}

@app.delete("/users/unblock/{username}")
async def unblock_user(username: str):
    if get_user(users, username) is None:
        raise HTTPException(status_code=404, detail="User not found")
    users.update_one({"username": username}, {"$set": {"disabled": False}})
    return {"message": "User unblocked successfully"}



@app.get("/users/{username}")
async def read_user(username: str):
    user = get_user(users, username)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    user = user.dict()
    user.pop("hashed_password")
    return user

@app.get("/users/noChat/")
async def read_users_noChat(
        current_user: Annotated[User, Depends(get_current_active_user)]
):
    list_users = list(users.find({"disabled": False}, {"hashed_password": 0}))
    list_users_noChat = []
    for user in list_users:
        if not existChatBetween(chats, current_user.username, user["username"]) and current_user.username != user["username"]:
            list_users_noChat.append(user)
    return list_users_noChat

@app.get("/chats/")
async def read_chats(
        current_user: Annotated[User, Depends(get_current_active_user)]
):
    list_chats = list(chats.aggregate([
        {"$match": {"$or": [{"usernameFrom": current_user.username}, {"usernameTo": current_user.username}]}},
    ]))
    return list_chats

@app.post("/chats/", response_model=Chat)
async def create_chat(
        chat: Chat,
        current_user: Annotated[User, Depends(get_current_active_user)]
):
    if existChatBetween(chats, current_user.username, chat.usernameTo):
        raise HTTPException(status_code=400, detail="Chat already exists")
    chat = chat.dict()
    chat["usernameFrom"] = current_user.username
    chat["usernameTo"] = chat["usernameTo"]
    chat["key"] = random.randint(30, 1336)
    chat["_id"] = str(uuid.uuid4())
    chats.insert_one(chat)
    chat.pop("key")
    return chat


@app.post("/chats/{chatId}/messages/", response_model=ChatMessage)
async def create_chat_message(
        chatMessage: ChatMessage,
        chatId: str,
        current_user: Annotated[User, Depends(get_current_active_user)]
):
    chatMessage = chatMessage.dict()
    chatMessage["username"] = current_user.username
    chatMessage["_id"] = str(uuid.uuid4())
    # get a date in the format: 2021-05-30 18:00:00
    now = datetime.now()
    # Formatea la fecha y hora según tu especificación
    formatted_timestamp = now.strftime("%Y-%m-%d %H:%M:%S")
    # Asigna el timestamp al diccionario
    chatMessage["timestamp"] = formatted_timestamp
    #key = await getKey(chats, chatId)
    #chatMessage["message"] = cifradoCesar(key, chatMessage["message"])
    chats.update_one({"_id": chatId}, {"$push": {"messages": chatMessage}})
    return chatMessage


async def get_database():
    client = AsyncIOMotorClient(MONGO_URI)
    db = client[DATABASE_NAME]
    return db


async def listen_to_changes(username, db: AsyncIOMotorDatabase = Depends(get_database)):
    timestamp = None
    while True:
        # Realiza una consulta para verificar cambios
        result = await db[COLLECTION_NAME].aggregate([
            {"$match": {"$or": [{"usernameFrom": username}, {"usernameTo": username}]}},
        ]).to_list(length=1000)
        try:
            return result
        except Exception as e:
            print(f"Error sending message: {e}")
    await asyncio.sleep(1)


@app.websocket("/ws/chat/")
async def websocket_endpoint(websocket: WebSocket, db: AsyncIOMotorDatabase = Depends(get_database)):
    await websocket.accept()
    username = ""
    while True:
        token = await websocket.receive_text()
        userActual = await getUserByToken(token)
        if userActual is None:
            raise HTTPException(status_code=400, detail="Invalid token")
        else:
            username = userActual["username"]
            result = await listen_to_changes(username, db)
            for chat in result:
                messages = chat["messages"] if "messages" in chat else []
                for message in messages:
                    message["message"] = descifradoCesar(int(chat["key"]), message["message"])
            await websocket.send_json(result)
            await websocket.receive_text()

    asyncio.ensure_future(listen_to_changes(username, db))
@app.get("/")
async def get():
    #redirect to the docs
    return RedirectResponse(url='/docs')



if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=3000, reload=True)
