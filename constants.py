from urllib.parse import quote_plus

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
DATABASE_NAME = "securityChat"
COLLECTION_NAME = "chats"
MONGO_URI = "mongodb://{}:{}@{}:{}/admin".format(
    quote_plus("admin"),
    quote_plus("CapybaraLoco323%"),
    "129.146.111.32",
    "27017"
)