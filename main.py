import os
from datetime import datetime, timedelta, timezone
from typing import Optional, List

from fastapi import FastAPI, HTTPException, Depends, status, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from jose import JWTError, jwt
from passlib.context import CryptContext
from bson import ObjectId

from database import db, create_document
from schemas import User as UserSchema, Game as GameSchema

# App and CORS
app = FastAPI(title="Dark Mod Hanan API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Auth settings
SECRET_KEY = os.getenv("JWT_SECRET", "super-secret-key-change")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# Utils
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class TokenData(BaseModel):
    email: Optional[EmailStr] = None

class UserOut(BaseModel):
    name: str
    email: EmailStr
    role: str

class GameOut(BaseModel):
    id: str
    title: str
    description: Optional[str]
    type: str
    cover_image_url: Optional[str]
    play_url: str
    added_by_email: EmailStr


def verify_password(plain_password: str, password_hash: str) -> bool:
    return pwd_context.verify(plain_password, password_hash)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# Database helpers (avoid truthiness on pymongo objects)
USERS = db["user"] if db is not None else None
GAMES = db["game"] if db is not None else None


def user_doc_to_out(doc) -> UserOut:
    return UserOut(name=doc.get("name"), email=doc.get("email"), role=doc.get("role", "user"))


def game_doc_to_out(doc) -> GameOut:
    return GameOut(
        id=str(doc.get("_id")),
        title=doc.get("title"),
        description=doc.get("description"),
        type=doc.get("type"),
        cover_image_url=doc.get("cover_image_url"),
        play_url=doc.get("play_url"),
        added_by_email=doc.get("added_by_email"),
    )


# Dependency to get current user
async def get_current_user(token: str = Depends(oauth2_scheme)) -> UserOut:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception

    user = USERS.find_one({"email": token_data.email}) if USERS is not None else None
    if user is None:
        raise credentials_exception
    return user_doc_to_out(user)


def require_admin(user: UserOut = Depends(get_current_user)) -> UserOut:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return user


# Routes
@app.get("/")
def read_root():
    return {"message": "Dark Mod Hanan API running"}


# Auth Endpoints
class RegisterBody(BaseModel):
    name: str
    email: EmailStr
    password: str


@app.post("/auth/register", response_model=UserOut)
def register(body: RegisterBody):
    if USERS is None:
        raise HTTPException(500, "Database not available")
    existing = USERS.find_one({"email": body.email})
    if existing:
        raise HTTPException(400, "Email already registered")
    user = UserSchema(name=body.name, email=body.email, password_hash=get_password_hash(body.password), role="user")
    _id = create_document("user", user)
    created = USERS.find_one({"_id": ObjectId(_id)})
    return user_doc_to_out(created)


@app.post("/auth/login", response_model=Token)
def login(username: str = Form(...), password: str = Form(...)):
    if USERS is None:
        raise HTTPException(500, "Database not available")
    user = USERS.find_one({"email": username})
    if not user or not verify_password(password, user.get("password_hash", "")):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    access_token = create_access_token({"sub": user["email"], "role": user.get("role", "user")})
    return Token(access_token=access_token)


@app.get("/auth/me", response_model=UserOut)
def me(current: UserOut = Depends(get_current_user)):
    return current


# Game Endpoints
@app.post("/games", response_model=GameOut)
def create_game(game: GameSchema, admin: UserOut = Depends(require_admin)):
    if GAMES is None:
        raise HTTPException(500, "Database not available")
    inserted_id = create_document("game", game)
    created = GAMES.find_one({"_id": ObjectId(inserted_id)})
    return game_doc_to_out(created)


@app.get("/games", response_model=List[GameOut])
def list_games(type: Optional[str] = None):
    if GAMES is None:
        raise HTTPException(500, "Database not available")
    query = {}
    if type in {"pc", "mobile"}:
        query["type"] = type
    docs = GAMES.find(query).sort("created_at", -1)
    return [game_doc_to_out(d) for d in docs]


@app.get("/games/{game_id}", response_model=GameOut)
def get_game(game_id: str):
    if GAMES is None:
        raise HTTPException(500, "Database not available")
    try:
        doc = GAMES.find_one({"_id": ObjectId(game_id)})
    except Exception:
        raise HTTPException(400, "Invalid game id")
    if not doc:
        raise HTTPException(404, "Game not found")
    return game_doc_to_out(doc)


@app.delete("/games/{game_id}")
def delete_game(game_id: str, admin: UserOut = Depends(require_admin)):
    if GAMES is None:
        raise HTTPException(500, "Database not available")
    try:
        res = GAMES.delete_one({"_id": ObjectId(game_id)})
    except Exception:
        raise HTTPException(400, "Invalid game id")
    if res.deleted_count == 0:
        raise HTTPException(404, "Game not found")
    return {"ok": True}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available" if db is None else "✅ Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["collections"] = db.list_collection_names()
    except Exception as e:
        response["database"] = f"⚠️ Error: {str(e)[:80]}"
    return response


# Seed admin on startup
@app.on_event("startup")
def seed_admin():
    if USERS is None:
        return
    # Provided email seems to have a comma; assuming intended .com
    admin_email_candidates = [
        "hanangamingking@gmail.com",
        "hanangamingking@gmail,com"
    ]
    admin_email = None
    for em in admin_email_candidates:
        existing = USERS.find_one({"email": em})
        if existing:
            return
        # set the first as our target for creation
        if admin_email is None and "," not in em:
            admin_email = em
    if admin_email is None:
        admin_email = "hanangamingking@gmail.com"

    admin_password = os.getenv("ADMIN_PASSWORD", "hanan!@#$%")

    user = UserSchema(
        name="Admin",
        email=admin_email,
        password_hash=get_password_hash(admin_password),
        role="admin"
    )
    try:
        create_document("user", user)
    except Exception:
        pass


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
