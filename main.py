import json

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
from sqlmodel import SQLModel, Session, select
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from datetime import datetime, timedelta
from typing import Optional, List
from jose import JWTError, jwt
import os
from fastapi.middleware.cors import CORSMiddleware

from db import engine, get_session
from models import User, Note, NoteCreate
from dotenv import load_dotenv

from schemas import UserCreate, UserLogin

load_dotenv()

# Load environment variables
SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

origins = [
    "http://localhost:5173",
    "https://ai-notes-editor.vercel.app"  # replace with your actual Vercel frontend domain
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,              # or use ['*'] for all origins (not recommended for prod)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    SQLModel.metadata.create_all(engine)


# --- Utility Functions ---

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(token: str = Depends(oauth2_scheme), session: Session = Depends(get_session)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = session.get(User, user_id)
    if user is None:
        raise credentials_exception
    return user


# --- Authentication Endpoints ---

@app.post("/register")
def register_user(user: UserCreate, session: Session = Depends(get_session)):
    user_exists = session.exec(select(User).where(User.username == user.username)).first()
    if user_exists:
        raise HTTPException(status_code=400, detail="Username already registered")

    user = User(username=user.username, hashed_password=get_password_hash(user.password))
    session.add(user)
    session.commit()
    session.refresh(user)
    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content={"message": "User registered successfully"}
    )


@app.post("/login")
def login(user: UserLogin, session: Session = Depends(get_session)):
    user_row = session.exec(select(User).where(User.username == user.username)).first()
    if not user_row or not verify_password(user.password, user_row.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    access_token = create_access_token(data={"sub": str(user_row.id)},
                                       expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": access_token, "token_type": "bearer", "user_id": user_row.id, "username": user_row.username}


@app.post("/token")
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(),  session: Session = Depends(get_session)):
    user_row = session.exec(select(User).where(User.username == form_data.username)).first()
    if not user_row or not verify_password(form_data.password, user_row.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    access_token = create_access_token(data={"sub": str(user_row.id)},
                                       expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": access_token, "token_type": "bearer", "user_id": user_row.id, "username": user_row.username}


# --- Notes Endpoints ---
@app.post("/notes", response_model=Note)
def create_note(note: NoteCreate, user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    serialized_tags = json.dumps(note.tags) if note.tags else "[]"
    new_note = Note(content=note.content, tags=serialized_tags, owner_id=user.id)
    session.add(new_note)
    session.commit()
    session.refresh(new_note)
    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content=jsonable_encoder(new_note)
    )


@app.get("/notes", response_model=List[Note])
def get_notes(user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    notes = session.exec(select(Note).where(Note.owner_id == user.id)).all()
    for note in notes:
        note.tags = json.loads(note.tags) if note.tags else []
    return notes


@app.delete("/notes/{note_id}")
def delete_note(note_id: int, user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    note = session.get(Note, note_id)
    if not note or note.owner_id != user.id:
        raise HTTPException(status_code=404, detail="Note not found or unauthorized")
    session.delete(note)
    session.commit()
    return JSONResponse(
        status_code=status.HTTP_204_NO_CONTENT,
        content={"message": "Note deleted successfully"}
    )


@app.delete("/notes")
def delete_all_notes(user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    notes = session.exec(
        select(Note).where(Note.owner_id == user.id)
    ).all()

    if not notes:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"message": "No notes found for this user"}
        )

    for note in notes:
        session.delete(note)
    session.commit()

    return JSONResponse(
        status_code=status.HTTP_204_NO_CONTENT,
        content={"message": "All notes deleted successfully"}
    )


@app.put("/notes/{note_id}", response_model=Note)
def update_note(
    note_id: int,
    note: NoteCreate,
    user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    db_note = session.exec(
        select(Note).where(Note.id == note_id, Note.owner_id == user.id)
    ).first()

    if not db_note:
        raise HTTPException(status_code=404, detail="Note not found")

    db_note.content = note.content
    db_note.tags = json.dumps(note.tags)
    session.add(db_note)
    session.commit()
    session.refresh(db_note)

    return db_note
