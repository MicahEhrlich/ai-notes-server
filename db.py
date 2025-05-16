from sqlmodel import create_engine, Session
import os

DATABASE_URL = os.getenv("DATABASE_URL")  # Render injects this automatically
engine = create_engine(DATABASE_URL, echo=True)


def get_session():
    with Session(engine) as session:
        yield session
