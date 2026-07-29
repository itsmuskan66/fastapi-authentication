from sqlalchemy import create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker
DATABASE_URL="postgresql://postgres:Fiesta@localhost:5432/My_app_db"

engine = create_engine(DATABASE_URL, echo=True)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def test_connection():
    try:
        with engine.connect() as connection:
            result = connection.execute(text("SELECT 1"))
            print("Database connection build:", result.scalar())
    except Exception as e:
        print(f"Database connection failed: {e}")


if __name__ == "__main__":
    test_connection()