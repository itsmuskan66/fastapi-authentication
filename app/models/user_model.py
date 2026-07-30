from sqlalchemy import Column, Integer, String, Boolean, DateTime, JSON
from datetime import datetime
from app.db.database import Base
import uuid
from sqlalchemy import ForeignKey

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    user_email = Column(String, unique=True, nullable=False)
    user_hashed_password = Column(String, nullable=False)

    # access_token DB mein STORE NAHI karte — sirf cookie mein jata hai.
    # refresh_token ek LIST hai (JSON array) — history rakhta hai.
    refresh_token = Column(JSON, nullable=False, default=list)

    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)