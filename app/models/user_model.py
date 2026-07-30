from sqlalchemy import Column, Integer, String, Boolean, DateTime
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

    access_token = Column(String, nullable=True)
    refresh_token = Column(String, nullable=True)

    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)



















#     id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
#     token = Column(String, unique=True, index=True, nullable=False)
#     # users.id is an Integer primary key, so user_id should be Integer and reference users.id
#     user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
#     revoked = Column(Boolean, default=False)
#     created_at = Column(DateTime, default=datetime.utcnow)
 
#     # Rotation chain track karne ke liye — pata chalta hai konsa token
#     # kis purane token ki jagah issue hua tha (audit/debugging ke liye).
#     replaced_by = Column(String, nullable=True)

# class RefreshToken(Base):
#     """Har refresh token ka DB record — rotation aur reuse-detection isi table se hoti hai."""
#     __tablename__ = "refresh_tokens"
 
#     id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
#     token = Column(String, unique=True, index=True, nullable=False)
#     # users.id is an Integer primary key, so user_id should be Integer and reference users.id
#     user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
#     revoked = Column(Boolean, default=False)
#     created_at = Column(DateTime, default=datetime.utcnow)
 
#     # Rotation chain track karne ke liye — pata chalta hai konsa token
#     # kis purane token ki jagah issue hua tha (audit/debugging ke liye).
#     replaced_by = Column(String, nullable=True)