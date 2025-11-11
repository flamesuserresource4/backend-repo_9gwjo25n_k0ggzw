"""
Database Schemas for Dark Mod Hanan

Each Pydantic model maps to a MongoDB collection (class name lowercased).
"""
from pydantic import BaseModel, Field, EmailStr
from typing import Optional, Literal

class User(BaseModel):
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Email address")
    password_hash: str = Field(..., description="BCrypt hashed password")
    role: Literal["admin", "user"] = Field("user", description="Role of the user")

class Game(BaseModel):
    title: str = Field(..., description="Game title")
    description: Optional[str] = Field(None, description="Game description")
    type: Literal["pc", "mobile"] = Field(..., description="Game type: pc or mobile")
    cover_image_url: Optional[str] = Field(None, description="Thumbnail/cover image URL")
    play_url: str = Field(..., description="Embeddable URL (HTML5 game or external host) to load in iframe")
    added_by_email: EmailStr = Field(..., description="Creator email")
