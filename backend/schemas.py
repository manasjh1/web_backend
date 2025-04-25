# backend/schemas.py
from pydantic import BaseModel, Field, validator, EmailStr
from typing import Optional, Dict, Any
from datetime import datetime

# --- Base Schemas ---
class Phone(BaseModel):
    mobile_number: str = Field(..., min_length=10, max_length=10, pattern=r'^\d{10}$')

class SuccessResponse(BaseModel):
    Status: str
    Details: str

class RegisterSuccessResponse(BaseModel):
    success: bool
    farmer_id: str

# --- Token Schemas (Likely needed by auth_utils) ---
class TokenData(BaseModel):
    sub: Optional[str] = None # Subject (mobile for farmer, email for admin)
    type: Optional[str] = None # 'farmer' or 'admin'
    user_id: Optional[str] = None # Can add user ID here if useful

# --- Farmer Schemas ---
class FarmerCreate(BaseModel):
    # Accept camelCase from frontend using aliases, store as snake_case
    mobile: str = Field(..., min_length=10, max_length=10, pattern=r'^\d{10}$')
    otp: str = Field(..., min_length=6, max_length=6, pattern=r'^\d{6}$')
    full_name: str = Field(..., alias='fullName', min_length=2, max_length=100)
    aadhaar_number: Optional[str] = Field(None, alias='aadhaarNumber', min_length=12, max_length=12, pattern=r'^\d{12}$')
    crop_type: Optional[str] = Field(None, alias='cropType', max_length=50)
    cultivation_area: Optional[str] = Field(None, alias='cultivationArea') # Accept as string initially
    cultivation_unit: Optional[str] = Field(None, alias='cultivationUnit', max_length=20)
    approximate_produce: Optional[str] = Field(None, alias='approximateProduce', max_length=100)
    pin_code: Optional[str] = Field(None, alias='pinCode', min_length=6, max_length=6, pattern=r'^\d{6}$')
    village: Optional[str] = Field(None, alias='village', max_length=100)
    district: Optional[str] = Field(None, alias='district', max_length=100)
    state: Optional[str] = Field(None, alias='state', max_length=50)
    geo_location: Optional[Dict[str, float]] = Field(None, alias='geoLocation') # Expecting {"lat": float, "lng": float}

    class Config:
        orm_mode = True
        allow_population_by_field_name = True # Allow using aliases for input

class FarmerOtpLogin(BaseModel):
    mobile: str = Field(..., min_length=10, max_length=10, pattern=r'^\d{10}$')
    otp: str = Field(..., min_length=6, max_length=6, pattern=r'^\d{6}$')

class FarmerProfile(BaseModel):
    id: str
    full_name: str
    mobile_number: str # Use snake_case for response model consistency
    aadhaar_number: Optional[str] = None
    crop_type: Optional[str] = None
    village: Optional[str] = None
    district: Optional[str] = None
    state: Optional[str] = None
    pin_code: Optional[str] = None
    cultivation_area: Optional[float] = None # Respond with float if possible
    cultivation_unit: Optional[str] = None
    approximate_produce: Optional[str] = None
    geo_location: Optional[Dict[str, float]] = None
    registered_at: datetime
    status: Optional[str] = None
    role: Optional[str] = None

    class Config:
        orm_mode = True # Read data from ORM objects

# --- Admin Schemas ---
class AdminLogin(BaseModel):
    email: EmailStr
    password: str

class AdminProfile(BaseModel):
    id: str # Assuming Admin ID is string, adjust if needed
    email: EmailStr
    full_name: Optional[str] = None
    role: str
    created_at: datetime
    last_login_at: Optional[datetime] = None

    class Config:
        orm_mode = True