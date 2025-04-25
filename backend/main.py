# backend/main.py
# Version 1.3.3 - Includes fix for TypeError and updated logic

import random
import logging
import os
import requests # Ensure 'requests' is installed (pip install requests)
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict

from fastapi import FastAPI, HTTPException, Depends, status, Response
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy import text # Required for db health check

# --- Project Imports ---
# Ensure these modules exist and are correctly structured
try:
    from database import get_db, engine
    import models
    from models import Farmer as FarmerDB
    from models import AdminUser as AdminUserDB
    import schemas
    import auth_utils
except ImportError as e:
    print(f"FATAL ERROR: Failed to import project modules: {e}")
    print("Please ensure database.py, models.py, schemas.py, and auth_utils.py exist and are importable.")
    raise SystemExit(f"ImportError: {e}")

# --- Basic Logging Configuration ---
# Sets up logging to show INFO level messages and above
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s', # Slightly improved format
    datefmt='%Y-%m-%d %H:%M:%S'
)
log = logging.getLogger(__name__) # Logger for this module

# --- Create DB Tables (on startup) ---
try:
    log.info("Attempting to create database tables if they don't exist...")
    models.Base.metadata.create_all(bind=engine)
    log.info("Database tables checked/created successfully.")
except Exception as e:
    log.critical(f"FATAL: Error creating database tables: {e}", exc_info=True)
    raise SystemExit("Database table creation failed, cannot start.")

# --- FastAPI Application Setup ---
app = FastAPI(
    title="Kisan Manch API",
    description="API for Kisan Manch Farmer (OTP Login/Registration) and Admin (Password Login).",
    version="1.3.3"
)

# --- CORS Middleware Configuration ---
default_origins = "http://localhost:3000,https://kisan-manch.vercel.app" # Default origins
allowed_origins_str = os.getenv("ALLOWED_ORIGINS", default_origins)
allowed_origins = [origin.strip() for origin in allowed_origins_str.split(',') if origin.strip()]
if not allowed_origins: # Fallback if env var is empty
    allowed_origins = [origin.strip() for origin in default_origins.split(',') if origin.strip()]

log.info(f"CORS configuration: Allowing origins: {allowed_origins}")
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True, # Essential for cookies
    allow_methods=["*"],    # Allows all standard HTTP methods
    allow_headers=["*"],    # Allows all headers
)

# --- Configuration & In-Memory OTP Store ---
TWOFACTOR_API_KEY = os.getenv("TWOFACTOR_API_KEY")
if not TWOFACTOR_API_KEY:
    log.warning("TWOFACTOR_API_KEY env var not set. OTP SMS sending is disabled.")
# --- !!! WARNING: Use Redis or DB for OTPs in production !!! ---
otp_store: Dict[str, str] = {} # Simple in-memory dict
log.warning("SECURITY WARNING: Using IN-MEMORY OTP store (NOT suitable for production).")

# --- Helper Function ---
def generate_farmer_id() -> str:
    """Generates a unique farmer ID (simple timestamp + random). Consider UUIDs."""
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
    random_num = random.randint(1000, 9999)
    return f"KM{timestamp}{random_num}"

# =========================== API ENDPOINTS ===========================

# --- Health Check ---
@app.get("/health", tags=["System"], status_code=status.HTTP_200_OK)
async def health_check(db: Session = Depends(get_db)):
    """Performs health check including basic database connectivity."""
    db_ok = False
    try:
        # Test database connection with a simple query
        db.execute(text("SELECT 1"))
        db_ok = True
        log.debug("Health check DB query successful.")
    except Exception as e:
         log.error(f"Health check DB connection error: {e}", exc_info=False) # Avoid traceback flood

    status_info = {"status": "healthy" if db_ok else "unhealthy"}
    status_info["db_connection"] = "ok" if db_ok else "failed"
    status_info["timestamp"] = datetime.now(timezone.utc).isoformat()
    return status_info

# --- Send OTP ---
@app.post("/send-otp", response_model=schemas.SuccessResponse, tags=["OTP"], status_code=status.HTTP_200_OK)
async def send_otp_route(data: schemas.Phone):
    """Generates OTP, stores it in memory, and attempts SMS send via 2Factor."""
    mobile_number = data.mobile_number
    masked_mobile = f"******{mobile_number[-4:]}"
    log.info(f"OTP Request received for: {masked_mobile}")

    otp = ''.join([str(random.randint(0, 9)) for _ in range(6)]) # Generate 6-digit OTP
    otp_store[mobile_number] = otp # Store it (will be lost on restart)
    log.info(f"Generated and stored OTP for {masked_mobile}: {otp}") # !!! REMOVE OTP FROM LOGS IN PRODUCTION !!!

    sms_sent = False
    if not TWOFACTOR_API_KEY:
        log.warning(f"SMS sending skipped for {masked_mobile} (NO API KEY)")
        return {"Status": "Success (Simulation)", "Details": f"OTP generated for {masked_mobile}. SMS sending skipped (No API Key)."}
    else:
        try:
            # ==========================================================================
            # !! ACTION REQUIRED: CONFIGURE THIS !!
            # 1. Replace 'YourAppNameTemplate' with your valid 2Factor template name.
            # 2. OR, if you don't use named templates, set template_name = None
            #    and ensure the URL doesn't include the template part.
            # ==========================================================================
            template_name = "YourAppNameTemplate"  # <--- REPLACE THIS or set to None

            base_url = f"https://2factor.in/API/V1/{TWOFACTOR_API_KEY}/SMS/{mobile_number}/{otp}"
            request_url = f"{base_url}/{template_name}" if template_name else base_url
            log_template = template_name if template_name else "(No Template Used)"

            log.info(f"Attempting SMS via 2Factor for {masked_mobile} using template: {log_template}...")
            response = requests.get(request_url, timeout=15)
            response.raise_for_status() # Check for HTTP errors (4xx/5xx)

            response_json = response.json()
            log.info(f"2Factor API response for {masked_mobile}: Status='{response_json.get('Status')}', Details='{response_json.get('Details')}'")

            if response_json.get("Status") == "Success":
                sms_sent = True
                log.info(f"Successfully requested SMS dispatch for {masked_mobile}.")
            else:
                log.error(f"2Factor reported SMS failure for {masked_mobile}: {response_json.get('Details', 'No details provided')}")

        # --- Specific error handling ---
        except requests.exceptions.Timeout: log.error(f"Timeout contacting 2Factor API for {masked_mobile}.")
        except requests.exceptions.HTTPError as e: log.error(f"HTTP error from 2Factor API for {masked_mobile}: {e.response.status_code} {e.response.text}")
        except requests.exceptions.RequestException as e: log.error(f"Network error contacting 2Factor API for {masked_mobile}: {e}")
        except Exception as e: log.error(f"Unexpected error during 2Factor communication for {masked_mobile}: {e}", exc_info=True)

    # --- Return response to client ---
    status_detail = f"OTP generated for {masked_mobile}."
    if sms_sent: status_detail = f"OTP sent successfully via SMS provider to {masked_mobile}."
    elif TWOFACTOR_API_KEY: status_detail += " Problem encountered sending SMS (see server logs)." # Note issue if key exists

    return {"Status": "Success", "Details": status_detail}

# --- Register Farmer ---
@app.post(
    "/api/register",
    response_model=schemas.RegisterSuccessResponse,
    tags=["Farmer Auth & Registration"],
    status_code=status.HTTP_201_CREATED,
    summary="Register a new farmer after OTP verification"
)
async def register_farmer_endpoint(data: schemas.FarmerCreate, db: Session = Depends(get_db)):
    """Handles farmer registration including OTP check and database insertion."""
    mobile_number = data.mobile # Pydantic model uses 'mobile'
    submitted_otp = data.otp
    masked_mobile = f"******{mobile_number[-4:]}"
    log.info(f"Registration Attempt: mobile={masked_mobile}")
    log.debug(f"Registration Data Received (Raw Schema): {data}")

    # 1. Verify OTP
    stored_otp = otp_store.get(mobile_number)
    if not stored_otp:
        log.warning(f"Registration Failure ({masked_mobile}): OTP not found in store (expired?).")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="OTP not found or has expired. Please request again.")
    if stored_otp != submitted_otp:
        log.warning(f"Registration Failure ({masked_mobile}): Invalid OTP submitted.")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid OTP provided.")
    log.info(f"OTP verified successfully for registration ({masked_mobile}).")

    # 2. Check Database for Existing User
    try:
        existing_mobile = db.query(FarmerDB).filter(FarmerDB.mobile_number == mobile_number).first()
        if existing_mobile:
            log.warning(f"Registration Conflict ({masked_mobile}): Mobile number already exists.")
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="This mobile number is already registered.")
        if data.aadhaar_number:
             # Check Aadhaar only if provided (assumes UNIQUE constraint in DB model)
             existing_aadhaar = db.query(FarmerDB).filter(FarmerDB.aadhaar_number == data.aadhaar_number).first()
             if existing_aadhaar:
                  log.warning(f"Registration Conflict ({masked_mobile}): Aadhaar already exists.")
                  raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="This Aadhaar number is already registered.")
    except SQLAlchemyError as e:
         log.error(f"Database error checking existing user ({masked_mobile}): {e}", exc_info=True)
         raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error checking user registry.")

    # 3. Generate Unique Farmer ID
    farmer_id = generate_farmer_id()

    # 4. Prepare Data and Save to Database
    try:
        # --- Correct Mapping from Pydantic 'data' to DB model attributes ---
        db_data_to_save = {
            "id": farmer_id,
            "full_name": data.full_name,
            "mobile_number": data.mobile, # <- Map data.mobile to models.Farmer.mobile_number
            "aadhaar_number": data.aadhaar_number,
            "crop_type": data.crop_type,
            "village": data.village,
            "district": data.district,
            "state": data.state,
            "pin_code": data.pin_code,
            "cultivation_unit": data.cultivation_unit,
            "approximate_produce": data.approximate_produce,
            "geo_location": data.geo_location,
            # cultivation_area needs potential conversion
        }

        # Safely convert cultivation_area (string input) to Numeric/Decimal for DB
        cultivation_area_val = None
        if data.cultivation_area is not None:
            try:
                cultivation_area_val = float(data.cultivation_area.strip()) # Use float for Decimal/Numeric
            except (ValueError, TypeError):
                 log.warning(f"Invalid 'cultivation_area' format ('{data.cultivation_area}') for {masked_mobile}. Saving as NULL.")
        db_data_to_save['cultivation_area'] = cultivation_area_val # Add converted or None value

        log.debug(f"Data prepared for DB insertion ({masked_mobile}): {db_data_to_save}")

        # Create the SQLAlchemy model instance
        db_farmer = FarmerDB(**db_data_to_save)

        db.add(db_farmer)  # Add to session
        db.commit()       # Commit transaction
        db.refresh(db_farmer) # Get DB-generated values (like registered_at)
        log.info(f"DATABASE: Farmer registered successfully. ID: {farmer_id}, Mobile: {masked_mobile}")

        # 5. Clean up OTP from store AFTER successful commit
        if mobile_number in otp_store:
            try: del otp_store[mobile_number]
            except KeyError: pass
            log.info(f"OTP for {masked_mobile} cleared from store post-registration.")

        return {"success": True, "farmer_id": farmer_id} # Return success response

    # --- Handle Database Errors During Commit ---
    except IntegrityError as e:
         db.rollback() # Rollback failed transaction
         e_str = str(e.orig).lower() # Get original DB error details
         detail = "A user might already exist with this Mobile Number or Aadhaar Number."
         if 'mobile_number' in e_str or 'uq_farmer_mobile' in e_str: detail = "This mobile number is already registered."
         elif 'aadhaar_number' in e_str or 'uq_farmer_aadhaar' in e_str: detail = "This Aadhaar number is already registered."
         log.warning(f"Database Integrity Error on registration ({masked_mobile}): {detail}. DB Msg: {e.orig}")
         raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=detail)
    except SQLAlchemyError as e: # Catch other specific DB errors
         db.rollback()
         log.error(f"Database Commit Error during registration ({masked_mobile}): {e}", exc_info=True)
         raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database error during registration.")
    except Exception as e: # Catch any other unexpected errors
         db.rollback()
         log.error(f"Unexpected Server Error during registration processing ({masked_mobile}): {e}", exc_info=True)
         raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Unexpected server error during registration.")


# --- Farmer Login ---
@app.post(
    "/api/login/verify-otp",
    response_model=schemas.FarmerProfile, # Responds with snake_case fields
    tags=["Farmer Auth & Registration"],
    summary="Verify OTP for farmer login and set authentication cookie"
)
async def login_verify_otp(response: Response, login_data: schemas.FarmerOtpLogin, db: Session = Depends(get_db)):
    """Handles farmer login via OTP verification and sets HTTPOnly cookie."""
    mobile_number = login_data.mobile # From request body
    submitted_otp = login_data.otp
    masked_mobile = f"******{mobile_number[-4:]}"
    log.info(f"Login Attempt: Verifying OTP for {masked_mobile}")

    # 1. Verify OTP
    stored_otp = otp_store.get(mobile_number)
    if not stored_otp:
        log.warning(f"Login Failure ({masked_mobile}): OTP not in store.")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="OTP invalid or expired. Please request again.")
    if stored_otp != submitted_otp:
        log.warning(f"Login Failure ({masked_mobile}): Incorrect OTP provided.")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid OTP provided.")
    log.info(f"OTP verified successfully for login ({masked_mobile}).")

    # 2. Find Registered Farmer
    try:
        user: Optional[FarmerDB] = db.query(FarmerDB).filter(FarmerDB.mobile_number == mobile_number).first()
    except SQLAlchemyError as e:
        log.error(f"Database error during farmer login lookup ({masked_mobile}): {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database error during login.")

    if not user:
        if mobile_number in otp_store: # Clean store if user invalid
             try: del otp_store[mobile_number]
             except KeyError: pass
        log.warning(f"Login Failure ({masked_mobile}): Farmer record not found.")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Mobile number is not registered.")

    # 3. Create Authentication Token (JWT) and Set Cookie
    try:
        expires_delta = timedelta(minutes=auth_utils.ACCESS_TOKEN_EXPIRE_MINUTES)
        token_payload = {"sub": user.mobile_number, "type": "farmer", "user_id": user.id}
        access_token = auth_utils.create_access_token(data=token_payload, expires_delta=expires_delta)

        is_prod = os.getenv("PRODUCTION", "false").lower() == "true"
        cookie_secure = is_prod # Secure flag only if in production (HTTPS)

        response.set_cookie(
            key=auth_utils.AUTH_COOKIE_NAME,
            value=access_token,
            httponly=True,      # Prevent JS access
            max_age=int(expires_delta.total_seconds()),
            expires=datetime.now(timezone.utc) + expires_delta,
            path="/",           # Cookie accessible on all paths
            samesite="lax",     # Recommended Samesite policy
            secure=cookie_secure # Should be True in production (HTTPS)
        )
        log.info(f"Authentication cookie set for farmer {user.id} ({masked_mobile}). Secure={cookie_secure}")

    except Exception as e:
        log.error(f"JWT/Cookie Error during login for {masked_mobile} (Farmer ID: {user.id}): {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Could not create login session.")

    # 4. Clean up OTP store after successful login & cookie set
    if mobile_number in otp_store:
        try: del otp_store[mobile_number]
        except KeyError: pass
        log.info(f"OTP for {masked_mobile} cleared post-login.")

    log.info(f"Login Successful: Farmer ID {user.id} ({masked_mobile})")
    # Return the SQLAlchemy User object. FastAPI will serialize it using the response_model.
    return user


# --- Get Current Farmer Profile ---
@app.get(
    "/api/users/me",
    response_model=schemas.FarmerProfile, # Ensure snake_case response
    tags=["Farmer Profile"],
    summary="Get profile of the currently authenticated farmer"
)
async def read_users_me(current_user: FarmerDB = Depends(auth_utils.get_current_farmer_user)):
    """Retrieves and returns profile data for the logged-in farmer."""
    log.info(f"Profile request successful for farmer: {current_user.id}")
    return current_user


# --- Admin Login ---
@app.post(
    "/api/admin/login",
    response_model=schemas.AdminProfile, # Ensure snake_case response
    tags=["Admin Auth"],
    summary="Login admin user with email/password and set auth cookie"
)
async def admin_login(response: Response, form_data: schemas.AdminLogin, db: Session = Depends(get_db)):
    """Handles admin login using email/password and sets HTTPOnly cookie."""
    log.info(f"Admin Login Attempt: email={form_data.email}")
    try:
        admin_user = db.query(AdminUserDB).filter(AdminUserDB.email == form_data.email).first()
    except SQLAlchemyError as e:
        log.error(f"Database error during admin login lookup ({form_data.email}): {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="DB error during login.")

    # Verify Admin User and Password
    if not admin_user or not auth_utils.verify_password(form_data.password, admin_user.hashed_password):
        log.warning(f"Admin Login Failed ({form_data.email}): Invalid credentials.")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")

    # Create JWT & Cookie for Admin
    try:
        expires_delta = timedelta(minutes=auth_utils.ACCESS_TOKEN_EXPIRE_MINUTES) # Or longer?
        token_payload = {"sub": admin_user.email, "type": "admin", "user_id": admin_user.id}
        access_token = auth_utils.create_access_token(data=token_payload, expires_delta=expires_delta)
        is_prod = os.getenv("PRODUCTION", "false").lower() == "true"
        cookie_secure = is_prod

        response.set_cookie(
            key=auth_utils.AUTH_COOKIE_NAME, value=access_token,
            httponly=True, max_age=int(expires_delta.total_seconds()),
            expires=datetime.now(timezone.utc) + expires_delta, path="/",
            samesite="lax", secure=cookie_secure
        )
        log.info(f"Auth cookie set for admin {admin_user.email}. Secure={cookie_secure}")
    except Exception as e:
        log.error(f"JWT/Cookie Error during admin login ({admin_user.email}): {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Could not create admin login session.")

    # Update Last Login Time (Optional, non-critical)
    try:
        admin_user.last_login_at = datetime.now(timezone.utc)
        db.commit()
    except SQLAlchemyError as e:
        db.rollback() # Rollback only this minor update if it fails
        log.error(f"Non-critical: Failed to update last_login_at for admin {admin_user.email}: {e}")

    log.info(f"Login Successful: Admin {admin_user.email}")
    return admin_user # Return Admin object, FastAPI serializes

# --- Get Current Admin Profile ---
@app.get(
    "/api/admin/me",
    response_model=schemas.AdminProfile, # Ensure snake_case response
    tags=["Admin Profile"],
    summary="Get profile of the currently authenticated admin"
)
async def read_admin_me(current_admin: AdminUserDB = Depends(auth_utils.get_current_admin_user)):
     """Retrieves and returns profile data for the logged-in admin."""
     log.info(f"Profile request successful for admin: {current_admin.email}")
     return current_admin

# --- Generic Logout ---
@app.post(
    "/api/logout",
    status_code=status.HTTP_200_OK,
    tags=["Authentication"],
    summary="Logout user/admin by clearing the authentication cookie"
)
async def logout(response: Response):
    """Clears the authentication cookie to log the user/admin out."""
    log.info("Logout request received. Clearing authentication cookie.")
    is_prod = os.getenv("PRODUCTION", "false").lower() == "true"
    cookie_secure = is_prod

    response.delete_cookie(
        key=auth_utils.AUTH_COOKIE_NAME,
        path="/",
        secure=cookie_secure, # Match secure flag from login
        httponly=True,       # Match httponly flag
        samesite="lax"       # Match samesite policy
    )
    return {"message": "Logout successful"}

# --- Run Application (using Uvicorn when script is executed directly) ---
if __name__ == "__main__":
    import uvicorn
    # Configuration for Uvicorn loaded from environment or defaults
    port = int(os.getenv("PORT", 8000)) # Default to 8000 for backend
    host = os.getenv("HOST", "0.0.0.0") # Listen on all interfaces by default
    reload_flag = os.getenv("UVICORN_RELOAD", "false").lower() == "true" # Default OFF
    log_level = os.getenv("UVICORN_LOG_LEVEL", "info").lower()

    # Log server start details
    log.info(f"--- Starting Kisan Manch API Server ---")
    log.info(f" Listening on: http://{host}:{port}")
    log.info(f" Uvicorn Reloading: {reload_flag}")
    log.info(f" Uvicorn Log Level: {log_level}")
    log.info(f" Allowed CORS Origins: {allowed_origins}")
    log.info(f" Production Mode (Secure Cookies): {os.getenv('PRODUCTION', 'false').lower() == 'true'}")

    # Run the Uvicorn server
    uvicorn.run(
        "main:app",             # App instance location (app object in main.py)
        host=host,              # Host to bind to
        port=port,              # Port to listen on
        reload=reload_flag,     # Enable/disable auto-reloading
        log_level=log_level,    # Set Uvicorn's logging level
    )