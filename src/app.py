"""
High School Management System API

A super simple FastAPI application that allows students to view and sign up
for extracurricular activities at Mergington High School.
"""

import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, Field
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse

app = FastAPI(title="Mergington High School API",
              description="API for viewing and signing up for extracurricular activities")

current_dir = Path(__file__).parent
app.mount("/static", StaticFiles(directory=current_dir / "static"), name="static")

AUTH_USERS_FILE = Path(os.getenv("AUTH_USERS_FILE", str(current_dir / "users.json")))
SESSION_COOKIE_NAME = "mergington_session"
SESSION_TTL_SECONDS = 8 * 60 * 60
PASSWORD_HASH_ITERATIONS = 310_000
SECURE_COOKIES = os.getenv("SECURE_COOKIES", "false").lower() == "true"
sessions: dict[str, dict] = {}


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=1, max_length=1024)


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt, PASSWORD_HASH_ITERATIONS
    )
    return f"pbkdf2_sha256${PASSWORD_HASH_ITERATIONS}${salt.hex()}${password_hash.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        algorithm, iterations, salt, expected_hash = stored_hash.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        actual_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt), int(iterations)
        ).hex()
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual_hash, expected_hash)


def load_user_accounts() -> list[dict]:
    try:
        with AUTH_USERS_FILE.open(encoding="utf-8") as account_file:
            accounts = json.load(account_file)
    except FileNotFoundError:
        return []
    if not isinstance(accounts, list):
        raise RuntimeError("The account store must contain a JSON list.")
    return accounts


def public_user(account: dict) -> dict:
    return {
        "username": account["username"],
        "email": account["email"],
        "role": account["role"],
    }


def get_optional_user(request: Request) -> dict | None:
    token = request.cookies.get(SESSION_COOKIE_NAME)
    session = sessions.get(token) if token else None
    if not session:
        return None
    if session["expires_at"] <= time.time():
        sessions.pop(token, None)
        return None
    username = session["username"]
    return next(
        (account for account in load_user_accounts()
         if account.get("username", "").casefold() == username.casefold()),
        None,
    )


def get_current_user(request: Request) -> dict:
    account = get_optional_user(request)
    if account is None:
        raise HTTPException(status_code=401, detail="Sign in is required")
    return account


def require_admin(account: dict = Depends(get_current_user)) -> dict:
    if account.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Administrator access is required")
    return account

# In-memory activity database
activities = {
    "Chess Club": {
        "description": "Learn strategies and compete in chess tournaments",
        "schedule": "Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 12,
        "participants": ["michael@mergington.edu", "daniel@mergington.edu"]
    },
    "Programming Class": {
        "description": "Learn programming fundamentals and build software projects",
        "schedule": "Tuesdays and Thursdays, 3:30 PM - 4:30 PM",
        "max_participants": 20,
        "participants": ["emma@mergington.edu", "sophia@mergington.edu"]
    },
    "Gym Class": {
        "description": "Physical education and sports activities",
        "schedule": "Mondays, Wednesdays, Fridays, 2:00 PM - 3:00 PM",
        "max_participants": 30,
        "participants": ["john@mergington.edu", "olivia@mergington.edu"]
    },
    "Soccer Team": {
        "description": "Join the school soccer team and compete in matches",
        "schedule": "Tuesdays and Thursdays, 4:00 PM - 5:30 PM",
        "max_participants": 22,
        "participants": ["liam@mergington.edu", "noah@mergington.edu"]
    },
    "Basketball Team": {
        "description": "Practice and play basketball with the school team",
        "schedule": "Wednesdays and Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["ava@mergington.edu", "mia@mergington.edu"]
    },
    "Art Club": {
        "description": "Explore your creativity through painting and drawing",
        "schedule": "Thursdays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["amelia@mergington.edu", "harper@mergington.edu"]
    },
    "Drama Club": {
        "description": "Act, direct, and produce plays and performances",
        "schedule": "Mondays and Wednesdays, 4:00 PM - 5:30 PM",
        "max_participants": 20,
        "participants": ["ella@mergington.edu", "scarlett@mergington.edu"]
    },
    "Math Club": {
        "description": "Solve challenging problems and participate in math competitions",
        "schedule": "Tuesdays, 3:30 PM - 4:30 PM",
        "max_participants": 10,
        "participants": ["james@mergington.edu", "benjamin@mergington.edu"]
    },
    "Debate Team": {
        "description": "Develop public speaking and argumentation skills",
        "schedule": "Fridays, 4:00 PM - 5:30 PM",
        "max_participants": 12,
        "participants": ["charlotte@mergington.edu", "henry@mergington.edu"]
    }
}


@app.get("/")
def root():
    return RedirectResponse(url="/static/index.html")


@app.post("/auth/login")
def login(credentials: LoginRequest, response: Response):
    account = next(
        (user for user in load_user_accounts()
         if user.get("username", "").casefold() == credentials.username.casefold()),
        None,
    )
    if account is None or not verify_password(
        credentials.password, account.get("password_hash", "")
    ):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = secrets.token_urlsafe(32)
    sessions[token] = {
        "username": account["username"],
        "expires_at": time.time() + SESSION_TTL_SECONDS,
    }
    response.set_cookie(
        SESSION_COOKIE_NAME,
        token,
        max_age=SESSION_TTL_SECONDS,
        httponly=True,
        secure=SECURE_COOKIES,
        samesite="lax",
        path="/",
    )
    return {"user": public_user(account)}


@app.get("/auth/me")
def current_user(request: Request):
    account = get_optional_user(request)
    return {"user": public_user(account) if account else None}


@app.post("/auth/logout")
def logout(request: Request, response: Response):
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if token:
        sessions.pop(token, None)
    response.delete_cookie(SESSION_COOKIE_NAME, path="/", httponly=True, samesite="lax")
    return {"message": "Signed out"}


@app.get("/activities")
def get_activities(request: Request):
    account = get_optional_user(request)
    is_admin = account is not None and account.get("role") == "admin"
    return {
        name: {
            **details,
            "participant_count": len(details["participants"]),
            "participants": details["participants"] if is_admin else [],
        }
        for name, details in activities.items()
    }


@app.post("/activities/{activity_name}/signup")
def signup_for_activity(
    activity_name: str,
    email: str,
    account: dict = Depends(require_admin),
):
    """Sign up a student for an activity"""
    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    # Get the specific activity
    activity = activities[activity_name]

    # Validate student is not already signed up
    if email in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is already signed up"
        )

    # Add student
    activity["participants"].append(email)
    return {"message": f"Signed up {email} for {activity_name} by {account['username']}"}


@app.delete("/activities/{activity_name}/unregister")
def unregister_from_activity(
    activity_name: str,
    email: str,
    account: dict = Depends(require_admin),
):
    """Unregister a student from an activity"""
    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    # Get the specific activity
    activity = activities[activity_name]

    # Validate student is signed up
    if email not in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is not signed up for this activity"
        )

    # Remove student
    activity["participants"].remove(email)
    return {"message": f"Unregistered {email} from {activity_name} by {account['username']}"}
