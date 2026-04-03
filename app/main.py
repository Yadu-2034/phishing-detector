import os
import sys
from fastapi import FastAPI, Request, HTTPException, Depends, Header
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import Optional
from datetime import timedelta
from slowapi.errors import RateLimitExceeded
from slowapi import _rate_limit_exceeded_handler

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.auth import (verify_password, create_access_token, decode_token,
                      verify_api_key, DEMO_USERS, ACCESS_TOKEN_EXPIRE_MINUTES)
from app.model import load_model, predict_url
from app.database import init_database, log_scan, get_all_logs, get_statistics
from app.rate_limiter import limiter

app = FastAPI(
    title="Phishing URL Detector",
    description="Detect phishing URLs using Machine Learning with DevSecOps",
    version="1.0.0"
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

templates = Jinja2Templates(directory="app/templates")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)

@app.on_event("startup")
async def startup_event():
    print("Starting Phishing URL Detector...")
    init_database()
    load_model()
    print("App is ready!")

class URLScanRequest(BaseModel):
    url: str

class URLScanResponse(BaseModel):
    url: str
    result: str
    risk_score: float
    message: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str

async def get_current_user(
    token: Optional[str] = Depends(oauth2_scheme),
    x_api_key: Optional[str] = Header(None)
):
    if x_api_key and verify_api_key(x_api_key):
        return {"username": "api_user", "auth_method": "api_key"}

    if token:
        username = decode_token(token)
        if username:
            return {"username": username, "auth_method": "jwt"}

    raise HTTPException(
        status_code=401,
        detail="Authentication required. Provide a valid JWT token or API key.",
        headers={"WWW-Authenticate": "Bearer"},
    )

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse(request=request, name="dashboard.html")

@app.post("/token", response_model=TokenResponse)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = DEMO_USERS.get(form_data.username)
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password"
        )
    access_token = create_access_token(
        data={"sub": form_data.username},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/scan-url", response_model=URLScanResponse)
@limiter.limit("10/minute")
async def scan_url(
    request: Request,
    scan_request: URLScanRequest,
    current_user: dict = Depends(get_current_user)
):
    url = scan_request.url.strip()

    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    if not (url.startswith("http://") or url.startswith("https://")):
        url = "http://" + url

    user_ip = request.client.host or "unknown"

    prediction, risk_score = predict_url(url)

    log_scan(
        url=url,
        prediction=prediction,
        risk_score=risk_score,
        user_ip=user_ip
    )

    if prediction == "Phishing":
        if risk_score >= 0.8:
            message = "HIGH RISK: This URL shows strong phishing indicators. Do not visit."
        else:
            message = "MEDIUM RISK: This URL appears suspicious."
    else:
        if risk_score <= 0.2:
            message = "LOW RISK: This URL appears safe."
        else:
            message = "This URL is likely safe but exercise caution."

    return URLScanResponse(
        url=url,
        result=prediction,
        risk_score=risk_score,
        message=message
    )

@app.get("/api/stats")
async def api_stats():
    return get_statistics()

@app.get("/api/logs")
async def api_logs(limit: int = 20):
    return get_all_logs(limit=limit)

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "phishing-detector"}
