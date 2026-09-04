"""Zero Trust Auth Proxy API — REST interface."""

from __future__ import annotations

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

app = FastAPI(title="CyberShield Zero Trust Proxy", version="1.0.0")


class RegisterRequest(BaseModel):
    username: str
    password: str
    roles: list[str] = ["user"]


class LoginRequest(BaseModel):
    username: str
    password: str


@app.get("/health")
async def health():
    return {"status": "healthy", "module": "zero-trust-proxy"}


@app.post("/api/v1/auth/register")
async def register(request: RegisterRequest):
    from modules.zero_trust_proxy.src.engine import ZeroTrustProxy

    proxy = ZeroTrustProxy()
    user = proxy.register_user(request.username, request.password, request.roles)
    if not user:
        raise HTTPException(status_code=409, detail="User already exists")
    return user.to_dict()


@app.post("/api/v1/auth/login")
async def login(request: LoginRequest):
    from modules.zero_trust_proxy.src.engine import ZeroTrustProxy

    proxy = ZeroTrustProxy()
    success, token = proxy.authenticate(request.username, request.password, "api")
    if not success:
        raise HTTPException(status_code=401, detail=token)
    return {"token": token, "token_type": "bearer"}


@app.post("/api/v1/auth/logout")
async def logout(authorization: str = Header(...)):
    from modules.zero_trust_proxy.src.engine import ZeroTrustProxy

    proxy = ZeroTrustProxy()
    token = authorization.replace("Bearer ", "")
    proxy.logout(token)
    return {"status": "logged_out"}


@app.get("/api/v1/audit")
async def get_audit(limit: int = 50):
    from modules.zero_trust_proxy.src.engine import ZeroTrustProxy

    proxy = ZeroTrustProxy()
    return proxy.get_audit_log(limit=limit)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8005)
