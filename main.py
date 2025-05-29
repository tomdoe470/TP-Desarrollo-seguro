from fastapi import FastAPI, Security, HTTPException, Depends, Request, status
from fastapi.security.api_key import APIKeyHeader
from fastapi.security import OAuth2PasswordRequestForm
from starlette.status import HTTP_403_FORBIDDEN
from datetime import datetime, timedelta
import jwt
import settings

app = FastAPI()

# API Key config
api_key_header = APIKeyHeader(name=settings.API_KEY_NAME, auto_error=False)

def get_api_key(api_key: str = Depends(api_key_header)):
    if api_key == settings.API_KEY:
        return api_key
    raise HTTPException(
        status_code=HTTP_403_FORBIDDEN,
        detail="API Key inválida"
    )

# IP Whitelist
def verify_ip(request: Request):
    client_ip = request.client.host
    if client_ip not in settings.ALLOWED_IPS:
        raise HTTPException(
            status_code=HTTP_403_FORBIDDEN,
            detail=f"Acceso denegado desde IP: {client_ip}"
        )
    return client_ip

# JWT: generar token
def create_jwt_token(data: dict, expires_delta: timedelta = timedelta(minutes=15)):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt

# JWT: verificar token
def verify_jwt(token: str):
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido")

def get_current_user(request: Request):
    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token faltante")
    token = auth.split(" ")[1]
    return verify_jwt(token)

# ---------- Rutas ----------

@app.get("/public")
def public_route():
    return {"mensaje": "Acceso público"}

@app.get("/private")
def private_route(api_key: str = Depends(get_api_key)):
    return {"mensaje": "Acceso con API Key autorizada"}

@app.get("/secure-data")
def secure_data(
    ip_ok: str = Depends(verify_ip),
    api_key: str = Depends(get_api_key)
):
    return {
        "mensaje": "Acceso con IP y API Key válidas",
        "ip_origen": ip_ok
    }

@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    # Usuario ficticio: username=admin, password=1234
    if form_data.username != "admin" or form_data.password != "1234":
        raise HTTPException(status_code=400, detail="Credenciales inválidas")
    
    token = create_jwt_token({"sub": form_data.username})
    return {"access_token": token, "token_type": "bearer"}

@app.get("/protected-jwt")
def jwt_protected_route(user=Depends(get_current_user)):
    return {
        "mensaje": f"Token JWT válido. Bienvenido, {user['sub']}",
        "expira_en": user['exp']
    }
