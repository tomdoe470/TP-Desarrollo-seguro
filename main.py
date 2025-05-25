from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.responses import JSONResponse
import secrets

app = FastAPI()
security = HTTPBasic()

@app.get("/public")
def read_public():
    return {"message": "Ruta pública"}

@app.get("/private")
def read_private(credentials: HTTPBasicCredentials = Depends(security)):
    correct_username = secrets.compare_digest(credentials.username, "Tom")
    correct_password = secrets.compare_digest(credentials.password, "clave123")
    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales inválidas",
            headers={"WWW-Authenticate": "Basic"},
        )
    return {"message": f"Hola, {credentials.username}!"}
