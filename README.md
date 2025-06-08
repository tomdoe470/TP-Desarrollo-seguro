# Trabajo Práctico Nº2 – Desarrollo Seguro de APIs

**Materia:** Desarrollo Seguro  
**Fecha:** Mayo de 2025  
**Profesor:** Lic. Juan Pablo Villalba
**Alumno:** Tomás de Otaduy

---

## 🧩 Descripción general

Este proyecto consiste en la creación de una API RESTful utilizando el framework **FastAPI**, con el objetivo de implementar y analizar todos los métodos de **autenticación y control de acceso**, conforme a buenas prácticas de seguridad.

Se desarrollaron diferentes rutas con acceso público y privado, incluyendo mecanismos de autenticación por **API Key**, validación por **dirección IP** y protección mediante **tokens JWT**. Además, la documentación se genera automáticamente conforme al estándar **OpenAPI**.

---

## 🛠️ Tecnologías utilizadas

- **Python 3.11+**
- **FastAPI 0.110**
- **Uvicorn 0.29**
- **PyJWT 2.8**
- **dotenv 1.0.1** (para configuración segura)
- **Swagger UI / ReDoc** (documentación automática)

---

## 🔐 Métodos de autenticación implementados

| Método            | Descripción                                                                 |
|------------------|------------------------------------------------------------------------------|
| API Key Header    | Requiere la clave definida en `settings.py` bajo el encabezado `X-API-Key`. |
| IP Whitelisting   | Solo permite el acceso a ciertas rutas si la IP de origen está en la lista autorizada. |
| JWT (JSON Web Token) | Se emite un token firmado para usuarios autenticados y se verifica en rutas protegidas. |

---

## ▶️ Cómo ejecutar el proyecto

1. Crear y activar un entorno virtual:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   uvicorn main:app --reload

Acceder a la documentación interactiva:
Swagger UI: http://127.0.0.1:8000/docs

## 📡 Endpoints disponibles

| Ruta                | Método | Requiere API Key | Requiere IP válida | Requiere JWT | Descripción                         |
|---------------------|--------|------------------|--------------------|--------------|-------------------------------------|
| `/public`           | GET    | ❌               | ❌                 | ❌           | Ruta de acceso libre                |
| `/private`          | GET    | ✅               | ❌                 | ❌           | Protegida con API Key               |
| `/secure-data`      | GET    | ✅               | ✅                 | ❌           | Protegida con IP autorizada y API Key |
| `/token`            | POST   | ❌               | ❌                 | ❌           | Devuelve un JWT si las credenciales son correctas |
| `/protected-jwt`    | GET    | ❌               | ❌                 | ✅           | Protegida con autenticación JWT     |

---

## 📌 Notas

- **Usuario de prueba:** `admin`  
- **Contraseña:** `1234`  
- **API Key esperada:** definida en `settings.py` como `API_KEY`  
- **IPs permitidas:** definidas en `settings.py` como `ALLOWED_IPS`  
- **JWT:** firmado con HS256 y expiración configurada  
- **Cabecera JWT:** `Authorization: Bearer <token>

   
