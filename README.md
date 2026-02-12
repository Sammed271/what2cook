# what2cook

FastAPI JWT authentication backend (Flutter-friendly).

## Features
- `POST /register` for account creation
- `POST /login` with OAuth2 password form (`username`, `password`) returning a JWT
- `POST /logout` placeholder for stateless JWT logout
- `GET /protected` protected endpoint requiring bearer token
- SQLite database storage (`auth.db`)
- Password hashing using bcrypt via Passlib
- CORS enabled for Flutter clients

## Install
```bash
pip install -r requirements.txt
```

## Run
```bash
uvicorn main:app --reload
```

Open docs at `http://127.0.0.1:8000/docs`.
