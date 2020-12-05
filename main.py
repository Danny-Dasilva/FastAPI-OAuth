from fastapi import APIRouter
from pydantic import BaseModel
import jwt
from urllib.parse import parse_qsl
import jwt

from fastapi import Header, HTTPException, status

from fastapi.security.utils import get_authorization_scheme_param

from pydantic import ValidationError


from typing import Dict

import httpx

from fastapi import APIRouter, Depends

from sqlalchemy.orm import Session

LOGIN_URL = "https://github.com/login/oauth/authorize"

TOKEN_URL = "https://github.com/login/oauth/access_token"

USER_URL = "https://api.github.com/user"

REDIRECT_URL = f"{settings.app_url}/auth/github"


LOGIN_URL = "https://github.com/login/oauth/authorize"

REDIRECT_URL = f"{settings.app_url}/auth/github"

router = APIRouter()

from pydantic import BaseModel

class AuthorizationResponse(BaseModel):
    state: str
    code: str

class GithubUser(BaseModel):
    login: str
    name: str
    company: str
    location: str
    email: str
    avatar_url: str

class User(BaseModel):
    id: int
    login: str
    name: str
    company: str
    location: str
    email: str
    picture: str
    class Config:
        orm_mode = True

class Token(BaseModel):
    access_token: str
    token_type: str
    user: User


@router.get("/login")
def get_login_url() -> Url:
    params = {
        "client_id": settings.github_client_id,
        "redirect_uri": REDIRECT_URL,
        "state": generate_token(),
    }
    return Url(url=f"{LOGIN_URL}?{urlencode(params)}")

def create_access_token(*, data: User, exp: int = None) -> bytes:
    to_encode = data.dict()
    if exp is not None:
        to_encode.update({"exp": exp})
    else:
        expire = datetime.utcnow() + timedelta(minutes=60)
        to_encode.update({"exp": expire})

    encoded_jwt = jwt.encode(
        to_encode, settings.jwt_secret_key, algorithm=settings.jwt_algorithm
    )
    return encoded_jwt

@router.post("/authorize")

async def verify_authorization(

 body: AuthorizationResponse, db: Session = Depends(get_db)
) -> Token:
    params = {
        "client_id": settings.github_client_id,
        "client_secret": settings.github_client_secret,
        "code": body.code,
        "state": body.state,
    }
    async with httpx.AsyncClient() as client:
        token_request = await client.post(TOKEN_URL, params=params)
        response: Dict[bytes, bytes] = dict(parse_qsl(token_request.content))
        github_token = response[b"access_token"].decode("utf-8")
        github_header = {"Authorization": f"token {github_token}"}
        user_request = await client.get(USER_URL, headers=github_header)
        github_user = GithubUser(**user_request.json())
    db_user = get_user_by_login(db, github_user.login)

    if db_user is None:
        db_user = create_user(db, github_user)

    verified_user = User.from_orm(db_user)
    access_token = create_access_token(data=verified_user)
    return Token(access_token=access_token, token_type="bearer", user=db_user)



def get_user_from_header(*, authorization: str = Header(None)) -> User:

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    scheme, token = get_authorization_scheme_param(authorization)

    if scheme.lower() != "bearer":
        raise credentials_exception
    try:
        payload = jwt.decode(
            token, settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm]
        )
        try:
            token_data = User(**payload)
            return token_data
        except ValidationError:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception

@router.get("/me", response_model=User)

def read_profile(
    user: User = Depends(get_user_from_header),
    db: Session = Depends(get_db),
) -> DbUser:
    db_user = get_user(db, user.id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user
    
class Url(BaseModel):
    url: str

if __name__ == '__main__':
    import uvicorn
    uvicorn.run("main:app", host='127.0.0.1', port=8000, reload=True, debug=True, workers=2)
