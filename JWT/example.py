from fastapi import FastAPI, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')

@app.post('/token')
async def token(form_data: OAuth2PasswordRequestForm = Depends()):
    return {'access_token': form_data.username + 'token'}

@app.get('/')
async def index(token: str = Depends(oauth2_scheme)):
    return {'the_token' : token}

if __name__ == '__main__':
    import uvicorn
    uvicorn.run("example:app", host='127.0.0.1', port=8000, reload=True, debug=True, workers=2)
