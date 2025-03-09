from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, Text
from sqlalchemy.orm import relationship, Session
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import JWTError, jwt
from pydantic import BaseModel, HttpUrl
from typing import Optional
import os
from sqlalchemy.sql import select
from fastapi import UploadFile, File
from fastapi.staticfiles import StaticFiles
import shutil
import uuid
import os
from dotenv import load_dotenv
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from fastapi import Request
from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, Text
from sqlalchemy.orm import relationship, Session
from sqlalchemy.ext.declarative import declarative_base
from fastapi import Form
from fastapi import UploadFile, File
from fastapi.middleware.cors import CORSMiddleware



# Configuration
load_dotenv()

# Use environment variables
DATABASE_URL = os.getenv("DATABASE_URL")
print("DATABASE_URL:", os.getenv("DATABASE_URL"))
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Database Setup
Base = declarative_base()
engine = create_async_engine(DATABASE_URL, echo=True)
SessionLocal = sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

# Password Hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)




# Models
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    posts = relationship("Post", back_populates="author")

class Post(Base):
    __tablename__ = "posts"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True, nullable=False)
    content = Column(Text, nullable=False)
    image_url = Column(String, nullable=True)  # Store image path
    created_at = Column(DateTime, default=datetime.utcnow)  # Store blog creation time
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)  # Store last update time
    author_id = Column(Integer, ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")

# Pydantic Schemas
class UserCreate(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class PostCreate(BaseModel):
    title: str
    content: str

class PostResponse(BaseModel):
    id: int
    title: str
    content: str
    image_url: Optional[str] = None  # Image URL (optional)
    created_at: datetime
    updated_at: datetime
    author_name: str
    class Config:
        orm_mode = True


# FastAPI App
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://wonderful-pudding-440cd3.netlify.app"],  # Allow requests from React frontend
    allow_credentials=True,
    allow_methods=["*"],  # Allow all HTTP methods (GET, POST, PUT, DELETE, etc.)
    allow_headers=["*"],  # Allow all headers
)

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True) 
# Dependency
async def get_db():
    async with SessionLocal() as session:
        yield session


app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    db_user = await db.execute(select(User).where(User.username == username))
    db_user = db_user.scalar_one_or_none()
    if db_user is None:
        raise credentials_exception
    return db_user

@app.get("/")
def home():
    return {"message": "FastAPI Server is Running"}
# Authentication
@app.post("/register")
async def register(user: UserCreate, db: Session = Depends(get_db)):
    hashed_password = get_password_hash(user.password)
    new_user = User(username=user.username, hashed_password=hashed_password)
    db.add(new_user)
    await db.commit()
    return {"message": "User created successfully"}

@app.post("/token", response_model=Token)
async def login(user: UserCreate, db: Session = Depends(get_db)):
    db_user = await db.execute(select(User).where(User.username == user.username))
    db_user = db_user.scalar_one_or_none()
    if not db_user or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    access_token = jwt.encode({"sub": db_user.username}, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": access_token, "token_type": "bearer"}

# Blog Post Endpoints
@app.post("/posts", response_model=PostResponse)
async def create_post(
    request: Request,  # Capture the incoming request
    title: str = Form(...), 
    content: str = Form(...), 
    image_url: UploadFile = File(None), 
    db: Session = Depends(get_db), 
    current_user: User = Depends(get_current_user)
):
    body = await request.form()
    print(body)
    image_path = None
    if image_url:
        print(f"Received image: {image_url.filename}")
        file_extension = image_url.filename.split(".")[-1]
        filename = f"{uuid.uuid4()}.{file_extension}"
        file_path = os.path.join(UPLOAD_DIR, filename)
        
        try:
            with open(file_path, "wb") as buffer:
                shutil.copyfileobj(image_url.file, buffer)
            image_path = f"/uploads/{filename}"  # Store relative path
            print(f"Saved image at: {file_path}")  # Debugging
        except Exception as e:
            print(f"Error saving image: {e}")

    else:
        print("No image received")

    new_post = Post(
        title=title,
        content=content,
        image_url=image_path,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
        author_id=current_user.id   # Replace with actual authenticated user ID
    )  
    # Replace with actual user ID from auth
    db.add(new_post)
    await db.commit()
    db.refresh(new_post)

    return {
        "id": new_post.id,
        "title": new_post.title,
        "content": new_post.content,
        "image_url": new_post.image_url,
        "created_at": new_post.created_at,
        "updated_at": new_post.updated_at,
        "author_name": new_post.author.username,  # Assuming there's a relationship
    }
@app.get("/posts", response_model=list[PostResponse])
async def get_posts(db: Session = Depends(get_db)):
    result = await db.execute(select(Post, User.username).join(User, Post.author_id == User.id).order_by(Post.created_at.desc()))
    posts = result.fetchall()

    return [
        PostResponse(
            id=post.id,
            title=post.title,
            content=post.content,
            image_url=post.image_url,
            created_at=post.created_at,
            updated_at=post.updated_at,
            author_name=username  # Return the username instead of author_id
        )
        for post, username in posts
    ]


@app.get("/posts/{post_id}", response_model=PostResponse)
async def get_post(post_id: int, db: Session = Depends(get_db)):
    result = await db.execute(
        select(Post, User.username)
        .join(User, Post.author_id == User.id)
        .where(Post.id == post_id)
    )
    post = result.fetchone()

    if not post:
        raise HTTPException(status_code=404, detail="Post not found")

    post, username = post  # Unpack the result

    return {
        "id": post.id,
        "title": post.title,
        "content": post.content,
        "image_url": post.image_url,
        "created_at": post.created_at,
        "updated_at": post.updated_at,
        "author_name": username,  # Return username instead of author_id
    }



@app.put("/posts/{post_id}", response_model=PostResponse)
async def update_post(
    post_id: int,
    title: str = Form(...), 
    content: str = Form(...),
    image_url: UploadFile = File(None),  
    db: AsyncSession = Depends(get_db),  # Use AsyncSession
    current_user: User = Depends(get_current_user)
):
    # Fetch post using async query
    result = await db.execute(select(Post).where(Post.id == post_id))
    db_post = result.scalar_one_or_none()

    if not db_post:
        raise HTTPException(status_code=404, detail="Post not found")

    # Ensure only the post owner can edit
    if db_post.author_id != current_user.id:
        raise HTTPException(status_code=403, detail="Permission denied")

    # Update title and content
    db_post.title = title
    db_post.content = content

    # Handle image upload (if provided)
    if image_url:
        file_extension = image_url.filename.split(".")[-1]
        filename = f"{uuid.uuid4()}.{file_extension}"
        file_path = os.path.join(UPLOAD_DIR, filename)
        
        try:
            with open(file_path, "wb") as buffer:
                shutil.copyfileobj(image_url.file, buffer)
            db_post.image_url = f"/uploads/{filename}"  
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error saving image: {e}")

    db_post.updated_at = datetime.utcnow()  # Update timestamp

    await db.commit()  # Use async commit
    await db.refresh(db_post)

    return {
        "id": db_post.id,
        "title": db_post.title,
        "content": db_post.content,
        "image_url": db_post.image_url,
        "created_at": db_post.created_at,
        "updated_at": db_post.updated_at,
        "author_name": db_post.author.username,
    }


@app.delete("/posts/{post_id}")
async def delete_post(post_id: int, db: Session = Depends(get_db)):
    db_post = await db.get(Post, post_id)
    if not db_post:
        raise HTTPException(status_code=404, detail="Post not found")
    await db.delete(db_post)
    await db.commit()
    return {"message": "Post deleted successfully"}
