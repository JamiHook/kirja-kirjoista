import os
import re
import hmac
import time
import json
import base64
import hashlib
import contextlib
from fastapi import FastAPI, HTTPException, Query, Header, Depends
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, List
import psycopg2
from psycopg2.pool import ThreadedConnectionPool
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv

# Load env variables
dotenv_path = os.path.join(os.path.dirname(__file__), ".env")
load_dotenv(dotenv_path)

db_url = os.environ.get("DATABASE_URL")
if not db_url:
    raise RuntimeError("DATABASE_URL environment variable is missing from .env file!")

# JWT-like session token configuration
SECRET_KEY = "tiimiakatemia_portal_secret_key_2026"

def generate_token(username: str, role: str) -> str:
    payload = {
        "username": username,
        "role": role,
        "exp": time.time() + 86400 * 7  # 7 days expiration
    }
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode('utf-8')).decode('utf-8')
    signature = hmac.new(SECRET_KEY.encode('utf-8'), payload_b64.encode('utf-8'), hashlib.sha256).hexdigest()
    return f"{payload_b64}.{signature}"

def verify_token(token: str) -> Optional[dict]:
    try:
        payload_b64, signature = token.split(".", 1)
        expected_signature = hmac.new(SECRET_KEY.encode('utf-8'), payload_b64.encode('utf-8'), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected_signature):
            return None
        
        payload = json.loads(base64.urlsafe_b64decode(payload_b64.encode('utf-8')).decode('utf-8'))
        if payload["exp"] < time.time():
            return None  # Expired
        return payload
    except Exception:
        return None

def verify_password(stored_password_hash: str, password: str) -> bool:
    try:
        salt_hex, key_hex = stored_password_hash.split(":", 1)
        salt = bytes.fromhex(salt_hex)
        key = bytes.fromhex(key_hex)
        new_key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        return new_key == key
    except Exception:
        return False

def hash_password(password: str) -> str:
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return salt.hex() + ":" + key.hex()

# Initialize connection pool
try:
    pool = ThreadedConnectionPool(1, 15, db_url)
except Exception as e:
    print(f"Failed to create connection pool: {e}")
    raise e

app = FastAPI(
    title="Kirja kirjoista – Tiimiakatemia Platform",
    description="Johannes Partasen Kirja kirjoista -aineiston tietokantapohjainen hakupalvelu",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@contextlib.contextmanager
def get_db_connection():
    conn = pool.getconn()
    try:
        yield conn
    finally:
        pool.putconn(conn)

@contextlib.contextmanager
def get_db_cursor(commit=False):
    with get_db_connection() as conn:
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        try:
            yield cursor
            if commit:
                conn.commit()
        except Exception as e:
            if commit:
                conn.rollback()
            raise e
        finally:
            cursor.close()

# Authentication dependency
def get_current_user(authorization: Optional[str] = Header(None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Kirjautuminen vaaditaan")
    token = authorization.split("Bearer ", 1)[1]
    payload = verify_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Sessio vanhentunut tai virheellinen, kirjaudu uudelleen")
    
    # Get user_id from DB
    with get_db_cursor() as cur:
        cur.execute("SELECT id, username, role FROM users WHERE username = %s;", (payload["username"],))
        user = cur.fetchone()
        if not user:
            raise HTTPException(status_code=401, detail="Käyttäjää ei löydy")
        return user

def require_roles(allowed_roles: List[str]):
    def dependency(current_user: dict = Depends(get_current_user)):
        if current_user["role"] not in allowed_roles:
            raise HTTPException(status_code=403, detail="Oikeus evätty: Toiminto vaatii toisen roolin")
        return current_user
    return dependency

# Pydantic models
class LoginRequest(BaseModel):
    username: str
    password: str

class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6, max_length=100)

class RoleUpdateRequest(BaseModel):
    role: str

class BookCreateOrUpdate(BaseModel):
    category_id: int
    author: str = Field(..., min_length=1)
    title: str = Field(..., min_length=1)
    publisher: Optional[str] = None
    year: Optional[int] = None
    isbn: Optional[str] = None
    language: Optional[str] = "suom."
    stars: Optional[int] = Field(1, ge=0, le=3)
    points: Optional[int] = Field(0, ge=0)
    processes: Optional[str] = ""
    kolahdukset: Optional[int] = Field(0, ge=0)

class ReviewCreate(BaseModel):
    rating: int = Field(..., ge=1, le=5)
    review_text: str = Field(..., min_length=3)

# ---------------- API Endpoints ----------------

# Auth Endpoints
@app.post("/api/auth/register")
def register(req: RegisterRequest):
    try:
        hashed = hash_password(req.password)
        with get_db_cursor(commit=True) as cur:
            # Check if username exists
            cur.execute("SELECT id FROM users WHERE username = %s;", (req.username.lower(),))
            if cur.fetchone():
                raise HTTPException(status_code=400, detail="Käyttäjätunnus on jo varattu")
            
            cur.execute("""
                INSERT INTO users (username, password_hash, role)
                VALUES (%s, %s, 'Reader')
                RETURNING id, username, role;
            """, (req.username.lower(), hashed))
            new_user = cur.fetchone()
            return new_user
    except HTTPException as he:
        raise he
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Rekisteröinti epäonnistui: {str(e)}")

@app.post("/api/auth/login")
def login(req: LoginRequest):
    try:
        with get_db_cursor() as cur:
            cur.execute("SELECT id, username, password_hash, role FROM users WHERE username = %s;", (req.username.lower(),))
            user = cur.fetchone()
            if not user or not verify_password(user["password_hash"], req.password):
                raise HTTPException(status_code=401, detail="Virheellinen käyttäjätunnus tai salasana")
            
            token = generate_token(user["username"], user["role"])
            return {
                "token": token,
                "username": user["username"],
                "role": user["role"]
            }
    except HTTPException as he:
        raise he
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Kirjautumisvirhe: {str(e)}")

@app.get("/api/auth/me")
def get_me(current_user: dict = Depends(get_current_user)):
    return current_user

# Admin Endpoints
@app.get("/api/admin/users")
def list_users(current_user: dict = Depends(require_roles(["Admin"]))):
    try:
        with get_db_cursor() as cur:
            cur.execute("SELECT id, username, role, created_at FROM users ORDER BY username;")
            return cur.fetchall()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

@app.put("/api/admin/users/{user_id}/role")
def update_user_role(user_id: int, req: RoleUpdateRequest, current_user: dict = Depends(require_roles(["Admin"]))):
    allowed_roles = ["Admin", "HeadEditor", "CoEditor", "Reader"]
    if req.role not in allowed_roles:
        raise HTTPException(status_code=400, detail=f"Virheellinen rooli. Sallitut: {allowed_roles}")
    
    try:
        with get_db_cursor(commit=True) as cur:
            cur.execute("UPDATE users SET role = %s WHERE id = %s RETURNING id, username, role;", (req.role, user_id))
            updated = cur.fetchone()
            if not updated:
                raise HTTPException(status_code=404, detail="Käyttäjää ei löydy")
            return updated
    except HTTPException as he:
        raise he
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

# Standard API endpoints (modified for RBAC)
@app.get("/api/categories")
def get_categories():
    try:
        with get_db_cursor() as cur:
            cur.execute("""
                SELECT id, code, name, domain, domain_code 
                FROM categories 
                ORDER BY domain_code, code;
            """)
            return cur.fetchall()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

@app.get("/api/books")
def get_books(
    q: Optional[str] = Query(None),
    category_id: Optional[int] = Query(None),
    domain: Optional[str] = Query(None),
    sort: str = Query("title")
):
    try:
        query_str = """
            SELECT b.id, b.category_id, b.author, b.title, b.publisher, b.year, b.isbn, b.language, b.stars, b.points, b.page_number, b.processes, b.kolahdukset,
                   c.code as category_code, c.name as category_name, c.domain as category_domain
            FROM books b
            LEFT JOIN categories c ON b.category_id = c.id
            WHERE 1=1
        """
        params = []

        if category_id is not None:
            query_str += " AND b.category_id = %s"
            params.append(category_id)

        if domain:
            query_str += " AND c.domain = %s"
            params.append(domain)

        if q:
            # Split query into words to support multi-word search (e.g. "ken robinson")
            search_terms = q.strip().split()
            for term in search_terms:
                if term:
                    term_lower = term.lower()
                    
                    # Prefix word boundary matching for short terms (length <= 3) in reviews
                    # to prevent false positives like "tom" in "suhteettoman" or "ken" in "kesken"
                    if len(term) <= 3 and term.isalnum():
                        review_cond = "EXISTS (SELECT 1 FROM reviews r WHERE r.book_id = b.id AND r.review_text ~* %s)"
                        review_pat = f"\\y{term}"
                    else:
                        review_cond = "EXISTS (SELECT 1 FROM reviews r WHERE r.book_id = b.id AND r.review_text ILIKE %s)"
                        review_pat = f"%{term}%"
                    
                    if term_lower == "tom":
                        # Support mapping "tom" to "thomas" in author name search
                        query_str += f""" AND (
                            b.title ILIKE %s OR 
                            b.author ILIKE %s OR 
                            b.author ILIKE %s OR
                            b.publisher ILIKE %s OR 
                            b.isbn ILIKE %s OR 
                            b.processes ILIKE %s OR
                            {review_cond}
                        )"""
                        params.extend([f"%{term}%", f"%{term}%", "%thomas%", f"%{term}%", f"%{term}%", f"%{term}%", review_pat])
                    else:
                        query_str += f""" AND (
                            b.title ILIKE %s OR 
                            b.author ILIKE %s OR 
                            b.publisher ILIKE %s OR 
                            b.isbn ILIKE %s OR 
                            b.processes ILIKE %s OR
                            {review_cond}
                        )"""
                        params.extend([f"%{term}%", f"%{term}%", f"%{term}%", f"%{term}%", f"%{term}%", review_pat])




        if sort == "author":
            query_str += " ORDER BY b.author ASC, b.title ASC"
        elif sort == "stars":
            query_str += " ORDER BY b.stars DESC, b.title ASC"
        elif sort == "points":
            query_str += " ORDER BY b.points DESC, b.title ASC"
        elif sort == "kolahdukset":
            query_str += " ORDER BY b.kolahdukset DESC, b.title ASC"
        else:
            query_str += " ORDER BY b.title ASC"

        with get_db_cursor() as cur:
            cur.execute(query_str, params)
            return cur.fetchall()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

@app.get("/api/books/{book_id}")
def get_book_details(book_id: int, authorization: Optional[str] = Header(None)):
    # Optional authorization to see if the user liked the reviews
    user_id = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split("Bearer ", 1)[1]
        payload = verify_token(token)
        if payload:
            with get_db_cursor() as cur:
                cur.execute("SELECT id FROM users WHERE username = %s;", (payload["username"],))
                row = cur.fetchone()
                if row:
                    user_id = row["id"]

    try:
        with get_db_cursor() as cur:
            cur.execute("""
                SELECT b.id, b.category_id, b.author, b.title, b.publisher, b.year, b.isbn, b.language, b.stars, b.points, b.page_number, b.processes, b.kolahdukset,
                       c.code as category_code, c.name as category_name, c.domain as category_domain
                FROM books b
                LEFT JOIN categories c ON b.category_id = c.id
                WHERE b.id = %s;
            """, (book_id,))
            book = cur.fetchone()
            
            if not book:
                raise HTTPException(status_code=404, detail="Book not found")

            # Fetch reviews with like stats
            cur.execute("""
                SELECT r.id, r.reviewer_name, r.rating, r.review_text, r.created_at,
                       (SELECT COUNT(*) FROM review_likes WHERE review_id = r.id) as likes_count,
                       EXISTS(SELECT 1 FROM review_likes WHERE review_id = r.id AND user_id = %s) as user_liked
                FROM reviews r
                WHERE r.book_id = %s
                ORDER BY r.created_at ASC;
            """, (user_id, book_id))
            reviews = cur.fetchall()
            
            book["reviews"] = reviews
            return book
    except HTTPException as he:
        raise he
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

# Create / Edit / Delete Books
@app.post("/api/books")
def create_book(book: BookCreateOrUpdate, current_user: dict = Depends(require_roles(["Admin", "HeadEditor", "CoEditor"]))):
    try:
        # CoEditor permissions limitation: CoEditors cannot set stars, points, processes, or kolahdukset
        stars = book.stars
        points = book.points
        processes = book.processes
        kolahdukset = book.kolahdukset
        
        if current_user["role"] == "CoEditor":
            stars = 1
            points = 0
            processes = ""
            kolahdukset = 0

        with get_db_cursor(commit=True) as cur:
            cur.execute("""
                INSERT INTO books (category_id, author, title, publisher, year, isbn, language, stars, points, processes, kolahdukset)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id;
            """, (
                book.category_id, book.author, book.title, book.publisher, book.year,
                book.isbn, book.language, stars, points, processes, kolahdukset
            ))
            book_id = cur.fetchone()["id"]
            
            # Create a default review entry for this book
            stars_str = "★" * stars + "☆" * (3 - stars)
            review_text = f"Teos lisätty tietokantaan käyttäjän {current_user['username']} toimesta."
            if current_user["role"] != "CoEditor":
                review_text += f" Suositus: {stars_str} ({stars} tähteä), kirjapisteet: {points} p."
                
            cur.execute("""
                INSERT INTO reviews (book_id, reviewer_name, rating, review_text)
                VALUES (%s, %s, %s, %s);
            """, (book_id, current_user["username"], stars or 1, review_text))
            
            return {"id": book_id, "detail": "Kirja lisätty onnistuneesti"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Kirjan lisäys epäonnistui: {str(e)}")

@app.put("/api/books/{book_id}")
def update_book(book_id: int, book: BookCreateOrUpdate, current_user: dict = Depends(require_roles(["Admin", "HeadEditor", "CoEditor"]))):
    try:
        with get_db_cursor(commit=True) as cur:
            cur.execute("SELECT id, stars, points, processes, kolahdukset FROM books WHERE id = %s;", (book_id,))
            existing = cur.fetchone()
            if not existing:
                raise HTTPException(status_code=404, detail="Kirjaa ei löydy")
            
            # CoEditor role cannot modify rating/assessment fields
            if current_user["role"] == "CoEditor":
                stars = existing["stars"]
                points = existing["points"]
                processes = existing["processes"]
                kolahdukset = existing["kolahdukset"]
            else:
                stars = book.stars
                points = book.points
                processes = book.processes
                kolahdukset = book.kolahdukset

            cur.execute("""
                UPDATE books 
                SET category_id = %s, author = %s, title = %s, publisher = %s, year = %s, 
                    isbn = %s, language = %s, stars = %s, points = %s, processes = %s, kolahdukset = %s
                WHERE id = %s;
            """, (
                book.category_id, book.author, book.title, book.publisher, book.year,
                book.isbn, book.language, stars, points, processes, kolahdukset, book_id
            ))
            return {"detail": "Kirjan tiedot päivitetty"}
    except HTTPException as he:
        raise he
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Kirjan päivitys epäonnistui: {str(e)}")

@app.delete("/api/books/{book_id}")
def delete_book(book_id: int, current_user: dict = Depends(require_roles(["Admin", "HeadEditor"]))):
    try:
        with get_db_cursor(commit=True) as cur:
            cur.execute("DELETE FROM books WHERE id = %s RETURNING id;", (book_id,))
            deleted = cur.fetchone()
            if not deleted:
                raise HTTPException(status_code=404, detail="Kirjaa ei löydy")
            return {"detail": "Kirja poistettu tietokannasta"}
    except HTTPException as he:
        raise he
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Kirjan poisto epäonnistui: {str(e)}")

# Comments / Reviews
@app.post("/api/books/{book_id}/reviews")
def add_review(book_id: int, review: ReviewCreate, current_user: dict = Depends(get_current_user)):
    try:
        with get_db_cursor(commit=True) as cur:
            cur.execute("SELECT id FROM books WHERE id = %s;", (book_id,))
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="Kirjaa ei löydy")

            cur.execute("""
                INSERT INTO reviews (book_id, reviewer_name, rating, review_text)
                VALUES (%s, %s, %s, %s)
                RETURNING id, book_id, reviewer_name, rating, review_text, created_at;
            """, (
                book_id,
                current_user["username"],
                review.rating,
                review.review_text
            ))
            new_review = cur.fetchone()
            new_review["likes_count"] = 0
            new_review["user_liked"] = False
            return new_review
    except HTTPException as he:
        raise he
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Kommentin lisäys epäonnistui: {str(e)}")

# Peukutus / Upvotes
@app.post("/api/reviews/{review_id}/like")
def like_review(review_id: int, current_user: dict = Depends(get_current_user)):
    try:
        with get_db_cursor(commit=True) as cur:
            # Check if review exists
            cur.execute("SELECT id FROM reviews WHERE id = %s;", (review_id,))
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="Arvostelua ei löydy")
            
            cur.execute("""
                INSERT INTO review_likes (user_id, review_id)
                VALUES (%s, %s)
                ON CONFLICT (user_id, review_id) DO NOTHING;
            """, (current_user["id"], review_id))
            return {"detail": "Arvostelua peukutettu"}
    except HTTPException as he:
        raise he
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Peukutus epäonnistui: {str(e)}")

@app.delete("/api/reviews/{review_id}/like")
def unlike_review(review_id: int, current_user: dict = Depends(get_current_user)):
    try:
        with get_db_cursor(commit=True) as cur:
            cur.execute("""
                DELETE FROM review_likes 
                WHERE user_id = %s AND review_id = %s;
            """, (current_user["id"], review_id))
            return {"detail": "Peukutus poistettu"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Peukutuksen poisto epäonnistui: {str(e)}")

@app.get("/api/stats")
def get_stats():
    try:
        with get_db_cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM books;")
            total_books = cur.fetchone()["count"]

            cur.execute("SELECT COUNT(*) FROM categories;")
            total_categories = cur.fetchone()["count"]

            cur.execute("SELECT COUNT(*) FROM reviews;")
            total_reviews = cur.fetchone()["count"]

            cur.execute("SELECT COALESCE(SUM(kolahdukset), 0) FROM books;")
            total_insights = cur.fetchone()["coalesce"]

            return {
                "total_books": total_books,
                "total_categories": total_categories,
                "total_reviews": total_reviews,
                "total_insights": total_insights
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

# Serve frontend
@app.get("/", response_class=HTMLResponse)
def get_index():
    index_path = os.path.join(os.path.dirname(__file__), "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return f.read()
    return HTMLResponse("<h1>index.html not found! Please check configuration.</h1>", status_code=404)

@app.get("/johannes.jpg")
def get_johannes_image():
    image_path = os.path.join(os.path.dirname(__file__), "johannes.jpg")
    if os.path.exists(image_path):
        return FileResponse(image_path)
    raise HTTPException(status_code=404, detail="Image not found")

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    host = "0.0.0.0" if "RENDER" in os.environ else "127.0.0.1"
    reload = False if "RENDER" in os.environ else True
    uvicorn.run("app:app", host=host, port=port, reload=reload)

