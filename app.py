import sqlite3
import uuid
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from flask_socketio import SocketIO, send, disconnect
from werkzeug.security import generate_password_hash, check_password_hash 
from functools import wraps
from flask_wtf import CSRFProtect
import os
import secrets      
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime, timedelta

# import validation helpers from separate module
from validators import (
    validate_username,
    validate_password,
    validate_uuid4,
    clean_text,
    validate_price,
)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY") or secrets.token_hex(32)
DATABASE = 'market.db'
socketio = SocketIO(app)

csrf = CSRFProtect(app)

app.config.update(
    SESSION_COOKIE_SECURE = True,       # HTTPS 전용
    SESSION_COOKIE_HTTPONLY = True,     # JS 접근 차단
    SESSION_COOKIE_SAMESITE = "Lax",    # 필요하면 Strict
    PERMANENT_SESSION_LIFETIME = 3600,  # 1시간(필요에 맞게)
)

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

limiter.init_app(app)

# 데이터베이스 연결 관리: 요청마다 연결 생성 후 사용, 종료 시 close
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # 결과를 dict처럼 사용하기 위함
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# 테이블 생성 (최초 실행 시에만)
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        # 사용자 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT
            )
        """)
        # 상품 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price NUMERIC NOT NULL CHECK(price > 0),
                seller_id TEXT NOT NULL
            )
        """)
        # 신고 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL
            )
        """)
        db.commit()

def login_required(view_func):
    """Decorator to enforce authentication for routes."""
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("로그인이 필요합니다.")
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)
    return wrapper

# 기본 라우트
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# 회원가입
@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("2 per hour", methods=["POST"])
def register():
    if request.method == 'POST':
        # ── 입력값 ──
        form = request.form
        raw_username          = form.get("username", "")
        raw_password            = form.get("password", "")
        raw_password_confirm    = form.get("password_confirm", "")

        # ── 비즈니스 로직 ──
        if raw_password != raw_password_confirm:
            flash('비밀번호가 일치하지 않습니다.')
            return redirect(url_for('register'))

        # 유효성 검사
        try:
            username = validate_username(raw_username)
            password = validate_password(raw_password)
        except ValueError as e:
            flash(str(e))
            return redirect(url_for("register"))
        
        db = get_db()
        cursor = db.cursor()
        # 중복 사용자 체크
        cursor.execute("SELECT 1 FROM user WHERE username = ?", (username,))
        if cursor.fetchone():
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        user_id = str(uuid.uuid4())
        cursor.execute("INSERT INTO user (id, username, password) VALUES (?, ?, ?)",
                       (user_id, username, hashed_password))
        db.commit()
        flash('회원가입이 완료되었습니다. 로그인 해주세요.')
        return redirect(url_for('login'))
    return render_template('register.html')

# 로그인
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("2 per minute", methods=["POST"])
def login():
    if request.method == 'POST':
        # ── 입력값 ──
        form = request.form
        raw_username = form.get("username", "").strip()
        raw_password = form.get("password", "")

        # ── 비즈니스 로직 ──
        try:
            username = validate_username(raw_username)
            password = validate_password(raw_password)
        except ValueError as e:
            flash(str(e))
            return redirect(url_for("login"))

        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        user = cursor.fetchone()
        if user and check_password_hash(user['password'], password):
            session.clear()  # 세션 고정 공격 방지
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('로그인 성공!')
            return redirect(url_for('dashboard'))
        else:
            flash('아이디 또는 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('login'))
    return render_template('login.html')

# 로그아웃
@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

# 대시보드: 사용자 정보와 전체 상품 리스트 표시
@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    cursor = db.cursor()
    # 현재 사용자 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    # 모든 상품 조회
    cursor.execute("SELECT * FROM product")
    all_products = cursor.fetchall()
    return render_template('dashboard.html', products=all_products, user=current_user)

# 프로필 페이지: bio 업데이트 가능
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        # ── 입력값 ──
        raw_bio = request.form.get("bio", "")
        try:
            bio = clean_text(raw_bio, max_len=300, blank_ok=True)
        except ValueError as e:
            flash(str(e))
            return redirect(url_for("profile"))

        db = get_db()
        cursor = db.cursor()
        cursor.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, session['user_id']))
        db.commit()
        flash('프로필이 업데이트되었습니다.')
        return redirect(url_for('profile'))

    cursor = get_db().cursor()
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    return render_template('profile.html', user=cursor.fetchone())

# 상품 등록
@app.route('/product/new', methods=['GET', 'POST'])
@login_required
@limiter.limit("2 per minute", methods=["POST"])
def new_product():
    if request.method == "POST":
        # ── 입력값 ──
        form = request.form
        raw_title       = form.get("title", "")
        raw_description = form.get("description", "")
        raw_price       = form.get("price", "")

        # ── 비즈니스 로직 ──
        try:
            title       = clean_text(raw_title, max_len=100)
            description = clean_text(raw_description, blank_ok=True)
            price       = validate_price(raw_price)
        except ValueError as e:
            flash(str(e))
            return redirect(url_for("new_product"))
        db = get_db()
        cursor = db.cursor()
        cursor.execute(
            "INSERT INTO product (id, title, description, price, seller_id) VALUES (?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), title, description, str(price), session['user_id'])
        )
        db.commit()
        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('new_product.html')

# 상품 상세보기
@app.route('/product/<product_id>')
@login_required
def view_product(product_id):
    if not validate_uuid4(product_id):
        flash("잘못된 상품 ID입니다.")
        return redirect(url_for("dashboard"))
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    # 판매자 정보 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (product['seller_id'],))
    seller = cursor.fetchone()
    return render_template('view_product.html', product=product, seller=seller)

# 신고하기
@app.route('/report', methods=['GET', 'POST'])
@limiter.limit("2 per minute", methods=["POST"])
@login_required
def report():
    if request.method == 'POST':
        # ── 입력값 ──
        form      = request.form
        raw_target_id = form.get("target_id", "")
        raw_reason= form.get("reason", "")

        # ── 비즈니스 로직 ──
        try:
            if not validate_uuid4(raw_target_id):
                raise ValueError("대상이 유효하지 않습니다.")
            reason = clean_text(raw_reason, max_len=300)
        except ValueError as e:
            flash(str(e))
            return redirect(url_for("report"))
        
        db = get_db()
        cursor = db.cursor()
        cursor.execute(
            "INSERT INTO report (id, reporter_id, target_id, reason) VALUES (?, ?, ?, ?)",
            (str(uuid.uuid4()), session['user_id'], raw_target_id, reason)
        )
        db.commit()
        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('report.html')

msg_history = {}

# 실시간 채팅: 클라이언트가 메시지를 보내면 전체 브로드캐스트
@socketio.on('send_message')
@login_required
def handle_send_message_event(data):
    # ── 입력값 ──
    uid           = session['user_id']
    now           = datetime.utcnow()
    raw_msg       = data.get("message", "")

    # ── 비즈니스 로직 ──
    window = now - timedelta(seconds=60)
    msg_history.setdefault(uid, []).append(now)
    # 60초 이내 30개 초과 시 무시
    msg_history[uid] = [t for t in msg_history[uid] if t > window]
    if len(msg_history[uid]) > 3:
        return
    
    try:
        msg = clean_text(raw_msg, max_len=1000)
    except ValueError as e:
        flash(str(e))
        return
    payload = {
        "message_id": str(uuid.uuid4()),
        "sender": uid,
        "username": session.get('username', 'Unknown'),
        "message": msg,
    }
    send(payload, broadcast=True)
    # data['message_id'] = str(uuid.uuid4())
    # send(data, broadcast=True)

if __name__ == '__main__':
    init_db()  # 앱 컨텍스트 내에서 테이블 생성
    socketio.run(app, debug=True)
