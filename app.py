import sqlite3
import uuid
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from flask_socketio import SocketIO, send, disconnect, join_room, leave_room, emit
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
    # PERMANENT_SESSION_LIFETIME = 3600,  # 1시간(필요에 맞게)
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
                bio TEXT,
                is_admin   INTEGER NOT NULL DEFAULT 0,
                is_banned  INTEGER NOT NULL DEFAULT 0
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
                target_type TEXT NOT NULL,        -- 'user' 또는 'product'
                target_id   TEXT NOT NULL,
                reason      TEXT NOT NULL,
                status      TEXT NOT NULL DEFAULT '관리자 처리 중',
                timestamp   DATETIME NOT NULL,
                FOREIGN KEY(reporter_id) REFERENCES user(id)
            )
        """)
        # 채팅방 테이블
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS chat_room (
            id TEXT PRIMARY KEY,
            product_id TEXT NOT NULL,
            buyer_id TEXT NOT NULL,
            seller_id TEXT NOT NULL,
            FOREIGN KEY(product_id) REFERENCES product(id),
            FOREIGN KEY(buyer_id)   REFERENCES user(id),
            FOREIGN KEY(seller_id)  REFERENCES user(id)
        )
        """)
        # 채팅 메시지 테이블
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS chat_message (
            id TEXT PRIMARY KEY,
            room_id TEXT NOT NULL,
            sender_id TEXT NOT NULL,
            message TEXT NOT NULL,
            timestamp DATETIME NOT NULL,
            FOREIGN KEY(room_id)   REFERENCES chat_room(id),
            FOREIGN KEY(sender_id) REFERENCES user(id)
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

# 비밀번호 변경
@app.route('/change_password', methods=['GET', 'POST'])
@login_required
@limiter.limit("2 per hour", methods=["POST"])
def change_password():
    if request.method == 'POST':
        # ── 입력값 ──
        form             = request.form
        raw_current_pw   = form.get("current_password", "")
        raw_new_pw       = form.get("new_password", "")
        raw_confirm_pw   = form.get("confirm_password", "")

        # ── 비즈니스 로직 ──
        # 새 비밀번호 일치 여부 검사
        if raw_new_pw != raw_confirm_pw:
            flash('새 비밀번호가 일치하지 않습니다.')
            return redirect(url_for('change_password'))

        # 새 비밀번호 정책 검사
        try:
            current_pw = validate_password(raw_current_pw)
            new_pw = validate_password(raw_new_pw)
        except ValueError as e:
            flash(str(e))
            return redirect(url_for('change_password'))

        db = get_db()
        cursor = db.cursor()
        # 현재 비밀번호 해시 조회
        cursor.execute("SELECT password FROM user WHERE id = ?", (session['user_id'],))
        row = cursor.fetchone()

        # 현재 비밀번호 검증
        if not row or not check_password_hash(row['password'], current_pw):
            flash('현재 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('change_password'))

        # 업데이트
        new_hash = generate_password_hash(new_pw)
        cursor.execute(
            "UPDATE user SET password = ? WHERE id = ?",
            (new_hash, session['user_id'])
        )
        db.commit()

        flash('비밀번호가 성공적으로 변경되었습니다.')
        return redirect(url_for('profile'))

    # GET 요청일 때는 템플릿 렌더링
    return render_template('change_password.html')


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
            # ── 금지된 사용자 차단 ──
            if user['is_banned']:
                flash('접근이 제한된 계정입니다. 관리자에게 문의하세요.')
                return redirect(url_for('index'))
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
        cursor.execute(
            "UPDATE user SET bio = ? WHERE id = ?",
            (bio, session['user_id'])
        )
        db.commit()
        flash('프로필이 업데이트되었습니다.')
        return redirect(url_for('profile'))

    # GET 요청 시 사용자 정보 + 본인이 등록한 상품 조회
    db = get_db()
    cursor = db.cursor()

    # 사용자 정보
    cursor.execute(
        "SELECT * FROM user WHERE id = ?",
        (session['user_id'],)
    )
    user = cursor.fetchone()

    # 사용자가 등록한 상품
    cursor.execute(
        "SELECT * FROM product WHERE seller_id = ?",
        (session['user_id'],)
    )
    products = cursor.fetchall()

    return render_template('profile.html', user=user, products=products)

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

# 공개 사용자 프로필 보기
@app.route('/user/<user_id>')
@login_required
def user_profile(user_id):
    # ── 본인 계정이면 /profile 로 자동 리다이렉트 ──
    if user_id == session.get('user_id'):
        return redirect(url_for('profile'))

    # ID 유효성 검사
    if not validate_uuid4(user_id):
        flash("잘못된 사용자 요청입니다.")
        return redirect(url_for('dashboard'))

    db = get_db()
    cursor = db.cursor()
    # 사용자 정보 조회 (id 포함)
    cursor.execute(
        "SELECT id, username, bio FROM user WHERE id = ?",
        (user_id,)
    )
    user = cursor.fetchone()
    if not user:
        flash("존재하지 않는 사용자입니다.")
        return redirect(url_for('dashboard'))

    # 해당 사용자가 등록한 상품 조회
    cursor.execute(
        "SELECT * FROM product WHERE seller_id = ?",
        (user_id,)
    )
    products = cursor.fetchall()

    return render_template('user_profile.html', user=user, products=products)

@app.route('/product/<product_id>/delete', methods=['POST'])
@login_required
@limiter.limit("2 per minute", methods=["POST"])
def delete_product(product_id):
    # ── 입력값  ──
    form = request.form
    raw_next = form.get('next', 'dashboard')

    # ── next 파라미터 화이트리스트 검증 ──
    allowed = {'dashboard', 'profile'}
    next_page = raw_next if raw_next in allowed else 'dashboard'

    # ── ID 유효성 검사 ──
    if not validate_uuid4(product_id):
        flash("잘못된 요청입니다.")
        return redirect(url_for(next_page))

    db = get_db()
    cursor = db.cursor()

    # 2) 상품 조회
    cursor.execute("SELECT seller_id FROM product WHERE id = ?", (product_id,))
    row = cursor.fetchone()
    if not row:
        flash("존재하지 않는 상품입니다.")
        return redirect(url_for(next_page))

    # 본인 여부 확인
    if row['seller_id'] != session['user_id']:
        flash("삭제 권한이 없습니다.")
        return redirect(url_for('view_product', product_id=product_id, next=next_page))

    # ── 삭제 실행 ──
    cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
    db.commit()
    flash("상품이 삭제되었습니다.")

    # ── 원래 페이지로 복귀 ──
    return redirect(url_for(next_page))

@app.route('/report', methods=['GET', 'POST'])
@limiter.limit("2 per minute", methods=["POST"])
@login_required
def report():
    db = get_db()
    cursor = db.cursor()

    if request.method == 'POST':
        # ── POST: 폼 제출 처리 ──
        target_type = request.form['target_type']
        target_id   = request.form['target_id']
        try:
            # ID 형식 검사
            if not validate_uuid4(target_id):
                raise ValueError("유효하지 않은 대상입니다.")
            # 사유만 입력받음
            reason = clean_text(request.form['reason'], max_len=300)
        except ValueError as e:
            flash(str(e))
            return redirect(request.url)

        # 저장
        cursor.execute(
            "INSERT INTO report "
            "(id, reporter_id, target_type, target_id, reason, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (str(uuid.uuid4()),
             session['user_id'],
             target_type,
             target_id,
             reason,
             datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'))
        )
        db.commit()
        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))

    # ── GET: 신고 폼 렌더링 ──
    target_type = request.args.get('target_type', '')
    target_id   = request.args.get('target_id', '')

    # 빈 값 혹은 유효하지 않은 UUID4 처리
    is_valid = False
    if target_id:
        try:
            is_valid = validate_uuid4(target_id)
        except ValueError:
            is_valid = False
    if target_type not in ('user','product') or not is_valid:
        flash("신고 대상이 지정되지 않았습니다.")
        return redirect(url_for('dashboard'))

    # UUID 검증 (빈 값이 아님을 보장했으므로 _require 에러 없음)
    if not validate_uuid4(target_id):
        flash("유효하지 않은 대상 ID입니다.")
        return redirect(url_for('dashboard'))

    # DB 조회하여 라벨 생성
    if target_type == 'product':
        cursor.execute("SELECT title FROM product WHERE id = ?", (target_id,))
        row = cursor.fetchone()
        if not row:
            flash("존재하지 않는 상품입니다.")
            return redirect(url_for('dashboard'))
        target_label = f"상품 “{row['title']}”"
    else:
        cursor.execute("SELECT username FROM user WHERE id = ?", (target_id,))
        row = cursor.fetchone()
        if not row:
            flash("존재하지 않는 사용자입니다.")
            return redirect(url_for('dashboard'))
        target_label = f"사용자 “{row['username']}”"

    return render_template(
        'report.html',
        target_type=target_type,
        target_id=target_id,
        target_label=target_label
    )


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

@app.route('/chat')
@login_required
def chat_list():
    db = get_db()
    cursor = db.cursor()
    uid = session['user_id']
    # 자신이 참여한 방(구매자 또는 판매자)
    cursor.execute("""
      SELECT
        cr.id          AS room_id,
        p.title        AS product_title,
        cr.buyer_id    AS buyer_id,
        cr.seller_id   AS seller_id,
        seller.username AS seller_name,
        buyer.username  AS buyer_name
      FROM chat_room cr
      JOIN product p      ON cr.product_id = p.id
      JOIN user seller    ON cr.seller_id  = seller.id
      JOIN user buyer     ON cr.buyer_id   = buyer.id
      WHERE cr.buyer_id = ?
         OR cr.seller_id = ?
    """, (uid, uid))
    rooms = cursor.fetchall()
    return render_template('chat_list.html', rooms=rooms)

@app.route('/chat/<room_id>')
@login_required
def chat_room(room_id):
    if not validate_uuid4(room_id):
        flash("잘못된 요청입니다.")
        return redirect(url_for('chat_list'))

    db = get_db()
    cursor = db.cursor()

    # 방 정보 & 권한 확인
    cursor.execute("""
      SELECT cr.product_id, p.title, cr.buyer_id, cr.seller_id
      FROM chat_room cr
      JOIN product p ON cr.product_id = p.id
      WHERE cr.id = ?
    """, (room_id,))
    room = cursor.fetchone()
    if not room or session['user_id'] not in (room['buyer_id'], room['seller_id']):
        flash("접근 권한이 없습니다.")
        return redirect(url_for('chat_list'))

    # 메시지 이력
    cursor.execute("""
      SELECT cm.sender_id, cm.message, cm.timestamp, u.username
      FROM chat_message cm
      JOIN user u ON cm.sender_id = u.id
      WHERE cm.room_id = ?
      ORDER BY cm.timestamp
    """, (room_id,))
    messages = cursor.fetchall()

    # 상대방 이름
    other_id = room['seller_id'] if session['user_id']==room['buyer_id'] else room['buyer_id']
    cursor.execute("SELECT username FROM user WHERE id = ?", (other_id,))
    other = cursor.fetchone()

    return render_template('chat_room.html',
                           room_id=room_id,
                           product_title=room['title'],
                           other_name=other['username'],
                           messages=messages)

@socketio.on('join_room')
@login_required
def on_join(data):
    room = data.get('room_id')
    join_room(room)   # flask-socketio 기능

@socketio.on('send_message')
@login_required
def handle_send_message_event(data):
    room_id = data.get('room_id')
    text    = data.get('message', '').strip()
    uid     = session['user_id']
    if not room_id or not text:
        return

    # 1) DB 저장
    ts = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
      "INSERT INTO chat_message (id, room_id, sender_id, message, timestamp) "
      "VALUES (?, ?, ?, ?, ?)",
      (str(uuid.uuid4()), room_id, uid, text, ts)
    )
    db.commit()

    # 2) 같은 방의 클라이언트에게만 브로드캐스트
    payload = {
      'username':    session.get('username'),
      'message':     text,
      'timestamp':   ts
    }
    emit('chat_message', payload, to=room_id)
    
@app.route('/product/<product_id>/chat', methods=['POST'])
@login_required
@limiter.limit("5 per minute", methods=["POST"])
def start_chat(product_id):
    # 상품 ID 유효성 검사
    if not validate_uuid4(product_id):
        flash("잘못된 요청입니다.")
        return redirect(url_for('dashboard'))

    db = get_db()
    cursor = db.cursor()

    # 상품과 판매자 조회
    cursor.execute("SELECT seller_id FROM product WHERE id = ?", (product_id,))
    row = cursor.fetchone()
    if not row:
        flash("존재하지 않는 상품입니다.")
        return redirect(url_for('dashboard'))
    seller_id = row['seller_id']
    buyer_id  = session['user_id']

    # 본인 게시글이면 프로필로
    if seller_id == buyer_id:
        return redirect(url_for('profile'))

    # 기존에 생성된 채팅방이 있는지 체크
    cursor.execute("""
        SELECT id
        FROM chat_room
        WHERE product_id = ? AND buyer_id = ? AND seller_id = ?
    """, (product_id, buyer_id, seller_id))
    room = cursor.fetchone()
    if room:
        room_id = room['id']
    else:
        # 새 방 생성
        room_id = str(uuid.uuid4())
        cursor.execute("""
            INSERT INTO chat_room (id, product_id, buyer_id, seller_id)
            VALUES (?, ?, ?, ?)
        """, (room_id, product_id, buyer_id, seller_id))
        db.commit()

    # 채팅방 페이지로 이동
    return redirect(url_for('chat_room', room_id=room_id))

@app.route('/my_reports')
@login_required
def user_report():
    db = get_db()
    cursor = db.cursor()
    uid = session['user_id']
    cursor.execute("""
      SELECT id, target_type, target_id, reason, status, timestamp
      FROM report
      WHERE reporter_id = ?
      ORDER BY timestamp DESC
    """, (uid,))
    rows = cursor.fetchall()

    # 분류 & 라벨링
    user_reports = []
    product_reports = []
    for r in rows:
        entry = dict(r)
        if r['target_type'] == 'product':
            cursor.execute("SELECT title FROM product WHERE id = ?", (r['target_id'],))
            p = cursor.fetchone()
            entry['label'] = p and p['title'] or '알 수 없는 상품'
            product_reports.append(entry)
        else:
            cursor.execute("SELECT username FROM user WHERE id = ?", (r['target_id'],))
            u = cursor.fetchone()
            entry['label'] = u and u['username'] or '알 수 없는 사용자'
            user_reports.append(entry)

    return render_template('report_history.html',
                           product_reports=product_reports,
                           user_reports=user_reports)


if __name__ == '__main__':
    init_db()  # 앱 컨텍스트 내에서 테이블 생성
    socketio.run(app, debug=True)
