import os
import secrets
import sqlite3
import uuid
from datetime import date, datetime
from decimal import Decimal, InvalidOperation
from functools import wraps
from io import BytesIO
from pathlib import Path

from flask import Flask, abort, flash, g, redirect, render_template, request, send_file, send_from_directory, session, url_for
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parent
DATA = Path(os.environ.get('WAREHOUSE_DATA_DIR', ROOT / 'instance'))
UPLOADS = Path(os.environ.get('WAREHOUSE_UPLOAD_DIR', ROOT / 'uploads'))
DATA.mkdir(parents=True, exist_ok=True)
UPLOADS.mkdir(parents=True, exist_ok=True)
KEY_FILE = DATA / 'secret.key'
if not KEY_FILE.exists():
    KEY_FILE.write_text(secrets.token_hex(32), encoding='utf-8')
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or KEY_FILE.read_text(encoding='utf-8').strip()
app.config['MAX_CONTENT_LENGTH'] = 8 * 1024 * 1024
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('COOKIE_SECURE') == '1'
DB = DATA / 'warehouse.db'
Q = 1000

SCHEMA = '''
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT NOT NULL, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','staff')), created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY, sku TEXT NOT NULL UNIQUE, name TEXT NOT NULL, species TEXT, grade TEXT, width_mm INTEGER, length_mm INTEGER, thickness_mm TEXT, unit TEXT NOT NULL, photo TEXT, note TEXT, active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS partners (id INTEGER PRIMARY KEY, name TEXT NOT NULL, kind TEXT NOT NULL, phone TEXT, email TEXT, address TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS orders (id INTEGER PRIMARY KEY, number TEXT NOT NULL UNIQUE, customer_id INTEGER REFERENCES partners(id), sender_id INTEGER REFERENCES partners(id), expected_date TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'planned', note TEXT, created_by INTEGER REFERENCES users(id), created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS order_lines (id INTEGER PRIMARY KEY, order_id INTEGER NOT NULL REFERENCES orders(id), product_id INTEGER NOT NULL REFERENCES products(id), expected_qty INTEGER NOT NULL CHECK(expected_qty>0), received_qty INTEGER NOT NULL DEFAULT 0 CHECK(received_qty>=0 AND received_qty<=expected_qty), note TEXT);
CREATE TABLE IF NOT EXISTS batches (id INTEGER PRIMARY KEY, product_id INTEGER NOT NULL REFERENCES products(id), code TEXT NOT NULL, qty INTEGER NOT NULL DEFAULT 0 CHECK(qty>=0), created_at TEXT NOT NULL, UNIQUE(product_id,code));
CREATE TABLE IF NOT EXISTS movements (id INTEGER PRIMARY KEY, product_id INTEGER NOT NULL REFERENCES products(id), batch_id INTEGER NOT NULL REFERENCES batches(id), order_id INTEGER REFERENCES orders(id), kind TEXT NOT NULL CHECK(kind IN ('receipt','dispatch','adjustment')), qty INTEGER NOT NULL CHECK(qty!=0), partner_id INTEGER REFERENCES partners(id), reference TEXT, note TEXT, actor_id INTEGER REFERENCES users(id), created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, actor_id INTEGER REFERENCES users(id), action TEXT NOT NULL, entity TEXT NOT NULL, entity_id INTEGER, details TEXT, created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_orders_date ON orders(expected_date);
CREATE INDEX IF NOT EXISTS idx_movements_time ON movements(created_at);
'''

def now():
    return datetime.now().astimezone().isoformat(timespec='seconds')

def conn():
    if 'db' not in g:
        g.db = sqlite3.connect(DB, timeout=15, isolation_level=None)
        g.db.row_factory = sqlite3.Row
        g.db.execute('PRAGMA foreign_keys=ON')
        g.db.execute('PRAGMA busy_timeout=15000')
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop('db', None)
    if db is not None:
        db.close()

with sqlite3.connect(DB) as db:
    db.executescript(SCHEMA)
    db.execute('PRAGMA journal_mode=WAL')

def one(sql, params=()):
    return conn().execute(sql, params).fetchone()

def all_rows(sql, params=()):
    return conn().execute(sql, params).fetchall()

def amount(raw, positive=True):
    try:
        value = Decimal(str(raw).replace(',', '.').strip()) * Q
        if value != value.to_integral_value() or (positive and value <= 0):
            raise ValueError
        return int(value)
    except (InvalidOperation, ValueError, TypeError):
        raise ValueError('Вкажіть додатну кількість з точністю до 0,001.')

def fmt(qty):
    return f'{Decimal(qty or 0) / Q:,.3f}'.replace(',', ' ').replace('.', ',')

app.jinja_env.filters['qty'] = fmt

def audit(action, entity, entity_id, details=''):
    conn().execute('INSERT INTO audit(actor_id,action,entity,entity_id,details,created_at) VALUES(?,?,?,?,?,?)', (session.get('uid'), action, entity, entity_id, details, now()))

def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get('uid'):
            return redirect(url_for('login'))
        return fn(*args, **kwargs)
    return wrapped

def admin_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get('uid'):
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            abort(403)
        return fn(*args, **kwargs)
    return wrapped

@app.before_request
def guard():
    if not one('SELECT id FROM users LIMIT 1') and request.endpoint not in ('setup', 'static'):
        return redirect(url_for('setup'))
    if request.method == 'POST':
        if not session.get('csrf') or request.form.get('csrf') != session['csrf']:
            abort(400, 'Невірний токен форми. Оновіть сторінку.')

@app.context_processor
def globals_for_templates():
    if 'csrf' not in session:
        session['csrf'] = secrets.token_urlsafe(24)
    return {'today': date.today().isoformat(), 'current_user': session.get('name'), 'is_admin': session.get('role') == 'admin', 'csrf': session['csrf']}

@app.route('/setup', methods=['GET','POST'])
def setup():
    if one('SELECT id FROM users LIMIT 1'):
        return redirect(url_for('login'))
    if request.method == 'POST':
        name = request.form.get('name','').strip()
        username = request.form.get('username','').strip().lower()
        password = request.form.get('password','')
        if not name or not username or len(password) < 8:
            flash('Заповніть ім’я, логін і пароль від 8 символів.', 'error')
        else:
            conn().execute('INSERT INTO users(name,username,password_hash,role,created_at) VALUES(?,?,?,?,?)', (name,username,generate_password_hash(password),'admin',now()))
            flash('Адміністратора створено. Увійдіть.', 'success')
            return redirect(url_for('login'))
    return render_template('auth.html', title='Перший запуск', setup=True)

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        user = one('SELECT * FROM users WHERE username=?', (request.form.get('username','').strip().lower(),))
        if user and check_password_hash(user['password_hash'], request.form.get('password','')):
            session.clear()
            session.update(uid=user['id'], name=user['name'], role=user['role'], csrf=secrets.token_urlsafe(24))
            return redirect(url_for('dashboard'))
        flash('Невірний логін або пароль.', 'error')
    return render_template('auth.html', title='Вхід', setup=False)

@app.post('/logout')
@login_required
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    stats = {
        'products': one('SELECT COUNT(*) n FROM products WHERE active=1')['n'],
        'stock': one('SELECT COUNT(*) n FROM batches WHERE qty>0')['n'],
        'incoming': one("SELECT COUNT(*) n FROM orders WHERE status!='received' AND expected_date>=?", (date.today().isoformat(),))['n'],
        'due': one("SELECT COUNT(*) n FROM orders WHERE status!='received' AND expected_date<=?", (date.today().isoformat(),))['n'],
    }
    stock = all_rows('SELECT p.*, COALESCE(SUM(b.qty),0) stock FROM products p LEFT JOIN batches b ON b.product_id=p.id WHERE p.active=1 GROUP BY p.id ORDER BY p.name LIMIT 8')
    upcoming = all_rows('SELECT o.*, c.name customer, s.name sender, (SELECT COUNT(*) FROM order_lines l WHERE l.order_id=o.id AND l.received_qty<l.expected_qty) open_lines FROM orders o LEFT JOIN partners c ON c.id=o.customer_id LEFT JOIN partners s ON s.id=o.sender_id WHERE o.status!=\'received\' ORDER BY o.expected_date,o.id LIMIT 6')
    recent = all_rows('SELECT m.*,p.name product,p.unit,b.code batch,u.name actor FROM movements m JOIN products p ON p.id=m.product_id JOIN batches b ON b.id=m.batch_id LEFT JOIN users u ON u.id=m.actor_id ORDER BY m.id DESC LIMIT 7')
    return render_template('dashboard.html', stats=stats, stock=stock, upcoming=upcoming, recent=recent)

@app.route('/products', methods=['GET','POST'])
@login_required
def products():
    if request.method == 'POST':
        sku = request.form.get('sku','').strip()
        name = request.form.get('name','').strip()
        unit = request.form.get('unit','').strip()
        if not sku or not name or unit not in ('м²','лист','пачка','м³'):
            flash('Вкажіть артикул, назву та одиницю виміру.', 'error')
        else:
            photo = request.files.get('photo')
            filename = None
            if photo and photo.filename:
                ext = Path(secure_filename(photo.filename)).suffix.lower()
                if ext not in ('.jpg','.jpeg','.png','.webp'):
                    flash('Фото має бути JPG, PNG або WEBP.', 'error')
                    return redirect(url_for('products'))
                filename = f'{uuid.uuid4().hex}{ext}'
                photo.save(UPLOADS / filename)
            try:
                db = conn()
                db.execute('BEGIN IMMEDIATE')
                cur = db.execute('INSERT INTO products(sku,name,species,grade,width_mm,length_mm,thickness_mm,unit,photo,note,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)', (sku,name,request.form.get('species','').strip(),request.form.get('grade','').strip(),int(request.form['width_mm']) if request.form.get('width_mm') else None,int(request.form['length_mm']) if request.form.get('length_mm') else None,request.form.get('thickness_mm','').strip(),unit,filename,request.form.get('note','').strip(),now()))
                audit('Створено товар','product',cur.lastrowid,sku)
                db.commit()
                flash('Товар додано.', 'success')
                return redirect(url_for('products'))
            except (sqlite3.IntegrityError,ValueError):
                conn().rollback()
                if filename: (UPLOADS / filename).unlink(missing_ok=True)
                flash('Артикул уже існує або розміри задано некоректно.', 'error')
    query = request.args.get('q','').strip()
    rows = all_rows('SELECT p.*, COALESCE(SUM(b.qty),0) stock FROM products p LEFT JOIN batches b ON b.product_id=p.id WHERE p.active=1 AND (p.name LIKE ? OR p.sku LIKE ?) GROUP BY p.id ORDER BY p.name', (f'%{query}%',f'%{query}%'))
    return render_template('products.html', products=rows, q=query)

@app.get('/uploads/<path:name>')
@login_required
def uploaded(name):
    return send_from_directory(UPLOADS, name)

@app.route('/partners', methods=['GET','POST'])
@login_required
def partners():
    if request.method == 'POST':
        name = request.form.get('name','').strip()
        if not name:
            flash('Вкажіть назву партнера.', 'error')
        else:
            db=conn(); db.execute('BEGIN IMMEDIATE')
            cur=db.execute('INSERT INTO partners(name,kind,phone,email,address,created_at) VALUES(?,?,?,?,?,?)', (name,request.form.get('kind','контрагент'),request.form.get('phone','').strip(),request.form.get('email','').strip(),request.form.get('address','').strip(),now()))
            audit('Створено партнера','partner',cur.lastrowid,name); db.commit()
            flash('Партнера додано.', 'success'); return redirect(url_for('partners'))
    return render_template('partners.html', partners=all_rows('SELECT * FROM partners ORDER BY name'))

@app.route('/orders', methods=['GET','POST'])
@login_required
def orders():
    if request.method == 'POST':
        number=request.form.get('number','').strip(); expected=request.form.get('expected_date','').strip()
        product_ids=request.form.getlist('product_id[]'); quantities=request.form.getlist('quantity[]')
        try:
            date.fromisoformat(expected)
            if not number or not product_ids or len(product_ids)!=len(quantities): raise ValueError
            lines=[(int(pid),amount(qty)) for pid,qty in zip(product_ids,quantities)]
            if any(not one('SELECT id FROM products WHERE id=? AND active=1',(pid,)) for pid,_ in lines): raise ValueError
            customer=int(request.form['customer_id']) if request.form.get('customer_id') else None
            sender=int(request.form['sender_id']) if request.form.get('sender_id') else None
            db=conn(); db.execute('BEGIN IMMEDIATE')
            cur=db.execute('INSERT INTO orders(number,customer_id,sender_id,expected_date,note,created_by,created_at) VALUES(?,?,?,?,?,?,?)', (number,customer,sender,expected,request.form.get('note','').strip(),session['uid'],now()))
            oid=cur.lastrowid
            db.executemany('INSERT INTO order_lines(order_id,product_id,expected_qty) VALUES(?,?,?)',[(oid,pid,qty) for pid,qty in lines])
            audit('Створено очікувану поставку','order',oid,number); db.commit()
            flash('Поставку заплановано.', 'success'); return redirect(url_for('order_detail',oid=oid))
        except (ValueError,sqlite3.IntegrityError):
            conn().rollback(); flash('Перевірте номер, дату, товари, кількості та контрагентів. Номер має бути унікальним.', 'error')
    rows=all_rows('SELECT o.*, c.name customer, s.name sender, (SELECT COUNT(*) FROM order_lines WHERE order_id=o.id AND received_qty<expected_qty) remaining FROM orders o LEFT JOIN partners c ON c.id=o.customer_id LEFT JOIN partners s ON s.id=o.sender_id ORDER BY o.expected_date DESC,o.id DESC')
    return render_template('orders.html', orders=rows, products=all_rows('SELECT * FROM products WHERE active=1 ORDER BY name'), partners=all_rows('SELECT * FROM partners ORDER BY name'))

@app.get('/orders/<int:oid>')
@login_required
def order_detail(oid):
    order=one('SELECT o.*,c.name customer,s.name sender FROM orders o LEFT JOIN partners c ON c.id=o.customer_id LEFT JOIN partners s ON s.id=o.sender_id WHERE o.id=?',(oid,))
    if not order: abort(404)
    lines=all_rows('SELECT l.*,p.sku,p.name,p.unit,p.photo,p.width_mm,p.length_mm,p.thickness_mm FROM order_lines l JOIN products p ON p.id=l.product_id WHERE l.order_id=?',(oid,))
    history=all_rows('SELECT m.*,p.name product,b.code batch,u.name actor FROM movements m JOIN products p ON p.id=m.product_id JOIN batches b ON b.id=m.batch_id LEFT JOIN users u ON u.id=m.actor_id WHERE m.order_id=? ORDER BY m.id DESC',(oid,))
    return render_template('order_detail.html', order=order, lines=lines, history=history)

@app.get('/receiving')
@login_required
def receiving():
    day=request.args.get('date') or date.today().isoformat()
    try: date.fromisoformat(day)
    except ValueError: day=date.today().isoformat()
    barcode=request.args.get('barcode','').strip()
    rows=all_rows('SELECT l.*,o.number,o.expected_date,o.status,p.sku,p.name,p.unit,p.photo,p.width_mm,p.length_mm,p.thickness_mm,c.name customer FROM order_lines l JOIN orders o ON o.id=l.order_id JOIN products p ON p.id=l.product_id LEFT JOIN partners c ON c.id=o.customer_id WHERE o.expected_date=? ORDER BY o.id,l.id',(day,))
    matches=[r for r in rows if barcode and r['received_qty']<r['expected_qty'] and barcode.lower() in (r['sku'].lower(),r['name'].lower())]
    return render_template('receiving.html', day=day, barcode=barcode, lines=rows, matches=matches, remaining=sum(1 for r in rows if r['received_qty']<r['expected_qty']))

@app.post('/receive')
@login_required
def receive():
    line_id=request.form.get('line_id'); day=request.form.get('day') or date.today().isoformat()
    try:
        qty=amount(request.form.get('quantity'))
        batch_code=request.form.get('batch_code','').strip()
        if not batch_code: raise ValueError('Вкажіть код партії.')
        db=conn(); db.execute('BEGIN IMMEDIATE')
        line=one('SELECT l.*,o.number,o.status FROM order_lines l JOIN orders o ON o.id=l.order_id WHERE l.id=?',(line_id,))
        if not line or qty>line['expected_qty']-line['received_qty']: raise ValueError('Кількість перевищує залишок за замовленням.')
        batch=one('SELECT * FROM batches WHERE product_id=? AND code=?',(line['product_id'],batch_code))
        if batch: batch_id=batch['id']
        else: batch_id=db.execute('INSERT INTO batches(product_id,code,created_at) VALUES(?,?,?)',(line['product_id'],batch_code,now())).lastrowid
        db.execute('UPDATE batches SET qty=qty+? WHERE id=?',(qty,batch_id))
        db.execute('UPDATE order_lines SET received_qty=received_qty+? WHERE id=?',(qty,line_id))
        db.execute('INSERT INTO movements(product_id,batch_id,order_id,kind,qty,reference,note,actor_id,created_at) VALUES(?,?,?,?,?,?,?,?,?)',(line['product_id'],batch_id,line['order_id'],'receipt',qty,line['number'],request.form.get('note','').strip(),session['uid'],now()))
        open_count=one('SELECT COUNT(*) n FROM order_lines WHERE order_id=? AND received_qty<expected_qty',(line['order_id'],))['n']
        db.execute('UPDATE orders SET status=? WHERE id=?',('received' if open_count==0 else 'partial',line['order_id']))
        audit('Прийнято товар','order',line['order_id'],f'{batch_code}: {fmt(qty)}'); db.commit()
        flash('Приймання збережено. Залишки оновлено.', 'success')
    except (ValueError,sqlite3.IntegrityError) as exc:
        conn().rollback(); flash(str(exc) or 'Не вдалося прийняти товар.', 'error')
    return redirect(url_for('receiving',date=day))

@app.route('/dispatch', methods=['GET','POST'])
@login_required
def dispatch():
    if request.method=='POST':
        try:
            qty=amount(request.form.get('quantity')); bid=int(request.form.get('batch_id'))
            partner=int(request.form['partner_id']) if request.form.get('partner_id') else None
            reference=request.form.get('reference','').strip()
            if not reference: raise ValueError('Вкажіть номер накладної або відправлення.')
            db=conn(); db.execute('BEGIN IMMEDIATE')
            batch=one('SELECT * FROM batches WHERE id=?',(bid,))
            if not batch or qty>batch['qty']: raise ValueError('У партії недостатньо залишку.')
            db.execute('UPDATE batches SET qty=qty-? WHERE id=?',(qty,bid))
            cur=db.execute('INSERT INTO movements(product_id,batch_id,kind,qty,partner_id,reference,note,actor_id,created_at) VALUES(?,?,?,?,?,?,?,?,?)',(batch['product_id'],bid,'dispatch',-qty,partner,reference,request.form.get('note','').strip(),session['uid'],now()))
            audit('Відвантажено товар','movement',cur.lastrowid,reference); db.commit()
            flash('Відвантаження проведено.', 'success'); return redirect(url_for('dispatch'))
        except (ValueError,sqlite3.IntegrityError) as exc:
            conn().rollback(); flash(str(exc) or 'Перевірте дані відвантаження.', 'error')
    batches=all_rows('SELECT b.*,p.name,p.sku,p.unit FROM batches b JOIN products p ON p.id=b.product_id WHERE b.qty>0 ORDER BY p.name,b.code')
    return render_template('dispatch.html', batches=batches, partners=all_rows('SELECT * FROM partners ORDER BY name'))

@app.route('/adjust', methods=['GET','POST'])
@admin_required
def adjust():
    if request.method=='POST':
        try:
            qty=amount(request.form.get('quantity'),positive=False)
            if qty==0: raise ValueError('Кількість не може дорівнювати нулю.')
            bid=int(request.form.get('batch_id')); reason=request.form.get('reason','').strip()
            if len(reason)<5: raise ValueError('Вкажіть причину коригування.')
            db=conn(); db.execute('BEGIN IMMEDIATE')
            batch=one('SELECT * FROM batches WHERE id=?',(bid,))
            if not batch or batch['qty']+qty<0: raise ValueError('Недостатньо залишку в партії.')
            db.execute('UPDATE batches SET qty=qty+? WHERE id=?',(qty,bid))
            cur=db.execute('INSERT INTO movements(product_id,batch_id,kind,qty,note,actor_id,created_at) VALUES(?,?,?,?,?,?,?)',(batch['product_id'],bid,'adjustment',qty,reason,session['uid'],now()))
            audit('Скориговано залишок','movement',cur.lastrowid,reason); db.commit()
            flash('Коригування проведено.', 'success'); return redirect(url_for('adjust'))
        except (ValueError,sqlite3.IntegrityError) as exc:
            conn().rollback(); flash(str(exc) or 'Перевірте дані.', 'error')
    return render_template('adjust.html', batches=all_rows('SELECT b.*,p.name,p.sku,p.unit FROM batches b JOIN products p ON p.id=b.product_id ORDER BY p.name,b.code'))

@app.get('/movements')
@login_required
def movements():
    kind=request.args.get('kind','')
    where='WHERE m.kind=?' if kind in ('receipt','dispatch','adjustment') else ''
    rows=all_rows(f'SELECT m.*,p.name product,p.sku,p.unit,b.code batch,u.name actor,pt.name partner FROM movements m JOIN products p ON p.id=m.product_id JOIN batches b ON b.id=m.batch_id LEFT JOIN users u ON u.id=m.actor_id LEFT JOIN partners pt ON pt.id=m.partner_id {where} ORDER BY m.id DESC LIMIT 500', (kind,) if where else ())
    return render_template('movements.html', movements=rows, kind=kind)

@app.get('/audit')
@admin_required
def audit_page():
    rows=all_rows('SELECT a.*,u.name actor FROM audit a LEFT JOIN users u ON u.id=a.actor_id ORDER BY a.id DESC LIMIT 500')
    return render_template('audit.html', rows=rows)

@app.route('/users', methods=['GET','POST'])
@admin_required
def users():
    if request.method=='POST':
        name=request.form.get('name','').strip(); username=request.form.get('username','').strip().lower(); password=request.form.get('password',''); role=request.form.get('role')
        if not name or not username or len(password)<8 or role not in ('admin','staff'):
            flash('Перевірте ім’я, логін, роль і пароль від 8 символів.', 'error')
        else:
            try:
                db=conn(); db.execute('BEGIN IMMEDIATE')
                cur=db.execute('INSERT INTO users(name,username,password_hash,role,created_at) VALUES(?,?,?,?,?)',(name,username,generate_password_hash(password),role,now()))
                audit('Створено користувача','user',cur.lastrowid,username); db.commit()
                flash('Користувача додано.', 'success'); return redirect(url_for('users'))
            except sqlite3.IntegrityError:
                conn().rollback(); flash('Такий логін уже існує.', 'error')
    return render_template('users.html', users=all_rows('SELECT id,name,username,role,created_at FROM users ORDER BY id'))

@app.get('/orders/<int:oid>/pdf')
@login_required
def order_pdf(oid):
    order=one('SELECT o.*,c.name customer,c.phone customer_phone,c.address customer_address,s.name sender,s.phone sender_phone FROM orders o LEFT JOIN partners c ON c.id=o.customer_id LEFT JOIN partners s ON s.id=o.sender_id WHERE o.id=?',(oid,))
    if not order: abort(404)
    lines=all_rows('SELECT l.*,p.sku,p.name,p.unit,p.species,p.grade,p.width_mm,p.length_mm,p.thickness_mm FROM order_lines l JOIN products p ON p.id=l.product_id WHERE l.order_id=?',(oid,))
    font_candidates = [ROOT/'static'/'DejaVuSans.ttf', Path('C:/Windows/Fonts/arial.ttf'), Path('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf')]
    font_path = next((path for path in font_candidates if path.exists()), None)
    if not font_path:
        abort(500, 'Для PDF потрібен шрифт Arial або DejaVu Sans з підтримкою української.')
    pdfmetrics.registerFont(TTFont('WarehouseFont', str(font_path)))
    font = 'WarehouseFont'
    buffer=BytesIO(); doc=SimpleDocTemplate(buffer,pagesize=A4,rightMargin=36,leftMargin=36,topMargin=42,bottomMargin=36)
    styles=getSampleStyleSheet(); styles['Title'].fontName=font; styles['Normal'].fontName=font; styles['Normal'].fontSize=9; styles['Normal'].leading=14
    P=lambda v: Paragraph(escape(str(v or '—')),styles['Normal'])
    story=[Paragraph(escape(f'Замовлення № {order["number"]}'),styles['Title']),Spacer(1,14)]
    for label,value in [('Очікувана дата',order['expected_date']),('Замовник',order['customer']),('Телефон замовника',order['customer_phone']),('Адреса замовника',order['customer_address']),('Відправник',order['sender']),('Телефон відправника',order['sender_phone']),('Створено',order['created_at']),('Примітка',order['note'])]: story.append(P(f'{label}: {value or "—"}'))
    story.append(Spacer(1,18))
    data=[[P(x) for x in ['Артикул / товар','Розміри','Очікується','Отримано']]]
    for l in lines:
        dims=' × '.join(str(x) for x in (l['width_mm'],l['length_mm'],l['thickness_mm']) if x)
        data.append([P(f'{l["sku"]} — {l["name"]}'),P(dims+' мм' if dims else '—'),P(f'{fmt(l["expected_qty"])} {l["unit"]}'),P(f'{fmt(l["received_qty"])} {l["unit"]}')])
    t=Table(data,colWidths=[190,115,105,105],repeatRows=1,hAlign='LEFT')
    t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#e8eee9')),('GRID',(0,0),(-1,-1),0.4,colors.HexColor('#cbd5ce')),('VALIGN',(0,0),(-1,-1),'TOP'),('LEFTPADDING',(0,0),(-1,-1),7),('RIGHTPADDING',(0,0),(-1,-1),7),('TOPPADDING',(0,0),(-1,-1),7),('BOTTOMPADDING',(0,0),(-1,-1),7)]))
    story.append(t); story.append(Spacer(1,26)); story.append(P('Підпис відправника: ____________________    Підпис одержувача: ____________________'))
    doc.build(story); buffer.seek(0)
    return send_file(buffer,mimetype='application/pdf',as_attachment=True,download_name=f'order-{secure_filename(order["number"])}.pdf')

if __name__=='__main__':
    app.run(host='127.0.0.1',port=int(os.environ.get('PORT','5000')),debug=False)
