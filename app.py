import os, sqlite3, secrets, hashlib
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, flash, abort
from werkzeug.utils import secure_filename

BASE=os.path.dirname(os.path.abspath(__file__))
DB=os.path.join(BASE,'portal.db')
UPLOAD=os.path.join(BASE,'static','uploads')
SECRET=os.environ.get('SECRET_KEY', secrets.token_hex(32))
ALLOWED={'pdf','jpg','jpeg','png','docx'}
app=Flask(__name__)
app.secret_key=SECRET
app.config['MAX_CONTENT_LENGTH']=10*1024*1024

USERS={'0301': {'role':'admin','name':'Head Office'}, **{f'{i:04d}': {'role':'branch','name':f'Branch SOL {i:04d}'} for i in range(302,326)}}

def hashpw(p): return hashlib.sha256(p.encode()).hexdigest()
def db():
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; return c

def init():
    os.makedirs(UPLOAD,exist_ok=True)
    c=db(); c.execute('CREATE TABLE IF NOT EXISTS users (sol TEXT PRIMARY KEY, name TEXT, role TEXT, password_hash TEXT NOT NULL)')
    c.execute('CREATE TABLE IF NOT EXISTS submissions (id INTEGER PRIMARY KEY AUTOINCREMENT, sol TEXT, filename TEXT, stored_name TEXT, uploaded_at TEXT)')
    for sol,u in USERS.items():
        if not c.execute('SELECT 1 FROM users WHERE sol=?',(sol,)).fetchone():
            # Credentials are written by setup script; temporary random password if app starts before setup.
            p=os.environ.get('DEFAULT_ADMIN_PASSWORD','ChangeMe@123') if sol=='0301' else os.environ.get(f'PASS_{sol}','ChangeMe@123')
            c.execute('INSERT INTO users(sol,name,role,password_hash) VALUES(?,?,?,?)',(sol,u['name'],u['role'],hashpw(p)))
    c.commit(); c.close()

def login_required(f):
    @wraps(f)
    def w(*a,**kw):
        if 'sol' not in session: return redirect(url_for('login'))
        return f(*a,**kw)
    return w

@app.route('/',methods=['GET','POST'])
def login():
    if request.method=='POST':
        sol=request.form.get('sol','').strip(); pw=request.form.get('password','')
        c=db(); u=c.execute('SELECT * FROM users WHERE sol=?',(sol,)).fetchone(); c.close()
        if u and hashpw(pw)==u['password_hash']:
            session.clear(); session['sol']=sol; session['role']=u['role']; session['name']=u['name']
            return redirect(url_for('dashboard'))
        flash('Invalid SOL ID or password.','error')
    return render_template('login.html')

@app.route('/logout')
def logout(): session.clear(); return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    c=db()
    if session['role']=='admin':
        rows=c.execute('''SELECT s.*, u.name FROM submissions s LEFT JOIN users u ON u.sol=s.sol ORDER BY s.uploaded_at DESC''').fetchall()
        branches=[]
        for i in range(302,326):
            sol=f'{i:04d}'; latest=c.execute('SELECT * FROM submissions WHERE sol=? ORDER BY uploaded_at DESC LIMIT 1',(sol,)).fetchone()
            branches.append({'sol':sol,'name':f'Branch SOL {sol}','latest':latest})
    else:
        rows=c.execute('SELECT * FROM submissions WHERE sol=? ORDER BY uploaded_at DESC',(session['sol'],)).fetchall(); branches=[]
    c.close(); return render_template('dashboard.html',rows=rows,branches=branches,is_admin=session['role']=='admin')

@app.route('/upload',methods=['POST'])
@login_required
def upload():
    if session['role']!='branch': abort(403)
    f=request.files.get('form_file')
    if not f or not f.filename: flash('Please select the fully filled form.','error'); return redirect(url_for('dashboard'))
    ext=f.filename.rsplit('.',1)[-1].lower() if '.' in f.filename else ''
    if ext not in ALLOWED: flash('Allowed files: PDF, JPG, PNG, DOCX.','error'); return redirect(url_for('dashboard'))
    safe=secure_filename(f.filename)
    stamp=datetime.now().strftime('%Y%m%d_%H%M%S')
    stored=f"{session['sol']}_{stamp}_{secrets.token_hex(4)}_{safe}"
    f.save(os.path.join(UPLOAD,stored))
    c=db(); c.execute('INSERT INTO submissions(sol,filename,stored_name,uploaded_at) VALUES(?,?,?,?)',(session['sol'],safe,stored,datetime.now().strftime('%d-%m-%Y %I:%M:%S %p'))); c.commit(); c.close()
    flash('Form uploaded successfully.','success'); return redirect(url_for('dashboard'))

@app.route('/files/<path:name>')
@login_required
def files(name):
    c=db(); row=c.execute('SELECT * FROM submissions WHERE stored_name=?',(name,)).fetchone(); c.close()
    if not row: abort(404)
    if session['role']!='admin' and row['sol']!=session['sol']: abort(403)
    return send_from_directory(UPLOAD,name,as_attachment=False)

@app.errorhandler(413)
def too_large(e): flash('File is too large. Maximum size is 10 MB.','error'); return redirect(url_for('dashboard'))

init()
if __name__=='__main__': app.run(host='0.0.0.0',port=int(os.environ.get('PORT',5000)))
