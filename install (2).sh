#!/bin/bash
# ============================================================
# Portfolio Website Auto Installer
# Domain: rizzdevs.biz.id
# ============================================================

# Pastikan tidak ada set -e di global
# Error handling per fungsi

# ---- WARNA ----
RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
BLU='\033[0;34m'
PRP='\033[0;35m'
CYN='\033[0;36m'
NC='\033[0m'
BLD='\033[1m'

ok()   { echo -e "${GRN}[OK]${NC} $1"; }
info() { echo -e "${BLU}[INFO]${NC} $1"; }
warn() { echo -e "${YLW}[WARN]${NC} $1"; }
err()  { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
step() { echo -e "\n${PRP}${BLD}====[ $1 ]====${NC}"; }

# ---- CEK ROOT ----
if [ "$(id -u)" -ne 0 ]; then
    echo "[ERROR] Harus dijalankan sebagai root: sudo bash install.sh"
    exit 1
fi

# ---- CEK OS ----
if ! command -v apt > /dev/null 2>&1; then
    echo "[ERROR] Hanya untuk Ubuntu/Debian"
    exit 1
fi

echo ""
echo "============================================================"
echo "   PORTFOLIO WEBSITE AUTO INSTALLER"
echo "   Domain: rizzdevs.biz.id"
echo "   Dark Theme | Full Stack | Admin Panel"
echo "============================================================"
echo ""

# ---- VARIABEL GLOBAL ----
DOMAIN="rizzdevs.biz.id"
APP_DIR="/var/www/portfolio"
DB_NAME="portfolio_db"
DB_USER="portfolio_user"
ADMIN_EMAIL="riskiardiane@gmail.com"

# Generate password aman (tanpa karakter @ di awal agar aman di URL)
RAND1=$(cat /dev/urandom | tr -dc 'a-f0-9' | head -c 16 2>/dev/null || echo "abc123def456ghi7")
RAND2=$(cat /dev/urandom | tr -dc 'a-f0-9' | head -c 32 2>/dev/null || echo "abc123def456ghi789jkl012mno345pq")
DB_PASS="Pf${RAND1}Xz"
SECRET_KEY="${RAND2}"

ok "Variabel siap"
info "DB_PASS  : ${DB_PASS}"
info "Domain   : ${DOMAIN}"
info "App Dir  : ${APP_DIR}"
echo ""

# ============================================================
# LANGKAH 1: INSTALL DEPENDENSI SISTEM
# ============================================================
step "LANGKAH 1/10: Install Dependensi Sistem"

info "Update apt..."
apt-get update -y

info "Install paket sistem..."
apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    build-essential \
    pkg-config \
    nginx \
    certbot \
    python3-certbot-nginx \
    mysql-server \
    default-libmysqlclient-dev \
    curl \
    wget \
    git \
    ufw \
    fail2ban \
    openssl

ok "Dependensi sistem terinstall"

# ============================================================
# LANGKAH 2: SETUP MYSQL
# ============================================================
step "LANGKAH 2/10: Setup MySQL Database"

systemctl start mysql
systemctl enable mysql

mysql -u root << SQLEOF
CREATE DATABASE IF NOT EXISTS ${DB_NAME} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';
GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'localhost';
FLUSH PRIVILEGES;
SQLEOF

if [ $? -eq 0 ]; then
    ok "MySQL: database '${DB_NAME}' dan user '${DB_USER}' siap"
else
    err "MySQL setup gagal! Cek log di atas."
fi

# ============================================================
# LANGKAH 3: SETUP DIREKTORI DAN PYTHON VENV
# ============================================================
step "LANGKAH 3/10: Setup Direktori dan Python Environment"

mkdir -p ${APP_DIR}/static/css
mkdir -p ${APP_DIR}/static/js
mkdir -p ${APP_DIR}/static/img
mkdir -p ${APP_DIR}/static/uploads
mkdir -p ${APP_DIR}/templates/admin
mkdir -p ${APP_DIR}/instance
mkdir -p /var/log/portfolio

info "Membuat Python virtual environment..."
python3 -m venv ${APP_DIR}/venv

info "Install Python packages..."
${APP_DIR}/venv/bin/pip install --upgrade pip --quiet
${APP_DIR}/venv/bin/pip install \
    flask \
    flask-sqlalchemy \
    flask-login \
    flask-wtf \
    flask-bcrypt \
    mysqlclient \
    gunicorn \
    pillow \
    python-dotenv \
    werkzeug \
    --quiet

ok "Python environment siap"

# ============================================================
# LANGKAH 4: BUAT FILE KONFIGURASI (.env)
# ============================================================
step "LANGKAH 4/10: Buat File Konfigurasi"

cat > ${APP_DIR}/.env << ENVEOF
SECRET_KEY=${SECRET_KEY}
DATABASE_URL=mysql+mysqldb://${DB_USER}:${DB_PASS}@localhost/${DB_NAME}?charset=utf8mb4
UPLOAD_FOLDER=${APP_DIR}/static/uploads
MAX_CONTENT_LENGTH=16777216
ENVEOF

ok "File .env dibuat"

# ============================================================
# LANGKAH 5: BUAT APP.PY (Flask Application)
# ============================================================
step "LANGKAH 5/10: Buat Flask Application"

cat > ${APP_DIR}/app.py << 'PYEOF'
import os, uuid
from datetime import datetime
from flask import (Flask, render_template, redirect, url_for,
                   flash, request, jsonify, abort, session)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (LoginManager, UserMixin, login_user,
                         logout_user, current_user)
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, TextAreaField, BooleanField, SelectField
from wtforms.validators import DataRequired, Length
from PIL import Image
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY']                  = os.environ.get('SECRET_KEY', 'dev-fallback-key')
app.config['SQLALCHEMY_DATABASE_URI']     = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER']              = os.environ.get('UPLOAD_FOLDER', '/var/www/portfolio/static/uploads')
app.config['MAX_CONTENT_LENGTH']         = int(os.environ.get('MAX_CONTENT_LENGTH', 16777216))
app.config['WTF_CSRF_TIME_LIMIT']        = 3600
app.config['SESSION_COOKIE_HTTPONLY']    = True
app.config['SESSION_COOKIE_SAMESITE']   = 'Lax'

ALLOWED_EXT = {'png','jpg','jpeg','gif','webp','svg'}
ALLOWED_LIST = list(ALLOWED_EXT)

db           = SQLAlchemy(app)
bcrypt       = Bcrypt(app)
login_mgr    = LoginManager(app)
login_mgr.login_view = None

# ======================================================
# MODELS
# ======================================================

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id         = db.Column(db.Integer, primary_key=True)
    email      = db.Column(db.String(120), unique=True, nullable=False)
    password   = db.Column(db.String(255), nullable=False)
    is_admin   = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class SiteSettings(db.Model):
    __tablename__ = 'site_settings'
    id         = db.Column(db.Integer, primary_key=True)
    key        = db.Column(db.String(100), unique=True, nullable=False)
    value      = db.Column(db.Text)

class Project(db.Model):
    __tablename__ = 'projects'
    id               = db.Column(db.Integer, primary_key=True)
    name             = db.Column(db.String(200), nullable=False)
    description      = db.Column(db.Text, nullable=False)
    long_description = db.Column(db.Text)
    image            = db.Column(db.String(500))
    live_url         = db.Column(db.String(500))
    github_url       = db.Column(db.String(500))
    tech_stack       = db.Column(db.String(500))
    category         = db.Column(db.String(100), default='Web Development')
    featured         = db.Column(db.Boolean, default=False)
    order            = db.Column(db.Integer, default=0)
    created_at       = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at       = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Skill(db.Model):
    __tablename__ = 'skills'
    id       = db.Column(db.Integer, primary_key=True)
    name     = db.Column(db.String(100), nullable=False)
    level    = db.Column(db.Integer, default=80)
    category = db.Column(db.String(100), default='Frontend')
    icon     = db.Column(db.String(100))
    order    = db.Column(db.Integer, default=0)

class Experience(db.Model):
    __tablename__ = 'experiences'
    id          = db.Column(db.Integer, primary_key=True)
    title       = db.Column(db.String(200), nullable=False)
    company     = db.Column(db.String(200), nullable=False)
    location    = db.Column(db.String(200))
    start_date  = db.Column(db.String(50), nullable=False)
    end_date    = db.Column(db.String(50), default='Present')
    description = db.Column(db.Text)
    order       = db.Column(db.Integer, default=0)

class Testimonial(db.Model):
    __tablename__ = 'testimonials'
    id      = db.Column(db.Integer, primary_key=True)
    name    = db.Column(db.String(200), nullable=False)
    role    = db.Column(db.String(200))
    company = db.Column(db.String(200))
    content = db.Column(db.Text, nullable=False)
    avatar  = db.Column(db.String(500))
    active  = db.Column(db.Boolean, default=True)
    order   = db.Column(db.Integer, default=0)

class ContactMessage(db.Model):
    __tablename__ = 'contact_messages'
    id         = db.Column(db.Integer, primary_key=True)
    name       = db.Column(db.String(200), nullable=False)
    email      = db.Column(db.String(200), nullable=False)
    subject    = db.Column(db.String(300))
    message    = db.Column(db.Text, nullable=False)
    read       = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ======================================================
# HELPERS
# ======================================================

@login_mgr.user_loader
def load_user(uid):
    return db.session.get(User, int(uid))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.',1)[1].lower() in ALLOWED_EXT

def save_image(file, size=(800,600)):
    if not file or not file.filename or not allowed_file(file.filename):
        return None
    ext = file.filename.rsplit('.',1)[1].lower()
    fname = uuid.uuid4().hex + '.' + ext
    path = os.path.join(app.config['UPLOAD_FOLDER'], fname)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if ext in {'jpg','jpeg','png','webp'}:
        img = Image.open(file)
        img.thumbnail(size, Image.LANCZOS)
        img.save(path, optimize=True, quality=85)
    else:
        file.save(path)
    return fname

def cfg():
    return {s.key: s.value for s in SiteSettings.query.all()}

def is_admin():
    return current_user.is_authenticated and current_user.is_admin

def require_admin():
    if not is_admin():
        abort(404)

# ======================================================
# FORMS
# ======================================================

class ProjectForm(FlaskForm):
    name             = StringField('Nama Project', validators=[DataRequired(), Length(max=200)])
    description      = TextAreaField('Deskripsi Singkat', validators=[DataRequired()])
    long_description = TextAreaField('Deskripsi Lengkap')
    image            = FileField('Gambar', validators=[FileAllowed(ALLOWED_LIST)])
    live_url         = StringField('URL Live')
    github_url       = StringField('URL GitHub')
    tech_stack       = StringField('Tech Stack (pisahkan koma)')
    category         = SelectField('Kategori', choices=[
        ('Web Development','Web Development'),('Mobile App','Mobile App'),
        ('UI/UX Design','UI/UX Design'),('Backend','Backend'),
        ('DevOps','DevOps'),('Other','Other')])
    featured         = BooleanField('Featured')
    order            = StringField('Urutan')

class SkillForm(FlaskForm):
    name     = StringField('Nama Skill', validators=[DataRequired()])
    level    = StringField('Level (0-100)', validators=[DataRequired()])
    category = SelectField('Kategori', choices=[
        ('Frontend','Frontend'),('Backend','Backend'),('Database','Database'),
        ('DevOps','DevOps'),('Design','Design'),('Other','Other')])
    icon     = StringField('Icon Class (devicon)')
    order    = StringField('Urutan')

class ExperienceForm(FlaskForm):
    title       = StringField('Jabatan', validators=[DataRequired()])
    company     = StringField('Perusahaan', validators=[DataRequired()])
    location    = StringField('Lokasi')
    start_date  = StringField('Mulai', validators=[DataRequired()])
    end_date    = StringField('Selesai')
    description = TextAreaField('Deskripsi')
    order       = StringField('Urutan')

class TestimonialForm(FlaskForm):
    name    = StringField('Nama', validators=[DataRequired()])
    role    = StringField('Jabatan')
    company = StringField('Perusahaan')
    content = TextAreaField('Testimoni', validators=[DataRequired()])
    avatar  = FileField('Foto', validators=[FileAllowed(ALLOWED_LIST)])
    active  = BooleanField('Aktif')
    order   = StringField('Urutan')

class SettingsForm(FlaskForm):
    hero_name       = StringField('Nama')
    hero_tagline    = StringField('Tagline')
    hero_bio        = TextAreaField('Bio')
    hero_image      = FileField('Foto Hero', validators=[FileAllowed(ALLOWED_LIST)])
    about_text      = TextAreaField('Teks About')
    email           = StringField('Email')
    phone           = StringField('Telepon')
    location        = StringField('Lokasi')
    github_url      = StringField('GitHub URL')
    linkedin_url    = StringField('LinkedIn URL')
    twitter_url     = StringField('Twitter URL')
    instagram_url   = StringField('Instagram URL')
    footer_text     = TextAreaField('Teks Footer')
    footer_copyright= StringField('Copyright')
    meta_description= TextAreaField('Meta Description')
    cv_url          = StringField('CV/Resume URL')

class ContactForm(FlaskForm):
    name    = StringField('Nama', validators=[DataRequired()])
    email   = StringField('Email', validators=[DataRequired()])
    subject = StringField('Subjek')
    message = TextAreaField('Pesan', validators=[DataRequired()])

# ======================================================
# PUBLIC ROUTES
# ======================================================

@app.route('/')
def index():
    settings     = cfg()
    projects     = Project.query.order_by(Project.order, Project.created_at.desc()).limit(6).all()
    featured     = Project.query.filter_by(featured=True).order_by(Project.order).limit(3).all()
    skills       = Skill.query.order_by(Skill.category, Skill.order).all()
    experiences  = Experience.query.order_by(Experience.order).all()
    testimonials = Testimonial.query.filter_by(active=True).order_by(Testimonial.order).all()
    skill_cats   = {}
    for s in skills:
        skill_cats.setdefault(s.category, []).append(s)
    form = ContactForm()
    return render_template('index.html',
        settings=settings, projects=projects, featured=featured,
        skill_categories=skill_cats, experiences=experiences,
        testimonials=testimonials, form=form)

@app.route('/projects')
def projects_page():
    settings = cfg()
    cat      = request.args.get('category','all')
    q        = Project.query
    if cat != 'all':
        q = q.filter_by(category=cat)
    projs = q.order_by(Project.order, Project.created_at.desc()).all()
    cats  = [c[0] for c in db.session.query(Project.category).distinct().all()]
    return render_template('projects.html', projects=projs, categories=cats,
                           active_cat=cat, settings=settings)

@app.route('/project/<int:pid>')
def project_detail(pid):
    project  = db.session.get(Project, pid)
    if project is None: abort(404)
    settings = cfg()
    related  = Project.query.filter(Project.category==project.category,
                                    Project.id!=project.id).limit(3).all()
    techs    = [t.strip() for t in (project.tech_stack or '').split(',') if t.strip()]
    return render_template('project_detail.html', project=project,
                           settings=settings, related=related, techs=techs)

@app.route('/contact', methods=['POST'])
def contact():
    form = ContactForm()
    if form.validate_on_submit():
        msg = ContactMessage(
            name=form.name.data, email=form.email.data,
            subject=form.subject.data, message=form.message.data)
        db.session.add(msg)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Pesan berhasil dikirim!'})
    return jsonify({'success': False, 'message': 'Isi semua field yang wajib.'})

# ======================================================
# ADMIN LOGIN (URL tersembunyi - return 404 jika bukan admin)
# ======================================================

@app.route('/secure-panel-7x9k2m', methods=['GET','POST'])
def admin_login():
    if is_admin():
        return redirect(url_for('admin_dashboard'))
    error = None
    if request.method == 'POST':
        em   = request.form.get('email','').strip()
        pw   = request.form.get('password','')
        user = User.query.filter_by(email=em).first()
        if user and user.is_admin and bcrypt.check_password_hash(user.password, pw):
            login_user(user, remember=False)
            session.permanent = False
            return redirect(url_for('admin_dashboard'))
        error = 'Email atau password salah'
    return render_template('admin/login.html', error=error)

@app.route('/admin/logout')
def admin_logout():
    if current_user.is_authenticated:
        logout_user()
    return redirect(url_for('index'))

# ======================================================
# ADMIN ROUTES (semua return 404 jika bukan admin)
# ======================================================

@app.route('/admin')
def admin_dashboard():
    require_admin()
    return render_template('admin/dashboard.html',
        projects_count  = Project.query.count(),
        skills_count    = Skill.query.count(),
        messages_count  = ContactMessage.query.count(),
        unread_count    = ContactMessage.query.filter_by(read=False).count(),
        recent_messages = ContactMessage.query.order_by(ContactMessage.created_at.desc()).limit(5).all())

# -- Projects --
@app.route('/admin/projects')
def admin_projects():
    require_admin()
    return render_template('admin/projects.html',
        projects=Project.query.order_by(Project.order, Project.created_at.desc()).all())

@app.route('/admin/projects/new', methods=['GET','POST'])
def admin_project_new():
    require_admin()
    form = ProjectForm()
    if form.validate_on_submit():
        img = save_image(request.files.get('image'), size=(1200,800))
        p   = Project(name=form.name.data, description=form.description.data,
                      long_description=form.long_description.data, image=img,
                      live_url=form.live_url.data, github_url=form.github_url.data,
                      tech_stack=form.tech_stack.data, category=form.category.data,
                      featured=form.featured.data, order=int(form.order.data or 0))
        db.session.add(p); db.session.commit()
        flash('Project ditambahkan!', 'success')
        return redirect(url_for('admin_projects'))
    return render_template('admin/project_form.html', form=form, title='Project Baru', project=None)

@app.route('/admin/projects/<int:pid>/edit', methods=['GET','POST'])
def admin_project_edit(pid):
    require_admin()
    p    = db.session.get(Project, pid)
    if p is None: abort(404)
    form = ProjectForm(obj=p)
    if form.validate_on_submit():
        img = save_image(request.files.get('image'), size=(1200,800))
        p.name=form.name.data; p.description=form.description.data
        p.long_description=form.long_description.data
        if img: p.image=img
        p.live_url=form.live_url.data; p.github_url=form.github_url.data
        p.tech_stack=form.tech_stack.data; p.category=form.category.data
        p.featured=form.featured.data; p.order=int(form.order.data or 0)
        p.updated_at=datetime.utcnow()
        db.session.commit()
        flash('Project diupdate!', 'success')
        return redirect(url_for('admin_projects'))
    return render_template('admin/project_form.html', form=form, title='Edit Project', project=p)

@app.route('/admin/projects/<int:pid>/delete', methods=['POST'])
def admin_project_delete(pid):
    require_admin()
    p = db.session.get(Project, pid)
    if p is None: abort(404)
    db.session.delete(p); db.session.commit()
    flash('Project dihapus!', 'success')
    return redirect(url_for('admin_projects'))

# -- Skills --
@app.route('/admin/skills')
def admin_skills():
    require_admin()
    return render_template('admin/skills.html',
        skills=Skill.query.order_by(Skill.category, Skill.order).all())

@app.route('/admin/skills/new', methods=['GET','POST'])
def admin_skill_new():
    require_admin()
    form = SkillForm()
    if form.validate_on_submit():
        s = Skill(name=form.name.data, level=int(form.level.data or 80),
                  category=form.category.data, icon=form.icon.data,
                  order=int(form.order.data or 0))
        db.session.add(s); db.session.commit()
        flash('Skill ditambahkan!', 'success')
        return redirect(url_for('admin_skills'))
    return render_template('admin/skill_form.html', form=form, title='Skill Baru', skill=None)

@app.route('/admin/skills/<int:sid>/edit', methods=['GET','POST'])
def admin_skill_edit(sid):
    require_admin()
    s    = db.session.get(Skill, sid)
    if s is None: abort(404)
    form = SkillForm(obj=s)
    if form.validate_on_submit():
        s.name=form.name.data; s.level=int(form.level.data or 80)
        s.category=form.category.data; s.icon=form.icon.data
        s.order=int(form.order.data or 0)
        db.session.commit()
        flash('Skill diupdate!', 'success')
        return redirect(url_for('admin_skills'))
    return render_template('admin/skill_form.html', form=form, title='Edit Skill', skill=s)

@app.route('/admin/skills/<int:sid>/delete', methods=['POST'])
def admin_skill_delete(sid):
    require_admin()
    s = db.session.get(Skill, sid)
    if s is None: abort(404)
    db.session.delete(s); db.session.commit()
    flash('Skill dihapus!', 'success')
    return redirect(url_for('admin_skills'))

# -- Experience --
@app.route('/admin/experience')
def admin_experience():
    require_admin()
    return render_template('admin/experience.html',
        experiences=Experience.query.order_by(Experience.order).all())

@app.route('/admin/experience/new', methods=['GET','POST'])
def admin_experience_new():
    require_admin()
    form = ExperienceForm()
    if form.validate_on_submit():
        e = Experience(title=form.title.data, company=form.company.data,
                       location=form.location.data, start_date=form.start_date.data,
                       end_date=form.end_date.data or 'Present',
                       description=form.description.data, order=int(form.order.data or 0))
        db.session.add(e); db.session.commit()
        flash('Experience ditambahkan!', 'success')
        return redirect(url_for('admin_experience'))
    return render_template('admin/experience_form.html', form=form, title='Tambah Experience', exp=None)

@app.route('/admin/experience/<int:eid>/edit', methods=['GET','POST'])
def admin_experience_edit(eid):
    require_admin()
    e    = db.session.get(Experience, eid)
    if e is None: abort(404)
    form = ExperienceForm(obj=e)
    if form.validate_on_submit():
        e.title=form.title.data; e.company=form.company.data
        e.location=form.location.data; e.start_date=form.start_date.data
        e.end_date=form.end_date.data or 'Present'
        e.description=form.description.data; e.order=int(form.order.data or 0)
        db.session.commit()
        flash('Experience diupdate!', 'success')
        return redirect(url_for('admin_experience'))
    return render_template('admin/experience_form.html', form=form, title='Edit Experience', exp=e)

@app.route('/admin/experience/<int:eid>/delete', methods=['POST'])
def admin_experience_delete(eid):
    require_admin()
    e = db.session.get(Experience, eid)
    if e is None: abort(404)
    db.session.delete(e); db.session.commit()
    flash('Experience dihapus!', 'success')
    return redirect(url_for('admin_experience'))

# -- Testimonials --
@app.route('/admin/testimonials')
def admin_testimonials():
    require_admin()
    return render_template('admin/testimonials.html',
        testimonials=Testimonial.query.order_by(Testimonial.order).all())

@app.route('/admin/testimonials/new', methods=['GET','POST'])
def admin_testimonial_new():
    require_admin()
    form = TestimonialForm()
    if form.validate_on_submit():
        av = save_image(request.files.get('avatar'), size=(200,200))
        t  = Testimonial(name=form.name.data, role=form.role.data,
                         company=form.company.data, content=form.content.data,
                         avatar=av, active=form.active.data,
                         order=int(form.order.data or 0))
        db.session.add(t); db.session.commit()
        flash('Testimoni ditambahkan!', 'success')
        return redirect(url_for('admin_testimonials'))
    return render_template('admin/testimonial_form.html', form=form, title='Tambah Testimoni', item=None)

@app.route('/admin/testimonials/<int:tid>/edit', methods=['GET','POST'])
def admin_testimonial_edit(tid):
    require_admin()
    t    = db.session.get(Testimonial, tid)
    if t is None: abort(404)
    form = TestimonialForm(obj=t)
    if form.validate_on_submit():
        av = save_image(request.files.get('avatar'), size=(200,200))
        t.name=form.name.data; t.role=form.role.data
        t.company=form.company.data; t.content=form.content.data
        if av: t.avatar=av
        t.active=form.active.data; t.order=int(form.order.data or 0)
        db.session.commit()
        flash('Testimoni diupdate!', 'success')
        return redirect(url_for('admin_testimonials'))
    return render_template('admin/testimonial_form.html', form=form, title='Edit Testimoni', item=t)

@app.route('/admin/testimonials/<int:tid>/delete', methods=['POST'])
def admin_testimonial_delete(tid):
    require_admin()
    t = db.session.get(Testimonial, tid)
    if t is None: abort(404)
    db.session.delete(t); db.session.commit()
    flash('Testimoni dihapus!', 'success')
    return redirect(url_for('admin_testimonials'))

# -- Settings --
@app.route('/admin/settings', methods=['GET','POST'])
def admin_settings():
    require_admin()
    form     = SettingsForm()
    settings = cfg()
    if form.validate_on_submit():
        fields = ['hero_name','hero_tagline','hero_bio','about_text','email','phone',
                  'location','github_url','linkedin_url','twitter_url','instagram_url',
                  'footer_text','footer_copyright','meta_description','cv_url']
        for f in fields:
            val = getattr(form, f).data or ''
            row = SiteSettings.query.filter_by(key=f).first()
            if row: row.value = val
            else: db.session.add(SiteSettings(key=f, value=val))
        img = save_image(request.files.get('hero_image'), size=(600,600))
        if img:
            row = SiteSettings.query.filter_by(key='hero_image').first()
            if row: row.value = img
            else: db.session.add(SiteSettings(key='hero_image', value=img))
        db.session.commit()
        flash('Pengaturan disimpan!', 'success')
        return redirect(url_for('admin_settings'))
    for field in form:
        if field.name in settings:
            field.data = settings[field.name]
    return render_template('admin/settings.html', form=form, settings=settings)

# -- Messages --
@app.route('/admin/messages')
def admin_messages():
    require_admin()
    msgs = ContactMessage.query.order_by(ContactMessage.created_at.desc()).all()
    ContactMessage.query.filter_by(read=False).update({'read': True})
    db.session.commit()
    return render_template('admin/messages.html', messages=msgs)

@app.route('/admin/messages/<int:mid>/delete', methods=['POST'])
def admin_message_delete(mid):
    require_admin()
    m = db.session.get(ContactMessage, mid)
    if m is None: abort(404)
    db.session.delete(m); db.session.commit()
    flash('Pesan dihapus!', 'success')
    return redirect(url_for('admin_messages'))

# ======================================================
# ERROR HANDLERS
# ======================================================

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html', settings=cfg()), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('404.html', settings=cfg()), 500

# ======================================================
# INIT DATABASE + SEED DATA
# ======================================================

def init_db():
    with app.app_context():
        db.create_all()

        if not User.query.filter_by(email='riskiardiane@gmail.com').first():
            admin = User(
                email    = 'riskiardiane@gmail.com',
                password = bcrypt.generate_password_hash('reRe2345@#$@#$E').decode('utf-8'),
                is_admin = True)
            db.session.add(admin)

        defaults = {
            'hero_name'        : 'Riski Ardiane',
            'hero_tagline'     : 'Full Stack Developer & Creative Technologist',
            'hero_bio'         : 'Saya membangun pengalaman digital yang memadukan desain elegan dengan fungsionalitas powerful.',
            'about_text'       : 'Saya adalah Full Stack Developer yang passionate dengan teknologi web modern.',
            'email'            : 'riskiardiane@gmail.com',
            'phone'            : '+62 xxx xxxx xxxx',
            'location'         : 'Indonesia',
            'github_url'       : 'https://github.com/rizzdevs',
            'linkedin_url'     : '#',
            'twitter_url'      : '#',
            'instagram_url'    : '#',
            'footer_text'      : 'Building the web, one line at a time.',
            'footer_copyright' : '2025 Riski Ardiane. All rights reserved.',
            'meta_description' : 'Portfolio - Riski Ardiane | rizzdevs.biz.id',
            'cv_url'           : '#',
        }
        for k, v in defaults.items():
            if not SiteSettings.query.filter_by(key=k).first():
                db.session.add(SiteSettings(key=k, value=v))

        if Project.query.count() == 0:
            db.session.add_all([
                Project(name='E-Commerce Platform',
                        description='Toko online full-featured dengan payment gateway, manajemen inventory, dan dashboard analytics real-time.',
                        long_description='Solusi e-commerce lengkap dibangun dengan Flask dan React. Fitur: autentikasi user, manajemen produk, keranjang belanja, pembayaran Stripe, tracking order, dan admin dashboard dengan analytics real-time.',
                        tech_stack='Python,Flask,React,MySQL,Redis,Stripe', category='Web Development', featured=True, order=1, live_url='#', github_url='#'),
                Project(name='DevOps Dashboard',
                        description='Dashboard monitoring infrastruktur real-time dengan alerts, log aggregation, dan visualisasi deployment pipeline.',
                        tech_stack='Python,Flask,Docker,Grafana,PostgreSQL', category='DevOps', featured=True, order=2, live_url='#', github_url='#'),
                Project(name='Mobile Task Manager',
                        description='Aplikasi manajemen tugas cross-platform dengan kolaborasi tim, kanban boards, dan analytics produktivitas.',
                        tech_stack='React Native,Node.js,MongoDB,Socket.io', category='Mobile App', featured=True, order=3, live_url='#', github_url='#'),
                Project(name='AI Content Generator',
                        description='Tool pembuatan konten berbasis GPT untuk blog, media sosial, dan copy marketing dengan optimasi SEO.',
                        tech_stack='Python,OpenAI,FastAPI,React,PostgreSQL', category='Backend', order=4, live_url='#', github_url='#'),
                Project(name='Portfolio CMS',
                        description='Custom CMS untuk profesional kreatif dengan antarmuka drag-and-drop.',
                        tech_stack='Python,Flask,MySQL,JavaScript,CSS3', category='Web Development', order=5, live_url='#', github_url='#'),
            ])

        if Skill.query.count() == 0:
            db.session.add_all([
                Skill(name='Python',     level=92, category='Backend',  icon='devicon-python-plain',     order=1),
                Skill(name='Flask',      level=90, category='Backend',  icon='devicon-flask-original',   order=2),
                Skill(name='Django',     level=82, category='Backend',  icon='devicon-django-plain',     order=3),
                Skill(name='JavaScript', level=88, category='Frontend', icon='devicon-javascript-plain', order=1),
                Skill(name='React',      level=85, category='Frontend', icon='devicon-react-original',   order=2),
                Skill(name='Vue.js',     level=75, category='Frontend', icon='devicon-vuejs-plain',      order=3),
                Skill(name='HTML/CSS',   level=95, category='Frontend', icon='devicon-html5-plain',      order=4),
                Skill(name='MySQL',      level=88, category='Database', icon='devicon-mysql-plain',      order=1),
                Skill(name='PostgreSQL', level=82, category='Database', icon='devicon-postgresql-plain', order=2),
                Skill(name='MongoDB',    level=78, category='Database', icon='devicon-mongodb-plain',    order=3),
                Skill(name='Docker',     level=80, category='DevOps',   icon='devicon-docker-plain',     order=1),
                Skill(name='Linux',      level=85, category='DevOps',   icon='devicon-linux-plain',      order=2),
                Skill(name='Nginx',      level=82, category='DevOps',   icon='devicon-nginx-plain',      order=3),
                Skill(name='Git',        level=90, category='DevOps',   icon='devicon-git-plain',        order=4),
            ])

        if Experience.query.count() == 0:
            db.session.add_all([
                Experience(title='Senior Full Stack Developer', company='Tech Solutions Co.',
                           location='Remote', start_date='Jan 2022', end_date='Present',
                           description='Memimpin pengembangan aplikasi web enterprise. Merancang microservices, mentoring junior devs.', order=1),
                Experience(title='Full Stack Developer', company='Digital Agency XYZ',
                           location='Jakarta, Indonesia', start_date='Mar 2020', end_date='Des 2021',
                           description='Membangun web app responsif untuk berbagai klien dengan React, Node.js, dan berbagai database.', order=2),
                Experience(title='Junior Web Developer', company='Startup Hub',
                           location='Bandung, Indonesia', start_date='Jun 2018', end_date='Feb 2020',
                           description='Mengembangkan fitur frontend dan REST API. Belajar best practice agile development.', order=3),
            ])

        if Testimonial.query.count() == 0:
            db.session.add_all([
                Testimonial(name='Ahmad Fauzi', role='CTO', company='TechCorp Indonesia',
                            content='Bekerja dengan Riski adalah pengalaman luar biasa. Skill teknis dan perhatian pada detail-nya sangat outstanding.', active=True, order=1),
                Testimonial(name='Sarah Dewi', role='Product Manager', company='Digital Startup',
                            content='Riski punya kombinasi langka antara keunggulan teknis dan kemampuan komunikasi yang baik.', active=True, order=2),
                Testimonial(name='Budi Santoso', role='Founder', company='E-Commerce Brand',
                            content='Performa platform e-commerce kami meningkat drastis setelah Riski mengoptimasi backend kami.', active=True, order=3),
            ])

        db.session.commit()
        print('[OK] Database initialized!')

if __name__ == '__main__':
    init_db()
    app.run(debug=False, host='127.0.0.1', port=5000)
PYEOF

echo "[OK] app.py dibuat"

# ============================================================
# LANGKAH 6: BUAT TEMPLATES HTML
# ============================================================
step "LANGKAH 6/10: Buat Templates HTML"

# BASE TEMPLATE
cat > ${APP_DIR}/templates/base.html << 'TMPL'
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="description" content="{{ settings.get('meta_description','Portfolio') }}">
<title>{% block title %}{{ settings.get('hero_name','Portfolio') }}{% endblock %} | rizzdevs</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>%E2%9A%A1</text></svg>">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=Syne:wght@400;600;700;800&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/devicons/devicon@v2.15.1/devicon.min.css">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
{% block extra_head %}{% endblock %}
</head>
<body>
<div class="noise"></div>

<nav class="navbar" id="navbar">
  <div class="container nav-wrap">
    <a href="{{ url_for('index') }}" class="logo">[rizz<span class="acc">devs</span>]</a>
    <ul class="nav-links">
      <li><a href="{{ url_for('index') }}#about">About</a></li>
      <li><a href="{{ url_for('index') }}#projects">Projects</a></li>
      <li><a href="{{ url_for('index') }}#skills">Skills</a></li>
      <li><a href="{{ url_for('index') }}#experience">Experience</a></li>
      <li><a href="{{ url_for('index') }}#contact">Contact</a></li>
      <li><a href="{{ settings.get('cv_url','#') }}" class="btn-nav" target="_blank">Resume</a></li>
    </ul>
    <button class="hamburger" id="hamburger"><span></span><span></span><span></span></button>
  </div>
</nav>
<div class="mobile-menu" id="mobileMenu">
  <ul>
    <li><a href="{{ url_for('index') }}#about">About</a></li>
    <li><a href="{{ url_for('index') }}#projects">Projects</a></li>
    <li><a href="{{ url_for('index') }}#skills">Skills</a></li>
    <li><a href="{{ url_for('index') }}#experience">Experience</a></li>
    <li><a href="{{ url_for('index') }}#contact">Contact</a></li>
    <li><a href="{{ settings.get('cv_url','#') }}" target="_blank">Resume</a></li>
  </ul>
</div>

{% block content %}{% endblock %}

<footer class="footer">
  <div class="container">
    <div class="footer-grid">
      <div class="footer-brand">
        <a href="{{ url_for('index') }}" class="logo">[rizz<span class="acc">devs</span>]</a>
        <p>{{ settings.get('footer_text','Building the web, one line at a time.') }}</p>
        <div class="socials">
          {% if settings.get('github_url') %}<a href="{{ settings.get('github_url') }}" target="_blank"><i class="fab fa-github"></i></a>{% endif %}
          {% if settings.get('linkedin_url') %}<a href="{{ settings.get('linkedin_url') }}" target="_blank"><i class="fab fa-linkedin"></i></a>{% endif %}
          {% if settings.get('twitter_url') %}<a href="{{ settings.get('twitter_url') }}" target="_blank"><i class="fab fa-twitter"></i></a>{% endif %}
          {% if settings.get('instagram_url') %}<a href="{{ settings.get('instagram_url') }}" target="_blank"><i class="fab fa-instagram"></i></a>{% endif %}
        </div>
      </div>
      <div class="footer-nav">
        <h4>Navigasi</h4>
        <ul>
          <li><a href="{{ url_for('index') }}#about">About</a></li>
          <li><a href="{{ url_for('index') }}#projects">Projects</a></li>
          <li><a href="{{ url_for('index') }}#skills">Skills</a></li>
          <li><a href="{{ url_for('index') }}#contact">Contact</a></li>
        </ul>
      </div>
      <div class="footer-contact-info">
        <h4>Kontak</h4>
        {% if settings.get('email') %}<p><i class="fas fa-envelope"></i> {{ settings.get('email') }}</p>{% endif %}
        {% if settings.get('location') %}<p><i class="fas fa-map-marker-alt"></i> {{ settings.get('location') }}</p>{% endif %}
        {% if settings.get('phone') %}<p><i class="fas fa-phone"></i> {{ settings.get('phone') }}</p>{% endif %}
      </div>
    </div>
    <div class="footer-bottom">
      <p>&copy; {{ settings.get('footer_copyright','2025 All rights reserved.') }}</p>
      <p>Made with <span style="color:#ff006e">&#9829;</span> &amp; Python</p>
    </div>
  </div>
</footer>

<div id="toast" class="toast"></div>
<script src="{{ url_for('static', filename='js/main.js') }}"></script>
{% block scripts %}{% endblock %}
</body>
</html>
TMPL

echo "[OK] base.html"

# INDEX
cat > ${APP_DIR}/templates/index.html << 'TMPL'
{% extends "base.html" %}
{% block content %}

<!-- HERO -->
<section class="hero" id="home">
  <div class="hero-bg"><div class="grid-bg"></div><div class="glow-orb"></div></div>
  <div class="container hero-inner">
    <div class="hero-text">
      <div class="badge"><span class="badge-dot"></span> Available for hire</div>
      <h1 class="hero-title">
        <span class="hi">Hello, I'm</span>
        <span class="name-text">{{ settings.get('hero_name','Developer') }}</span>
      </h1>
      <p class="tagline">{{ settings.get('hero_tagline','') }}</p>
      <p class="bio">{{ settings.get('hero_bio','') }}</p>
      <div class="hero-btns">
        <a href="#projects" class="btn btn-primary">Lihat Karya <i class="fas fa-arrow-right"></i></a>
        <a href="#contact" class="btn btn-outline">Hubungi Saya</a>
      </div>
      <div class="hero-stats">
        <div class="hstat"><span class="hnum">{{ projects|length }}+</span><span class="hlbl">Projects</span></div>
        <div class="hdiv"></div>
        <div class="hstat"><span class="hnum">5+</span><span class="hlbl">Tahun Exp.</span></div>
        <div class="hdiv"></div>
        <div class="hstat"><span class="hnum">{{ skill_categories|length * 4 }}+</span><span class="hlbl">Teknologi</span></div>
      </div>
    </div>
    <div class="hero-visual">
      <div class="img-wrap">
        {% if settings.get('hero_image') %}
        <img src="{{ url_for('static', filename='uploads/' + settings.get('hero_image')) }}" alt="{{ settings.get('hero_name') }}" class="hero-img">
        {% else %}
        <div class="hero-placeholder"><i class="fas fa-code"></i></div>
        {% endif %}
        <div class="ring r1"></div><div class="ring r2"></div><div class="ring r3"></div>
      </div>
      <div class="fc fc1"><i class="fab fa-python"></i> Python</div>
      <div class="fc fc2"><i class="fab fa-react"></i> React</div>
      <div class="fc fc3"><i class="fas fa-server"></i> DevOps</div>
    </div>
  </div>
  <a href="#about" class="scroll-hint"><div class="s-mouse"><div class="s-dot"></div></div><span>scroll</span></a>
</section>

<!-- ABOUT -->
<section class="section" id="about">
  <div class="container">
    <div class="sec-header">
      <span class="sec-tag">// 01</span>
      <h2 class="sec-title">About <span class="acc">Me</span></h2>
    </div>
    <div class="about-grid">
      <div class="about-text">
        <p>{{ settings.get('about_text','') }}</p>
        <div class="about-info">
          {% if settings.get('email') %}<div class="ainfo"><i class="fas fa-envelope"></i><span>{{ settings.get('email') }}</span></div>{% endif %}
          {% if settings.get('location') %}<div class="ainfo"><i class="fas fa-map-marker-alt"></i><span>{{ settings.get('location') }}</span></div>{% endif %}
        </div>
        <a href="{{ settings.get('cv_url','#') }}" class="btn btn-primary" target="_blank"><i class="fas fa-download"></i> Download CV</a>
      </div>
      <div class="code-block">
        <div class="code-hdr"><span class="dot rd"></span><span class="dot yl"></span><span class="dot gn"></span><span class="code-fn">developer.py</span></div>
        <pre class="code-body"><code><span class="ck">class</span> <span class="cc">Developer</span>:
  <span class="cf">def</span> <span class="cf">__init__</span>(self):
    self.name = <span class="cs">"{{ settings.get('hero_name','Dev') }}"</span>
    self.role = <span class="cs">"Full Stack Dev"</span>
    self.loc  = <span class="cs">"{{ settings.get('location','Indonesia') }}"</span>
    self.skills = [
      <span class="cs">"Python"</span>, <span class="cs">"Flask"</span>,
      <span class="cs">"React"</span>, <span class="cs">"MySQL"</span>,
      <span class="cs">"Docker"</span>, <span class="cs">"Nginx"</span>
    ]

  <span class="cf">def</span> <span class="cf">passion</span>(self):
    <span class="ck">return</span> <span class="cs">"Build amazing things"</span></code></pre>
      </div>
    </div>
  </div>
</section>

<!-- PROJECTS -->
<section class="section sec-dark" id="projects">
  <div class="container">
    <div class="sec-header">
      <span class="sec-tag">// 02</span>
      <h2 class="sec-title">My <span class="acc">Projects</span></h2>
    </div>
    <div class="proj-grid">
      {% for p in projects %}
      <article class="proj-card">
        <div class="proj-img">
          {% if p.image %}<img src="{{ url_for('static', filename='uploads/'+p.image) }}" alt="{{ p.name }}" loading="lazy">
          {% else %}<div class="proj-ph"><i class="fas fa-code"></i></div>{% endif %}
          {% if p.featured %}<span class="proj-badge">Featured</span>{% endif %}
        </div>
        <div class="proj-body">
          <span class="proj-cat">{{ p.category }}</span>
          <h3><a href="{{ url_for('project_detail', pid=p.id) }}">{{ p.name }}</a></h3>
          <p>{{ p.description[:120] }}{% if p.description|length > 120 %}...{% endif %}</p>
          {% if p.tech_stack %}
          <div class="tech-tags">{% for t in p.tech_stack.split(',')[:3] %}<span>{{ t.strip() }}</span>{% endfor %}</div>
          {% endif %}
          <div class="proj-links">
            <a href="{{ url_for('project_detail', pid=p.id) }}" class="plink-main">Detail <i class="fas fa-arrow-right"></i></a>
            {% if p.github_url and p.github_url != '#' %}<a href="{{ p.github_url }}" target="_blank" class="plink-icon"><i class="fab fa-github"></i></a>{% endif %}
            {% if p.live_url and p.live_url != '#' %}<a href="{{ p.live_url }}" target="_blank" class="plink-icon"><i class="fas fa-external-link-alt"></i></a>{% endif %}
          </div>
        </div>
      </article>
      {% endfor %}
    </div>
    <div class="sec-footer"><a href="{{ url_for('projects_page') }}" class="btn btn-outline">Lihat Semua Project <i class="fas fa-arrow-right"></i></a></div>
  </div>
</section>

<!-- SKILLS -->
<section class="section" id="skills">
  <div class="container">
    <div class="sec-header">
      <span class="sec-tag">// 03</span>
      <h2 class="sec-title">Tech <span class="acc">Stack</span></h2>
    </div>
    {% for cat, skills in skill_categories.items() %}
    <div class="skill-group">
      <h3 class="skill-cat">{{ cat }}</h3>
      <div class="skill-grid">
        {% for s in skills %}
        <div class="skill-card">
          {% if s.icon %}<i class="{{ s.icon }} sk-icon"></i>{% else %}<span class="sk-letter">{{ s.name[0] }}</span>{% endif %}
          <span class="sk-name">{{ s.name }}</span>
          <div class="sk-bar-wrap">
            <div class="sk-bar"><div class="sk-fill" data-target="{{ s.level }}" style="width:0%"></div></div>
            <span class="sk-pct">{{ s.level }}%</span>
          </div>
        </div>
        {% endfor %}
      </div>
    </div>
    {% endfor %}
  </div>
</section>

<!-- EXPERIENCE -->
{% if experiences %}
<section class="section sec-dark" id="experience">
  <div class="container">
    <div class="sec-header">
      <span class="sec-tag">// 04</span>
      <h2 class="sec-title">Work <span class="acc">Experience</span></h2>
    </div>
    <div class="timeline">
      {% for e in experiences %}
      <div class="tl-item">
        <div class="tl-dot"></div>
        <div class="tl-card">
          <div class="tl-head">
            <div><h3>{{ e.title }}</h3><p class="tl-co"><i class="fas fa-building"></i> {{ e.company }}{% if e.location %} &middot; <i class="fas fa-map-marker-alt"></i> {{ e.location }}{% endif %}</p></div>
            <span class="tl-date">{{ e.start_date }} &mdash; {{ e.end_date }}</span>
          </div>
          {% if e.description %}<p class="tl-desc">{{ e.description }}</p>{% endif %}
        </div>
      </div>
      {% endfor %}
    </div>
  </div>
</section>
{% endif %}

<!-- TESTIMONIALS -->
{% if testimonials %}
<section class="section" id="testimonials">
  <div class="container">
    <div class="sec-header">
      <span class="sec-tag">// 05</span>
      <h2 class="sec-title">Client <span class="acc">Words</span></h2>
    </div>
    <div class="testi-grid">
      {% for t in testimonials %}
      <div class="testi-card">
        <div class="testi-stars">&#9733;&#9733;&#9733;&#9733;&#9733;</div>
        <p class="testi-txt">"{{ t.content }}"</p>
        <div class="testi-author">
          {% if t.avatar %}<img src="{{ url_for('static', filename='uploads/'+t.avatar) }}" alt="{{ t.name }}">
          {% else %}<div class="testi-av">{{ t.name[0] }}</div>{% endif %}
          <div><strong>{{ t.name }}</strong><span>{{ t.role }}{% if t.company %} &middot; {{ t.company }}{% endif %}</span></div>
        </div>
      </div>
      {% endfor %}
    </div>
  </div>
</section>
{% endif %}

<!-- CONTACT -->
<section class="section sec-dark" id="contact">
  <div class="container">
    <div class="sec-header">
      <span class="sec-tag">// 06</span>
      <h2 class="sec-title">Get In <span class="acc">Touch</span></h2>
      <p class="sec-sub">Ada project? Yuk ngobrol.</p>
    </div>
    <div class="contact-grid">
      <div class="contact-info">
        {% if settings.get('email') %}<div class="cinfo-item"><div class="cinfo-icon"><i class="fas fa-envelope"></i></div><div><h4>Email</h4><a href="mailto:{{ settings.get('email') }}">{{ settings.get('email') }}</a></div></div>{% endif %}
        {% if settings.get('phone') %}<div class="cinfo-item"><div class="cinfo-icon"><i class="fas fa-phone"></i></div><div><h4>Telepon</h4><p>{{ settings.get('phone') }}</p></div></div>{% endif %}
        {% if settings.get('location') %}<div class="cinfo-item"><div class="cinfo-icon"><i class="fas fa-map-marker-alt"></i></div><div><h4>Lokasi</h4><p>{{ settings.get('location') }}</p></div></div>{% endif %}
        <div class="cinfo-socials">
          {% if settings.get('github_url') %}<a href="{{ settings.get('github_url') }}" target="_blank" class="soc-btn"><i class="fab fa-github"></i> GitHub</a>{% endif %}
          {% if settings.get('linkedin_url') %}<a href="{{ settings.get('linkedin_url') }}" target="_blank" class="soc-btn"><i class="fab fa-linkedin"></i> LinkedIn</a>{% endif %}
        </div>
      </div>
      <form class="contact-form" id="contactForm">
        <input type="hidden" name="csrf_token" value="{{ form.csrf_token._value() }}">
        <div class="form-row">
          <div class="fg"><label>Nama *</label><input type="text" name="name" required placeholder="John Doe"></div>
          <div class="fg"><label>Email *</label><input type="email" name="email" required placeholder="john@example.com"></div>
        </div>
        <div class="fg"><label>Subjek</label><input type="text" name="subject" placeholder="Inquiry project..."></div>
        <div class="fg"><label>Pesan *</label><textarea name="message" rows="6" required placeholder="Ceritakan project-mu..."></textarea></div>
        <button type="submit" class="btn btn-primary btn-full">
          <span class="btn-txt">Kirim Pesan <i class="fas fa-paper-plane"></i></span>
          <span class="btn-load" style="display:none"><i class="fas fa-spinner fa-spin"></i> Mengirim...</span>
        </button>
      </form>
    </div>
  </div>
</section>
{% endblock %}

{% block scripts %}
<script>
// Animate skill bars
const obs = new IntersectionObserver(entries => {
  entries.forEach(e => {
    if(e.isIntersecting) {
      e.target.querySelectorAll('.sk-fill').forEach(b => { b.style.width = b.dataset.target + '%'; });
    }
  });
}, {threshold:0.3});
document.querySelectorAll('.skill-group').forEach(g => obs.observe(g));

// Contact form
document.getElementById('contactForm').addEventListener('submit', async function(e) {
  e.preventDefault();
  var btn = this.querySelector('button[type=submit]');
  btn.querySelector('.btn-txt').style.display='none';
  btn.querySelector('.btn-load').style.display='inline';
  btn.disabled=true;
  try {
    var r = await fetch('/contact',{method:'POST',body:new FormData(this)});
    var d = await r.json();
    showToast(d.message, d.success?'success':'error');
    if(d.success) this.reset();
  } catch(ex) { showToast('Terjadi kesalahan, coba lagi.','error'); }
  btn.querySelector('.btn-txt').style.display='inline';
  btn.querySelector('.btn-load').style.display='none';
  btn.disabled=false;
});
</script>
{% endblock %}
TMPL

echo "[OK] index.html"

# PROJECT DETAIL
cat > ${APP_DIR}/templates/project_detail.html << 'TMPL'
{% extends "base.html" %}
{% block title %}{{ project.name }}{% endblock %}
{% block content %}
<div class="pd-hero">
  <div class="container">
    <a href="{{ url_for('projects_page') }}" class="back-btn"><i class="fas fa-arrow-left"></i> Semua Project</a>
    <span class="proj-cat">{{ project.category }}</span>
    <h1>{{ project.name }}</h1>
    <p class="pd-sub">{{ project.description }}</p>
    <div class="pd-links">
      {% if project.live_url and project.live_url != '#' %}<a href="{{ project.live_url }}" target="_blank" class="btn btn-primary"><i class="fas fa-external-link-alt"></i> Live Demo</a>{% endif %}
      {% if project.github_url and project.github_url != '#' %}<a href="{{ project.github_url }}" target="_blank" class="btn btn-outline"><i class="fab fa-github"></i> Source Code</a>{% endif %}
    </div>
  </div>
</div>
<div class="container pd-body">
  {% if project.image %}<div class="pd-img"><img src="{{ url_for('static', filename='uploads/'+project.image) }}" alt="{{ project.name }}"></div>{% endif %}
  <div class="pd-grid">
    <div class="pd-main">
      {% if project.long_description %}<h2>Tentang Project</h2><p>{{ project.long_description }}</p>{% endif %}
    </div>
    <aside class="pd-aside">
      {% if techs %}<div class="aside-card"><h4>Tech Stack</h4><div class="tech-tags">{% for t in techs %}<span class="tech-tag">{{ t }}</span>{% endfor %}</div></div>{% endif %}
      {% if project.live_url or project.github_url %}<div class="aside-card"><h4>Links</h4>{% if project.live_url and project.live_url != '#' %}<a href="{{ project.live_url }}" target="_blank" class="aside-lnk"><i class="fas fa-external-link-alt"></i> Live Demo</a>{% endif %}{% if project.github_url and project.github_url != '#' %}<a href="{{ project.github_url }}" target="_blank" class="aside-lnk"><i class="fab fa-github"></i> GitHub</a>{% endif %}</div>{% endif %}
    </aside>
  </div>
  {% if related %}
  <div class="related"><h2>Project Terkait</h2>
    <div class="proj-grid">{% for p in related %}<article class="proj-card"><div class="proj-img">{% if p.image %}<img src="{{ url_for('static', filename='uploads/'+p.image) }}" alt="{{ p.name }}" loading="lazy">{% else %}<div class="proj-ph"><i class="fas fa-code"></i></div>{% endif %}</div><div class="proj-body"><h3><a href="{{ url_for('project_detail', pid=p.id) }}">{{ p.name }}</a></h3><p>{{ p.description[:100] }}...</p></div></article>{% endfor %}
    </div>
  </div>
  {% endif %}
</div>
{% endblock %}
TMPL

# PROJECTS PAGE
cat > ${APP_DIR}/templates/projects.html << 'TMPL'
{% extends "base.html" %}
{% block title %}Projects{% endblock %}
{% block content %}
<div class="page-hero"><div class="container"><h1>All <span class="acc">Projects</span></h1><p>Semua karya yang pernah saya buat</p></div></div>
<section class="section">
  <div class="container">
    {% if categories %}
    <div class="filter-bar">
      <button class="filter-btn {% if active_cat=='all' %}active{% endif %}" onclick="location.href='{{ url_for('projects_page') }}'">Semua</button>
      {% for c in categories %}<button class="filter-btn {% if active_cat==c %}active{% endif %}" onclick="location.href='{{ url_for('projects_page') }}?category={{ c }}'">{{ c }}</button>{% endfor %}
    </div>
    {% endif %}
    <div class="proj-grid">
      {% for p in projects %}
      <article class="proj-card">
        <div class="proj-img">{% if p.image %}<img src="{{ url_for('static', filename='uploads/'+p.image) }}" alt="{{ p.name }}" loading="lazy">{% else %}<div class="proj-ph"><i class="fas fa-code"></i></div>{% endif %}{% if p.featured %}<span class="proj-badge">Featured</span>{% endif %}</div>
        <div class="proj-body">
          <span class="proj-cat">{{ p.category }}</span>
          <h3><a href="{{ url_for('project_detail', pid=p.id) }}">{{ p.name }}</a></h3>
          <p>{{ p.description[:120] }}{% if p.description|length > 120 %}...{% endif %}</p>
          {% if p.tech_stack %}<div class="tech-tags">{% for t in p.tech_stack.split(',')[:3] %}<span>{{ t.strip() }}</span>{% endfor %}</div>{% endif %}
          <div class="proj-links"><a href="{{ url_for('project_detail', pid=p.id) }}" class="plink-main">Detail <i class="fas fa-arrow-right"></i></a>{% if p.github_url and p.github_url != '#' %}<a href="{{ p.github_url }}" target="_blank" class="plink-icon"><i class="fab fa-github"></i></a>{% endif %}{% if p.live_url and p.live_url != '#' %}<a href="{{ p.live_url }}" target="_blank" class="plink-icon"><i class="fas fa-external-link-alt"></i></a>{% endif %}</div>
        </div>
      </article>
      {% endfor %}
    </div>
  </div>
</section>
{% endblock %}
TMPL

# 404
cat > ${APP_DIR}/templates/404.html << 'TMPL'
{% extends "base.html" %}
{% block content %}
<div class="err-page"><div class="container"><div class="err-code">404</div><h1>Halaman Tidak Ditemukan</h1><p>Halaman yang kamu cari tidak ada atau sudah dipindahkan.</p><a href="{{ url_for('index') }}" class="btn btn-primary">Ke Beranda</a></div></div>
{% endblock %}
TMPL

ok "Public templates dibuat"

# ADMIN BASE
cat > ${APP_DIR}/templates/admin/base.html << 'TMPL'
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex,nofollow">
<title>Admin Panel | rizzdevs</title>
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700&family=Space+Mono:wght@400;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<link rel="stylesheet" href="{{ url_for('static', filename='css/admin.css') }}">
</head>
<body class="adm-body">
<div class="adm-layout">
  <aside class="sidebar" id="sidebar">
    <div class="sb-logo">[admin<span class="acc">panel</span>]</div>
    <nav class="sb-nav">
      <a href="{{ url_for('admin_dashboard') }}" class="sb-link {% if request.endpoint=='admin_dashboard' %}active{% endif %}"><i class="fas fa-tachometer-alt"></i> Dashboard</a>
      <a href="{{ url_for('admin_projects') }}" class="sb-link {% if 'project' in request.endpoint %}active{% endif %}"><i class="fas fa-folder-open"></i> Projects</a>
      <a href="{{ url_for('admin_skills') }}" class="sb-link {% if 'skill' in request.endpoint %}active{% endif %}"><i class="fas fa-code"></i> Skills</a>
      <a href="{{ url_for('admin_experience') }}" class="sb-link {% if 'experience' in request.endpoint %}active{% endif %}"><i class="fas fa-briefcase"></i> Experience</a>
      <a href="{{ url_for('admin_testimonials') }}" class="sb-link {% if 'testimonial' in request.endpoint %}active{% endif %}"><i class="fas fa-quote-left"></i> Testimonials</a>
      <a href="{{ url_for('admin_messages') }}" class="sb-link {% if 'message' in request.endpoint %}active{% endif %}"><i class="fas fa-envelope"></i> Messages</a>
      <a href="{{ url_for('admin_settings') }}" class="sb-link {% if 'settings' in request.endpoint %}active{% endif %}"><i class="fas fa-cog"></i> Settings</a>
      <div class="sb-sep"></div>
      <a href="{{ url_for('index') }}" class="sb-link" target="_blank"><i class="fas fa-globe"></i> Lihat Website</a>
      <a href="{{ url_for('admin_logout') }}" class="sb-link sb-logout"><i class="fas fa-sign-out-alt"></i> Logout</a>
    </nav>
  </aside>
  <main class="adm-main">
    <div class="adm-topbar">
      <button id="sbToggle" class="sb-toggle"><i class="fas fa-bars"></i></button>
      <div class="adm-user"><i class="fas fa-user-circle"></i> {{ current_user.email }}</div>
    </div>
    <div class="adm-content">
      {% with msgs = get_flashed_messages(with_categories=true) %}
      {% for cat,msg in msgs %}<div class="alert alert-{{ cat }}">{{ msg }}</div>{% endfor %}
      {% endwith %}
      {% block content %}{% endblock %}
    </div>
  </main>
</div>
<script>document.getElementById('sbToggle').onclick=()=>document.getElementById('sidebar').classList.toggle('open');</script>
</body>
</html>
TMPL

# ADMIN LOGIN
cat > ${APP_DIR}/templates/admin/login.html << 'TMPL'
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<meta name="robots" content="noindex,nofollow">
<title>Login</title>
<link href="https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=Syne:wght@700;800&display=swap" rel="stylesheet">
<link rel="stylesheet" href="{{ url_for('static', filename='css/admin.css') }}">
</head>
<body class="adm-body login-body">
<div class="login-wrap">
  <div class="login-card">
    <div class="login-logo">[rizz<span class="acc">devs</span>]</div>
    <h2>Admin Access</h2>
    {% if error %}<div class="alert alert-danger">{{ error }}</div>{% endif %}
    <form method="POST" autocomplete="off">
      <div class="fg"><label>Email</label><input type="email" name="email" required autofocus placeholder="admin@example.com"></div>
      <div class="fg"><label>Password</label><input type="password" name="password" required placeholder="&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;"></div>
      <button type="submit" class="btn-login">Masuk <i class="fas fa-arrow-right"></i></button>
    </form>
  </div>
</div>
</body>
</html>
TMPL

# ADMIN DASHBOARD
cat > ${APP_DIR}/templates/admin/dashboard.html << 'TMPL'
{% extends "admin/base.html" %}
{% block content %}
<h1 class="pg-title">Dashboard</h1>
<div class="stats-grid">
  <div class="stat-card"><div class="si"><i class="fas fa-folder-open"></i></div><div class="sv"><span class="sn">{{ projects_count }}</span><span class="sl">Projects</span></div></div>
  <div class="stat-card"><div class="si"><i class="fas fa-code"></i></div><div class="sv"><span class="sn">{{ skills_count }}</span><span class="sl">Skills</span></div></div>
  <div class="stat-card"><div class="si"><i class="fas fa-envelope"></i></div><div class="sv"><span class="sn">{{ messages_count }}</span><span class="sl">Messages</span></div></div>
  <div class="stat-card {% if unread_count %}hl{% endif %}"><div class="si"><i class="fas fa-bell"></i></div><div class="sv"><span class="sn">{{ unread_count }}</span><span class="sl">Belum Dibaca</span></div></div>
</div>
<div class="adm-box">
  <div class="box-hdr"><h2>Pesan Terbaru</h2><a href="{{ url_for('admin_messages') }}">Lihat Semua</a></div>
  {% if recent_messages %}
  <table class="adm-tbl">
    <thead><tr><th>Nama</th><th>Email</th><th>Subjek</th><th>Tanggal</th></tr></thead>
    <tbody>{% for m in recent_messages %}<tr {% if not m.read %}class="unread"{% endif %}><td>{{ m.name }}</td><td>{{ m.email }}</td><td>{{ m.subject or '-' }}</td><td>{{ m.created_at.strftime('%d/%m/%Y %H:%M') }}</td></tr>{% endfor %}</tbody>
  </table>
  {% else %}<p class="empty">Belum ada pesan.</p>{% endif %}
</div>
<div class="qa-section">
  <h2>Quick Actions</h2>
  <div class="qa-grid">
    <a href="{{ url_for('admin_project_new') }}" class="qa-card"><i class="fas fa-plus"></i> Project Baru</a>
    <a href="{{ url_for('admin_skill_new') }}" class="qa-card"><i class="fas fa-plus"></i> Tambah Skill</a>
    <a href="{{ url_for('admin_experience_new') }}" class="qa-card"><i class="fas fa-plus"></i> Tambah Experience</a>
    <a href="{{ url_for('admin_settings') }}" class="qa-card"><i class="fas fa-cog"></i> Settings</a>
  </div>
</div>
{% endblock %}
TMPL

# Buat semua admin templates lainnya
cat > ${APP_DIR}/templates/admin/projects.html << 'TMPL'
{% extends "admin/base.html" %}
{% block content %}
<div class="pg-hdr"><h1 class="pg-title">Projects</h1><a href="{{ url_for('admin_project_new') }}" class="btn-a-primary"><i class="fas fa-plus"></i> Baru</a></div>
<table class="adm-tbl">
  <thead><tr><th>Gambar</th><th>Nama</th><th>Kategori</th><th>Featured</th><th>Urutan</th><th>Aksi</th></tr></thead>
  <tbody>
    {% for p in projects %}
    <tr>
      <td>{% if p.image %}<img src="{{ url_for('static', filename='uploads/'+p.image) }}" class="tbl-thumb">{% else %}-{% endif %}</td>
      <td><strong>{{ p.name }}</strong></td><td>{{ p.category }}</td>
      <td>{% if p.featured %}<span class="badge-y">Ya</span>{% else %}Tidak{% endif %}</td>
      <td>{{ p.order }}</td>
      <td class="acts">
        <a href="{{ url_for('project_detail', pid=p.id) }}" target="_blank" class="act-v"><i class="fas fa-eye"></i></a>
        <a href="{{ url_for('admin_project_edit', pid=p.id) }}" class="act-e"><i class="fas fa-edit"></i></a>
        <form method="POST" action="{{ url_for('admin_project_delete', pid=p.id) }}" style="display:inline" onsubmit="return confirm('Hapus project ini?')"><button type="submit" class="act-d"><i class="fas fa-trash"></i></button></form>
      </td>
    </tr>
    {% else %}<tr><td colspan="6" class="empty">Belum ada project. <a href="{{ url_for('admin_project_new') }}">Tambah sekarang!</a></td></tr>
    {% endfor %}
  </tbody>
</table>
{% endblock %}
TMPL

cat > ${APP_DIR}/templates/admin/project_form.html << 'TMPL'
{% extends "admin/base.html" %}
{% block content %}
<div class="pg-hdr"><h1 class="pg-title">{{ title }}</h1><a href="{{ url_for('admin_projects') }}" class="btn-a-outline"><i class="fas fa-arrow-left"></i> Kembali</a></div>
<form method="POST" enctype="multipart/form-data" class="adm-form">
  {{ form.hidden_tag() }}
  <div class="fg2"><div class="fg">{{ form.name.label }}<br>{{ form.name(class='fc') }}</div><div class="fg">{{ form.category.label }}<br>{{ form.category(class='fc') }}</div></div>
  <div class="fg">{{ form.description.label }}<br>{{ form.description(class='fc', rows=3) }}</div>
  <div class="fg">{{ form.long_description.label }}<br>{{ form.long_description(class='fc', rows=6) }}</div>
  <div class="fg">{{ form.image.label }}<br>{{ form.image(class='fc') }}{% if project and project.image %}<img src="{{ url_for('static', filename='uploads/'+project.image) }}" style="margin-top:8px;max-height:120px;border-radius:8px">{% endif %}</div>
  <div class="fg2"><div class="fg">{{ form.live_url.label }}<br>{{ form.live_url(class='fc', placeholder='https://...') }}</div><div class="fg">{{ form.github_url.label }}<br>{{ form.github_url(class='fc', placeholder='https://github.com/...') }}</div></div>
  <div class="fg">{{ form.tech_stack.label }}<br>{{ form.tech_stack(class='fc', placeholder='Python, Flask, React') }}</div>
  <div class="fg2"><div class="fg">{{ form.order.label }}<br>{{ form.order(class='fc', placeholder='0') }}</div><div class="fg fcheck">{{ form.featured() }} {{ form.featured.label }}</div></div>
  <button type="submit" class="btn-a-primary">Simpan</button>
</form>
{% endblock %}
TMPL

cat > ${APP_DIR}/templates/admin/skills.html << 'TMPL'
{% extends "admin/base.html" %}
{% block content %}
<div class="pg-hdr"><h1 class="pg-title">Skills</h1><a href="{{ url_for('admin_skill_new') }}" class="btn-a-primary"><i class="fas fa-plus"></i> Baru</a></div>
<table class="adm-tbl">
  <thead><tr><th>Nama</th><th>Kategori</th><th>Level</th><th>Icon</th><th>Urutan</th><th>Aksi</th></tr></thead>
  <tbody>
    {% for s in skills %}
    <tr>
      <td><strong>{{ s.name }}</strong></td><td>{{ s.category }}</td>
      <td><div style="background:#1a2535;border-radius:4px;height:8px;width:100px"><div style="background:#00ff88;height:8px;border-radius:4px;width:{{ s.level }}%"></div></div> {{ s.level }}%</td>
      <td>{% if s.icon %}<i class="{{ s.icon }}"></i> <small>{{ s.icon }}</small>{% else %}-{% endif %}</td>
      <td>{{ s.order }}</td>
      <td class="acts">
        <a href="{{ url_for('admin_skill_edit', sid=s.id) }}" class="act-e"><i class="fas fa-edit"></i></a>
        <form method="POST" action="{{ url_for('admin_skill_delete', sid=s.id) }}" style="display:inline" onsubmit="return confirm('Hapus?')"><button type="submit" class="act-d"><i class="fas fa-trash"></i></button></form>
      </td>
    </tr>
    {% else %}<tr><td colspan="6" class="empty">Belum ada skill.</td></tr>{% endfor %}
  </tbody>
</table>
{% endblock %}
TMPL

cat > ${APP_DIR}/templates/admin/skill_form.html << 'TMPL'
{% extends "admin/base.html" %}
{% block content %}
<div class="pg-hdr"><h1 class="pg-title">{{ title }}</h1><a href="{{ url_for('admin_skills') }}" class="btn-a-outline"><i class="fas fa-arrow-left"></i> Kembali</a></div>
<form method="POST" class="adm-form">
  {{ form.hidden_tag() }}
  <div class="fg2"><div class="fg">{{ form.name.label }}<br>{{ form.name(class='fc') }}</div><div class="fg">{{ form.category.label }}<br>{{ form.category(class='fc') }}</div></div>
  <div class="fg2"><div class="fg">{{ form.level.label }}<br>{{ form.level(class='fc', placeholder='0-100') }}</div><div class="fg">{{ form.order.label }}<br>{{ form.order(class='fc', placeholder='0') }}</div></div>
  <div class="fg">{{ form.icon.label }}<br>{{ form.icon(class='fc', placeholder='devicon-python-plain') }}<small>Cek icon di <a href="https://devicon.dev" target="_blank">devicon.dev</a></small></div>
  <button type="submit" class="btn-a-primary">Simpan</button>
</form>
{% endblock %}
TMPL

cat > ${APP_DIR}/templates/admin/experience.html << 'TMPL'
{% extends "admin/base.html" %}
{% block content %}
<div class="pg-hdr"><h1 class="pg-title">Experience</h1><a href="{{ url_for('admin_experience_new') }}" class="btn-a-primary"><i class="fas fa-plus"></i> Baru</a></div>
<table class="adm-tbl">
  <thead><tr><th>Jabatan</th><th>Perusahaan</th><th>Periode</th><th>Urutan</th><th>Aksi</th></tr></thead>
  <tbody>
    {% for e in experiences %}
    <tr>
      <td><strong>{{ e.title }}</strong></td><td>{{ e.company }}</td>
      <td>{{ e.start_date }} - {{ e.end_date }}</td><td>{{ e.order }}</td>
      <td class="acts">
        <a href="{{ url_for('admin_experience_edit', eid=e.id) }}" class="act-e"><i class="fas fa-edit"></i></a>
        <form method="POST" action="{{ url_for('admin_experience_delete', eid=e.id) }}" style="display:inline" onsubmit="return confirm('Hapus?')"><button type="submit" class="act-d"><i class="fas fa-trash"></i></button></form>
      </td>
    </tr>
    {% else %}<tr><td colspan="5" class="empty">Belum ada data experience.</td></tr>{% endfor %}
  </tbody>
</table>
{% endblock %}
TMPL

cat > ${APP_DIR}/templates/admin/experience_form.html << 'TMPL'
{% extends "admin/base.html" %}
{% block content %}
<div class="pg-hdr"><h1 class="pg-title">{{ title }}</h1><a href="{{ url_for('admin_experience') }}" class="btn-a-outline"><i class="fas fa-arrow-left"></i> Kembali</a></div>
<form method="POST" class="adm-form">
  {{ form.hidden_tag() }}
  <div class="fg2"><div class="fg">{{ form.title.label }}<br>{{ form.title(class='fc') }}</div><div class="fg">{{ form.company.label }}<br>{{ form.company(class='fc') }}</div></div>
  <div class="fg2"><div class="fg">{{ form.location.label }}<br>{{ form.location(class='fc') }}</div><div class="fg">{{ form.order.label }}<br>{{ form.order(class='fc') }}</div></div>
  <div class="fg2"><div class="fg">{{ form.start_date.label }}<br>{{ form.start_date(class='fc', placeholder='Jan 2022') }}</div><div class="fg">{{ form.end_date.label }}<br>{{ form.end_date(class='fc', placeholder='Present') }}</div></div>
  <div class="fg">{{ form.description.label }}<br>{{ form.description(class='fc', rows=5) }}</div>
  <button type="submit" class="btn-a-primary">Simpan</button>
</form>
{% endblock %}
TMPL

cat > ${APP_DIR}/templates/admin/testimonials.html << 'TMPL'
{% extends "admin/base.html" %}
{% block content %}
<div class="pg-hdr"><h1 class="pg-title">Testimonials</h1><a href="{{ url_for('admin_testimonial_new') }}" class="btn-a-primary"><i class="fas fa-plus"></i> Baru</a></div>
<table class="adm-tbl">
  <thead><tr><th>Nama</th><th>Jabatan / Perusahaan</th><th>Aktif</th><th>Urutan</th><th>Aksi</th></tr></thead>
  <tbody>
    {% for t in testimonials %}
    <tr>
      <td><strong>{{ t.name }}</strong></td><td>{{ t.role }}{% if t.company %} &middot; {{ t.company }}{% endif %}</td>
      <td>{% if t.active %}<span class="badge-y">Ya</span>{% else %}Tidak{% endif %}</td><td>{{ t.order }}</td>
      <td class="acts">
        <a href="{{ url_for('admin_testimonial_edit', tid=t.id) }}" class="act-e"><i class="fas fa-edit"></i></a>
        <form method="POST" action="{{ url_for('admin_testimonial_delete', tid=t.id) }}" style="display:inline" onsubmit="return confirm('Hapus?')"><button type="submit" class="act-d"><i class="fas fa-trash"></i></button></form>
      </td>
    </tr>
    {% else %}<tr><td colspan="5" class="empty">Belum ada testimonial.</td></tr>{% endfor %}
  </tbody>
</table>
{% endblock %}
TMPL

cat > ${APP_DIR}/templates/admin/testimonial_form.html << 'TMPL'
{% extends "admin/base.html" %}
{% block content %}
<div class="pg-hdr"><h1 class="pg-title">{{ title }}</h1><a href="{{ url_for('admin_testimonials') }}" class="btn-a-outline"><i class="fas fa-arrow-left"></i> Kembali</a></div>
<form method="POST" enctype="multipart/form-data" class="adm-form">
  {{ form.hidden_tag() }}
  <div class="fg2"><div class="fg">{{ form.name.label }}<br>{{ form.name(class='fc') }}</div><div class="fg">{{ form.role.label }}<br>{{ form.role(class='fc') }}</div></div>
  <div class="fg2"><div class="fg">{{ form.company.label }}<br>{{ form.company(class='fc') }}</div><div class="fg">{{ form.order.label }}<br>{{ form.order(class='fc') }}</div></div>
  <div class="fg">{{ form.content.label }}<br>{{ form.content(class='fc', rows=5) }}</div>
  <div class="fg">{{ form.avatar.label }}<br>{{ form.avatar(class='fc') }}{% if item and item.avatar %}<img src="{{ url_for('static', filename='uploads/'+item.avatar) }}" style="margin-top:8px;max-height:80px;border-radius:50%">{% endif %}</div>
  <div class="fcheck">{{ form.active() }} {{ form.active.label }}</div>
  <button type="submit" class="btn-a-primary">Simpan</button>
</form>
{% endblock %}
TMPL

cat > ${APP_DIR}/templates/admin/messages.html << 'TMPL'
{% extends "admin/base.html" %}
{% block content %}
<h1 class="pg-title">Pesan Masuk</h1>
<table class="adm-tbl">
  <thead><tr><th>Nama</th><th>Email</th><th>Subjek</th><th>Pesan</th><th>Tanggal</th><th>Aksi</th></tr></thead>
  <tbody>
    {% for m in messages %}
    <tr {% if not m.read %}class="unread"{% endif %}>
      <td><strong>{{ m.name }}</strong></td><td><a href="mailto:{{ m.email }}">{{ m.email }}</a></td>
      <td>{{ m.subject or '-' }}</td><td>{{ m.message[:80] }}{% if m.message|length>80 %}...{% endif %}</td>
      <td>{{ m.created_at.strftime('%d/%m/%Y %H:%M') }}</td>
      <td class="acts">
        <form method="POST" action="{{ url_for('admin_message_delete', mid=m.id) }}" style="display:inline" onsubmit="return confirm('Hapus pesan ini?')"><button type="submit" class="act-d"><i class="fas fa-trash"></i></button></form>
      </td>
    </tr>
    {% else %}<tr><td colspan="6" class="empty">Belum ada pesan.</td></tr>{% endfor %}
  </tbody>
</table>
{% endblock %}
TMPL

cat > ${APP_DIR}/templates/admin/settings.html << 'TMPL'
{% extends "admin/base.html" %}
{% block content %}
<h1 class="pg-title">Pengaturan Website</h1>
<form method="POST" enctype="multipart/form-data" class="adm-form">
  {{ form.hidden_tag() }}
  <div class="adm-box"><h3>Hero Section</h3>
    <div class="fg2"><div class="fg">{{ form.hero_name.label }}<br>{{ form.hero_name(class='fc') }}</div><div class="fg">{{ form.hero_tagline.label }}<br>{{ form.hero_tagline(class='fc') }}</div></div>
    <div class="fg">{{ form.hero_bio.label }}<br>{{ form.hero_bio(class='fc', rows=4) }}</div>
    <div class="fg">{{ form.hero_image.label }}<br>{{ form.hero_image(class='fc') }}{% if settings.get('hero_image') %}<img src="{{ url_for('static', filename='uploads/'+settings.get('hero_image')) }}" style="margin-top:8px;max-height:120px;border-radius:12px">{% endif %}</div>
  </div>
  <div class="adm-box"><h3>About</h3>
    <div class="fg">{{ form.about_text.label }}<br>{{ form.about_text(class='fc', rows=5) }}</div>
    <div class="fg">{{ form.cv_url.label }}<br>{{ form.cv_url(class='fc') }}</div>
  </div>
  <div class="adm-box"><h3>Kontak</h3>
    <div class="fg2"><div class="fg">{{ form.email.label }}<br>{{ form.email(class='fc') }}</div><div class="fg">{{ form.phone.label }}<br>{{ form.phone(class='fc') }}</div></div>
    <div class="fg">{{ form.location.label }}<br>{{ form.location(class='fc') }}</div>
  </div>
  <div class="adm-box"><h3>Social Media</h3>
    <div class="fg2"><div class="fg">{{ form.github_url.label }}<br>{{ form.github_url(class='fc') }}</div><div class="fg">{{ form.linkedin_url.label }}<br>{{ form.linkedin_url(class='fc') }}</div></div>
    <div class="fg2"><div class="fg">{{ form.twitter_url.label }}<br>{{ form.twitter_url(class='fc') }}</div><div class="fg">{{ form.instagram_url.label }}<br>{{ form.instagram_url(class='fc') }}</div></div>
  </div>
  <div class="adm-box"><h3>Footer</h3>
    <div class="fg">{{ form.footer_text.label }}<br>{{ form.footer_text(class='fc', rows=3) }}</div>
    <div class="fg">{{ form.footer_copyright.label }}<br>{{ form.footer_copyright(class='fc') }}</div>
  </div>
  <div class="adm-box"><h3>SEO</h3>
    <div class="fg">{{ form.meta_description.label }}<br>{{ form.meta_description(class='fc', rows=3) }}</div>
  </div>
  <button type="submit" class="btn-a-primary">Simpan Pengaturan</button>
</form>
{% endblock %}
TMPL

ok "Semua templates admin dibuat"

# ============================================================
# LANGKAH 7: BUAT CSS & JS
# ============================================================
step "LANGKAH 7/10: Buat CSS dan JavaScript"

cat > ${APP_DIR}/static/css/style.css << 'CSSEOF'
:root{--bg:#080c12;--bg2:#0d1320;--bg3:#111927;--bd:rgba(255,255,255,.07);--txt:#e2e8f0;--muted:#64748b;--acc:#00ff88;--acc2:#00d4ff;--acc3:#ff006e;--adim:rgba(0,255,136,.08);--card:#0f1923;--r:12px;--rl:20px;--fn:'Syne',sans-serif;--fm:'Space Mono',monospace;--tr:all .3s cubic-bezier(.4,0,.2,1)}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{background:var(--bg);color:var(--txt);font-family:var(--fn);line-height:1.7;overflow-x:hidden}
a{color:inherit;text-decoration:none}
img{max-width:100%;display:block}
.container{max-width:1200px;margin:0 auto;padding:0 1.5rem}
.acc{color:var(--acc)}
.noise{position:fixed;inset:0;z-index:999;pointer-events:none;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='200' height='200'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.75' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='200' height='200' filter='url(%23n)' opacity='0.03'/%3E%3C/svg%3E");opacity:.5}

/* NAV */
.navbar{position:fixed;top:0;left:0;right:0;z-index:100;padding:1rem 0;transition:var(--tr)}
.navbar.scrolled{background:rgba(8,12,18,.95);backdrop-filter:blur(20px);border-bottom:1px solid var(--bd);padding:.75rem 0}
.nav-wrap{display:flex;align-items:center;justify-content:space-between}
.logo{font-family:var(--fm);font-size:1.2rem;font-weight:700}
.nav-links{display:flex;align-items:center;gap:2rem;list-style:none}
.nav-links a{font-family:var(--fm);font-size:.875rem;color:var(--muted);transition:var(--tr);position:relative}
.nav-links a:not(.btn-nav):hover{color:var(--txt)}
.nav-links a:not(.btn-nav)::after{content:'';position:absolute;bottom:-2px;left:0;width:0;height:1px;background:var(--acc);transition:var(--tr)}
.nav-links a:not(.btn-nav):hover::after{width:100%}
.btn-nav{border:1px solid var(--acc)!important;color:var(--acc)!important;padding:.4rem 1rem;border-radius:6px}
.btn-nav:hover{background:var(--acc);color:var(--bg)!important}
.hamburger{display:none;background:none;border:none;cursor:pointer;flex-direction:column;gap:5px;padding:4px}
.hamburger span{width:24px;height:2px;background:var(--txt);display:block;transition:var(--tr)}
.mobile-menu{display:none;position:fixed;top:0;right:-100%;width:min(80vw,300px);height:100vh;background:var(--bg2);border-left:1px solid var(--bd);z-index:99;padding:5rem 2rem 2rem;transition:right .3s ease}
.mobile-menu.open{right:0;display:block}
.mobile-menu ul{list-style:none;display:flex;flex-direction:column;gap:1.5rem}
.mobile-menu a{font-family:var(--fm);font-size:1rem;color:var(--muted)}
.mobile-menu a:hover{color:var(--acc)}

/* HERO */
.hero{min-height:100vh;display:flex;align-items:center;position:relative;overflow:hidden;padding:8rem 0 4rem}
.hero-bg{position:absolute;inset:0;z-index:0}
.grid-bg{position:absolute;inset:0;background-image:linear-gradient(rgba(0,255,136,.04) 1px,transparent 1px),linear-gradient(90deg,rgba(0,255,136,.04) 1px,transparent 1px);background-size:50px 50px}
.glow-orb{position:absolute;top:-200px;right:-200px;width:700px;height:700px;background:radial-gradient(circle,rgba(0,255,136,.06) 0%,transparent 70%)}
.hero-inner{position:relative;z-index:1;display:grid;grid-template-columns:1fr 1fr;gap:4rem;align-items:center}
.badge{display:inline-flex;align-items:center;gap:.5rem;border:1px solid rgba(0,255,136,.3);background:rgba(0,255,136,.05);color:var(--acc);font-family:var(--fm);font-size:.8rem;padding:.4rem 1rem;border-radius:100px;margin-bottom:1.5rem}
.badge-dot{width:8px;height:8px;border-radius:50%;background:var(--acc);animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.5;transform:scale(.8)}}
.hero-title{font-size:clamp(2.5rem,5vw,4rem);font-weight:800;line-height:1.1;margin-bottom:1rem}
.hi{display:block;font-size:.55em;color:var(--muted);font-weight:400}
.name-text{display:block;background:linear-gradient(135deg,#fff 0%,var(--acc) 50%,var(--acc2) 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.tagline{font-size:1rem;color:var(--acc);font-family:var(--fm);margin-bottom:.75rem}
.bio{color:var(--muted);max-width:480px;margin-bottom:2rem}
.hero-btns{display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:3rem}
.hero-stats{display:flex;align-items:center;gap:2rem}
.hstat{text-align:center}
.hnum{display:block;font-family:var(--fm);font-size:1.8rem;font-weight:700;color:var(--acc)}
.hlbl{font-size:.75rem;color:var(--muted);font-family:var(--fm);text-transform:uppercase;letter-spacing:.1em}
.hdiv{width:1px;height:40px;background:var(--bd)}
.hero-visual{position:relative;display:flex;justify-content:center}
.img-wrap{position:relative;width:280px;height:280px}
.hero-img{width:100%;height:100%;object-fit:cover;border-radius:50%;position:relative;z-index:2;border:3px solid rgba(0,255,136,.3)}
.hero-placeholder{width:100%;height:100%;border-radius:50%;background:var(--bg3);display:flex;align-items:center;justify-content:center;font-size:4rem;color:var(--acc);position:relative;z-index:2;border:3px solid rgba(0,255,136,.3)}
.ring{position:absolute;border-radius:50%;border:1px solid rgba(0,255,136,.1);animation:rot 20s linear infinite}
.r1{inset:-20px}.r2{inset:-40px;animation-duration:30s;animation-direction:reverse}.r3{inset:-60px;animation-duration:40s}
@keyframes rot{from{transform:rotate(0)}to{transform:rotate(360deg)}}
.fc{position:absolute;background:var(--card);border:1px solid var(--bd);padding:.5rem .9rem;border-radius:10px;font-size:.78rem;font-family:var(--fm);display:flex;align-items:center;gap:.4rem;z-index:3;animation:fl 4s ease-in-out infinite;white-space:nowrap}
.fc i{color:var(--acc)}
.fc1{top:-10px;right:-20px}.fc2{bottom:30%;left:-30px;animation-delay:1.5s}.fc3{bottom:-10px;right:-10px;animation-delay:3s}
@keyframes fl{0%,100%{transform:translateY(0)}50%{transform:translateY(-10px)}}
.scroll-hint{position:absolute;bottom:2rem;left:50%;transform:translateX(-50%);display:flex;flex-direction:column;align-items:center;gap:.4rem;color:var(--muted);font-size:.75rem;font-family:var(--fm);z-index:1}
.s-mouse{width:22px;height:36px;border:2px solid var(--muted);border-radius:11px;display:flex;justify-content:center;padding-top:5px}
.s-dot{width:4px;height:7px;background:var(--acc);border-radius:2px;animation:sd 2s ease infinite}
@keyframes sd{0%{transform:translateY(0);opacity:1}100%{transform:translateY(13px);opacity:0}}

/* BUTTONS */
.btn{display:inline-flex;align-items:center;gap:.5rem;padding:.75rem 1.75rem;border-radius:var(--r);font-weight:600;font-family:var(--fm);font-size:.875rem;border:none;cursor:pointer;transition:var(--tr);text-decoration:none;white-space:nowrap}
.btn-primary{background:var(--acc);color:var(--bg)}
.btn-primary:hover{background:#00e67a;transform:translateY(-2px);box-shadow:0 8px 30px rgba(0,255,136,.3)}
.btn-outline{background:transparent;color:var(--acc);border:1px solid rgba(0,255,136,.4)}
.btn-outline:hover{background:rgba(0,255,136,.08);transform:translateY(-2px)}
.btn-full{width:100%;justify-content:center}

/* SECTIONS */
.section{padding:6rem 0}
.sec-dark{background:var(--bg2)}
.sec-header{margin-bottom:3rem}
.sec-tag{font-family:var(--fm);font-size:.8rem;color:var(--acc);letter-spacing:.2em}
.sec-title{font-size:clamp(2rem,4vw,3rem);font-weight:800;margin-top:.5rem}
.sec-sub{color:var(--muted);margin-top:.5rem}
.sec-footer{text-align:center;margin-top:3rem}

/* ABOUT */
.about-grid{display:grid;grid-template-columns:1fr 1fr;gap:4rem;align-items:start}
.about-text p{color:var(--muted);margin-bottom:1.5rem;line-height:1.8}
.about-info{display:flex;flex-direction:column;gap:.75rem;margin-bottom:1.5rem}
.ainfo{display:flex;align-items:center;gap:.75rem;font-family:var(--fm);font-size:.875rem;color:var(--muted)}
.ainfo i{color:var(--acc);width:16px}
.code-block{background:#040810;border:1px solid var(--bd);border-radius:var(--rl);overflow:hidden;font-family:var(--fm);font-size:.82rem}
.code-hdr{background:var(--bg3);padding:.6rem 1rem;display:flex;align-items:center;gap:.5rem;border-bottom:1px solid var(--bd)}
.dot{width:12px;height:12px;border-radius:50%}
.rd{background:#ff5f57}.yl{background:#febc2e}.gn{background:#28c840}
.code-fn{margin-left:auto;color:var(--muted);font-size:.78rem}
.code-body{padding:1.25rem;overflow-x:auto}
code{white-space:pre}
.ck{color:#ff79c6}.cc{color:#8be9fd}.cf{color:#50fa7b}.cs{color:#f1fa8c}

/* PROJECTS */
.proj-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:1.5rem}
.proj-card{background:var(--card);border:1px solid var(--bd);border-radius:var(--rl);overflow:hidden;transition:var(--tr)}
.proj-card:hover{border-color:rgba(0,255,136,.2);transform:translateY(-4px);box-shadow:0 20px 60px rgba(0,0,0,.4)}
.proj-img{position:relative;aspect-ratio:16/9;overflow:hidden}
.proj-img img{width:100%;height:100%;object-fit:cover;transition:transform .5s ease}
.proj-card:hover .proj-img img{transform:scale(1.05)}
.proj-ph{width:100%;height:100%;background:var(--bg3);display:flex;align-items:center;justify-content:center;font-size:2.5rem;color:var(--muted)}
.proj-badge{position:absolute;top:.75rem;left:.75rem;background:var(--acc);color:var(--bg);font-size:.7rem;font-weight:700;font-family:var(--fm);padding:.2rem .6rem;border-radius:4px}
.proj-body{padding:1.25rem}
.proj-cat{font-family:var(--fm);font-size:.75rem;color:var(--acc)}
.proj-body h3{margin:.4rem 0 .5rem;font-size:1.1rem}
.proj-body h3 a:hover{color:var(--acc)}
.proj-body p{color:var(--muted);font-size:.875rem;margin-bottom:1rem;line-height:1.6}
.tech-tags{display:flex;flex-wrap:wrap;gap:.4rem;margin-bottom:1rem}
.tech-tags span,.tech-tag{font-family:var(--fm);font-size:.7rem;background:var(--adim);color:var(--acc);padding:.2rem .5rem;border-radius:4px}
.proj-links{display:flex;align-items:center;gap:.75rem}
.plink-main{font-family:var(--fm);font-size:.8rem;color:var(--acc);display:flex;align-items:center;gap:.4rem;transition:gap .2s}
.plink-main:hover{gap:.75rem}
.plink-icon{width:32px;height:32px;border-radius:8px;background:var(--bg3);display:flex;align-items:center;justify-content:center;font-size:.9rem;color:var(--muted);transition:var(--tr)}
.plink-icon:hover{background:var(--adim);color:var(--acc)}

/* SKILLS */
.skill-group{margin-bottom:2.5rem}
.skill-cat{font-family:var(--fm);font-size:.85rem;color:var(--muted);text-transform:uppercase;letter-spacing:.15em;margin-bottom:1.5rem;padding-bottom:.5rem;border-bottom:1px solid var(--bd)}
.skill-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:1rem}
.skill-card{background:var(--card);border:1px solid var(--bd);border-radius:var(--r);padding:1.25rem;display:flex;flex-direction:column;gap:.75rem;transition:var(--tr)}
.skill-card:hover{border-color:rgba(0,255,136,.2)}
.sk-icon{font-size:2rem;color:var(--acc)}
.sk-letter{width:38px;height:38px;border-radius:9px;background:var(--adim);color:var(--acc);display:flex;align-items:center;justify-content:center;font-weight:700;font-size:1.1rem}
.sk-name{font-weight:600;font-size:.9rem}
.sk-bar-wrap{display:flex;align-items:center;gap:.75rem}
.sk-bar{flex:1;height:4px;background:var(--bg3);border-radius:2px;overflow:hidden}
.sk-fill{height:100%;background:linear-gradient(90deg,var(--acc),var(--acc2));border-radius:2px;transition:width 1.2s cubic-bezier(.4,0,.2,1)}
.sk-pct{font-family:var(--fm);font-size:.75rem;color:var(--acc);width:36px;text-align:right}

/* TIMELINE */
.timeline{position:relative;padding-left:2rem}
.timeline::before{content:'';position:absolute;left:8px;top:0;bottom:0;width:1px;background:var(--bd)}
.tl-item{position:relative;margin-bottom:2.5rem}
.tl-dot{position:absolute;left:-2rem;top:4px;width:16px;height:16px;border-radius:50%;background:var(--bg);border:2px solid var(--acc);box-shadow:0 0 12px rgba(0,255,136,.3)}
.tl-card{background:var(--card);border:1px solid var(--bd);border-radius:var(--r);padding:1.5rem;transition:var(--tr)}
.tl-card:hover{border-color:rgba(0,255,136,.2)}
.tl-head{display:flex;justify-content:space-between;align-items:flex-start;gap:1rem;margin-bottom:.75rem;flex-wrap:wrap}
.tl-head h3{font-size:1.1rem}
.tl-co{font-size:.875rem;color:var(--muted);margin-top:.25rem}
.tl-co i{color:var(--acc);margin-right:.25rem}
.tl-date{font-family:var(--fm);font-size:.8rem;color:var(--acc);white-space:nowrap}
.tl-desc{color:var(--muted);font-size:.9rem;line-height:1.7}

/* TESTIMONIALS */
.testi-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:1.5rem}
.testi-card{background:var(--card);border:1px solid var(--bd);border-radius:var(--rl);padding:1.75rem;transition:var(--tr)}
.testi-card:hover{border-color:rgba(0,255,136,.2)}
.testi-stars{color:#fbbf24;font-size:1rem;margin-bottom:1rem}
.testi-txt{color:var(--muted);font-style:italic;line-height:1.8;margin-bottom:1.5rem}
.testi-author{display:flex;align-items:center;gap:1rem}
.testi-author img{width:48px;height:48px;border-radius:50%;object-fit:cover}
.testi-av{width:48px;height:48px;border-radius:50%;background:var(--adim);color:var(--acc);display:flex;align-items:center;justify-content:center;font-weight:700;flex-shrink:0}
.testi-author strong{display:block;font-size:.9rem}
.testi-author span{font-size:.8rem;color:var(--muted);font-family:var(--fm)}

/* CONTACT */
.contact-grid{display:grid;grid-template-columns:1fr 1.5fr;gap:4rem}
.cinfo-item{display:flex;align-items:flex-start;gap:1rem;margin-bottom:1.5rem}
.cinfo-icon{width:46px;height:46px;border-radius:12px;background:var(--adim);color:var(--acc);display:flex;align-items:center;justify-content:center;font-size:1rem;flex-shrink:0}
.cinfo-item h4{font-size:.85rem;color:var(--muted);margin-bottom:.2rem;font-family:var(--fm)}
.cinfo-item a,.cinfo-item p{color:var(--txt);font-size:.9rem}
.cinfo-item a:hover{color:var(--acc)}
.cinfo-socials{display:flex;gap:.75rem;margin-top:2rem}
.soc-btn{display:flex;align-items:center;gap:.5rem;border:1px solid var(--bd);background:var(--card);padding:.6rem 1.1rem;border-radius:8px;font-family:var(--fm);font-size:.8rem;color:var(--muted);transition:var(--tr)}
.soc-btn:hover{border-color:var(--acc);color:var(--acc)}
.contact-form{display:flex;flex-direction:column;gap:1rem}
.form-row{display:grid;grid-template-columns:1fr 1fr;gap:1rem}
.fg{display:flex;flex-direction:column;gap:.4rem}
.fg label{font-size:.83rem;color:var(--muted);font-family:var(--fm)}
.fg input,.fg textarea{background:var(--bg2);border:1px solid var(--bd);border-radius:var(--r);padding:.85rem 1rem;color:var(--txt);font-family:var(--fn);font-size:.9rem;transition:var(--tr);resize:vertical}
.fg input:focus,.fg textarea:focus{outline:none;border-color:rgba(0,255,136,.4);box-shadow:0 0 0 3px rgba(0,255,136,.07)}
.fg input::placeholder,.fg textarea::placeholder{color:var(--muted)}

/* FOOTER */
.footer{background:var(--bg2);border-top:1px solid var(--bd);padding:4rem 0 2rem}
.footer-grid{display:grid;grid-template-columns:1.5fr 1fr 1.2fr;gap:3rem;margin-bottom:3rem}
.footer-brand p{color:var(--muted);font-size:.9rem;margin:1rem 0 1.5rem}
.socials{display:flex;gap:.75rem}
.socials a{width:36px;height:36px;border-radius:8px;background:var(--bg3);border:1px solid var(--bd);display:flex;align-items:center;justify-content:center;color:var(--muted);transition:var(--tr)}
.socials a:hover{background:var(--adim);color:var(--acc);border-color:rgba(0,255,136,.2)}
.footer-nav h4,.footer-contact-info h4{font-family:var(--fm);font-size:.78rem;color:var(--muted);text-transform:uppercase;letter-spacing:.1em;margin-bottom:1rem}
.footer-nav ul{list-style:none;display:flex;flex-direction:column;gap:.6rem}
.footer-nav a{color:var(--muted);font-size:.9rem;transition:var(--tr)}
.footer-nav a:hover{color:var(--acc)}
.footer-contact-info p{color:var(--muted);font-size:.875rem;margin-bottom:.5rem;display:flex;align-items:center;gap:.5rem}
.footer-contact-info i{color:var(--acc)}
.footer-bottom{display:flex;justify-content:space-between;align-items:center;border-top:1px solid var(--bd);padding-top:2rem;color:var(--muted);font-size:.85rem;font-family:var(--fm);flex-wrap:wrap;gap:1rem}

/* TOAST */
.toast{position:fixed;bottom:2rem;right:2rem;z-index:9999;background:var(--card);border:1px solid var(--bd);padding:1rem 1.5rem;border-radius:var(--r);font-family:var(--fm);font-size:.875rem;transform:translateY(100px);opacity:0;transition:var(--tr);max-width:340px}
.toast.show{transform:translateY(0);opacity:1}
.toast.success{border-color:var(--acc);color:var(--acc)}
.toast.error{border-color:var(--acc3);color:var(--acc3)}

/* PROJECT DETAIL */
.pd-hero{background:var(--bg2);padding:8rem 0 4rem;border-bottom:1px solid var(--bd)}
.back-btn{display:inline-flex;align-items:center;gap:.5rem;color:var(--muted);font-family:var(--fm);font-size:.875rem;margin-bottom:1.5rem;transition:var(--tr)}
.back-btn:hover{color:var(--acc)}
.pd-hero h1{font-size:clamp(2rem,4vw,3rem);font-weight:800;margin:.5rem 0 1rem}
.pd-sub{color:var(--muted);max-width:600px;margin-bottom:2rem}
.pd-links{display:flex;gap:1rem}
.pd-body{padding:4rem 0}
.pd-img{border-radius:var(--rl);overflow:hidden;margin-bottom:3rem;border:1px solid var(--bd)}
.pd-img img{width:100%}
.pd-grid{display:grid;grid-template-columns:1fr 280px;gap:3rem;margin-bottom:4rem}
.pd-main h2{font-size:1.5rem;margin-bottom:1rem}
.pd-main p{color:var(--muted);line-height:1.8}
.aside-card{background:var(--card);border:1px solid var(--bd);border-radius:var(--r);padding:1.25rem;margin-bottom:1rem}
.aside-card h4{font-family:var(--fm);font-size:.78rem;color:var(--muted);text-transform:uppercase;letter-spacing:.1em;margin-bottom:1rem}
.aside-lnk{display:flex;align-items:center;gap:.5rem;color:var(--muted);font-size:.9rem;padding:.5rem 0;border-bottom:1px solid var(--bd);transition:var(--tr)}
.aside-lnk:last-child{border-bottom:none}
.aside-lnk:hover{color:var(--acc)}
.related h2{font-size:1.5rem;margin-bottom:2rem}
.page-hero{background:var(--bg2);padding:8rem 0 4rem;border-bottom:1px solid var(--bd)}
.page-hero h1{font-size:clamp(2rem,4vw,3rem);font-weight:800}
.page-hero p{color:var(--muted);margin-top:.5rem;font-family:var(--fm)}
.filter-bar{display:flex;flex-wrap:wrap;gap:.75rem;margin-bottom:2.5rem}
.filter-btn{background:var(--card);border:1px solid var(--bd);color:var(--muted);font-family:var(--fm);font-size:.8rem;padding:.45rem 1.1rem;border-radius:100px;cursor:pointer;transition:var(--tr)}
.filter-btn.active,.filter-btn:hover{background:var(--adim);color:var(--acc);border-color:rgba(0,255,136,.3)}
.err-page{display:flex;align-items:center;justify-content:center;min-height:80vh;text-align:center;padding:4rem 1rem}
.err-code{font-size:8rem;font-weight:800;font-family:var(--fm);color:var(--acc);opacity:.3;line-height:1}
.err-page h1{font-size:2rem;margin:1rem 0 .5rem}
.err-page p{color:var(--muted);margin-bottom:2rem}

/* RESPONSIVE */
@media(max-width:1024px){.hero-inner,.about-grid,.contact-grid,.pd-grid{grid-template-columns:1fr}.hero-visual{order:-1}.hero-btns,.hero-stats,.badge{justify-content:center}.bio{margin-inline:auto}.footer-grid{grid-template-columns:1fr 1fr}}
@media(max-width:768px){.nav-links{display:none}.hamburger{display:flex}.hero{padding:6rem 0 4rem}.fc{display:none}.form-row{grid-template-columns:1fr}.footer-grid{grid-template-columns:1fr}.footer-bottom{flex-direction:column;text-align:center}.tl-head{flex-direction:column}}
CSSEOF

# ADMIN CSS
cat > ${APP_DIR}/static/css/admin.css << 'CSSEOF'
:root{--bg:#060a10;--bg2:#0a1018;--bg3:#0e1620;--sb:#080d14;--card:#0f1923;--bd:rgba(255,255,255,.07);--txt:#e2e8f0;--muted:#64748b;--acc:#00ff88;--danger:#ff4757;--warn:#ffa502;--r:10px;--fn:'Syne',sans-serif;--fm:'Space Mono',monospace;--sw:240px}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body.adm-body{background:var(--bg);color:var(--txt);font-family:var(--fn);min-height:100vh}
a{color:inherit;text-decoration:none}
img{max-width:100%}
.acc{color:var(--acc)}

.adm-layout{display:flex;min-height:100vh}
.sidebar{width:var(--sw);background:var(--sb);border-right:1px solid var(--bd);display:flex;flex-direction:column;position:fixed;left:0;top:0;bottom:0;z-index:50;overflow-y:auto;transition:transform .3s ease}
.sb-logo{padding:1.5rem;font-family:var(--fm);font-size:1rem;font-weight:700;border-bottom:1px solid var(--bd)}
.sb-nav{display:flex;flex-direction:column;padding:1rem 0;flex:1}
.sb-link{display:flex;align-items:center;gap:.75rem;padding:.7rem 1.5rem;color:var(--muted);font-size:.875rem;transition:all .2s;border-left:3px solid transparent}
.sb-link:hover,.sb-link.active{color:var(--txt);background:rgba(0,255,136,.05);border-left-color:var(--acc)}
.sb-link i{width:16px;text-align:center}
.sb-sep{height:1px;background:var(--bd);margin:.5rem 1rem}
.sb-logout:hover{color:var(--danger)!important;background:rgba(255,71,87,.05)!important}
.adm-main{margin-left:var(--sw);flex:1;display:flex;flex-direction:column;min-width:0}
.adm-topbar{position:sticky;top:0;z-index:40;background:rgba(8,13,20,.95);backdrop-filter:blur(20px);border-bottom:1px solid var(--bd);padding:.875rem 1.5rem;display:flex;justify-content:space-between;align-items:center}
.sb-toggle{background:none;border:none;color:var(--muted);cursor:pointer;font-size:1.1rem;padding:.25rem}
.adm-user{font-family:var(--fm);font-size:.8rem;color:var(--muted);display:flex;align-items:center;gap:.5rem}
.adm-content{padding:2rem 1.5rem;flex:1}
.pg-title{font-size:1.5rem;font-weight:700;margin-bottom:1.5rem}
.pg-hdr{display:flex;justify-content:space-between;align-items:center;margin-bottom:1.5rem;flex-wrap:wrap;gap:1rem}
.pg-hdr .pg-title{margin-bottom:0}

.stats-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:1rem;margin-bottom:2rem}
.stat-card{background:var(--card);border:1px solid var(--bd);border-radius:var(--r);padding:1.25rem;display:flex;align-items:center;gap:1rem;transition:border-color .2s}
.stat-card:hover,.stat-card.hl{border-color:rgba(0,255,136,.2)}
.si{font-size:1.5rem;color:var(--acc)}
.sn{display:block;font-size:1.75rem;font-weight:700;font-family:var(--fm);color:var(--acc)}
.sl{font-size:.75rem;color:var(--muted)}
.adm-box{background:var(--card);border:1px solid var(--bd);border-radius:var(--r);padding:1.5rem;margin-bottom:1.5rem}
.adm-box h3{font-size:.9rem;color:var(--muted);font-family:var(--fm);margin-bottom:1.25rem;padding-bottom:.5rem;border-bottom:1px solid var(--bd)}
.box-hdr{display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem}
.box-hdr h2{font-size:1rem}
.box-hdr a{font-family:var(--fm);font-size:.8rem;color:var(--acc)}
.qa-section{margin-bottom:1.5rem}
.qa-section h2{font-size:.9rem;font-family:var(--fm);color:var(--muted);text-transform:uppercase;letter-spacing:.1em;margin-bottom:1rem}
.qa-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:.75rem}
.qa-card{background:var(--card);border:1px solid var(--bd);border-radius:var(--r);padding:1rem;text-align:center;font-family:var(--fm);font-size:.8rem;color:var(--muted);transition:all .2s;display:flex;flex-direction:column;align-items:center;gap:.5rem}
.qa-card i{font-size:1.25rem;color:var(--acc)}
.qa-card:hover{border-color:rgba(0,255,136,.2);color:var(--txt)}

.adm-tbl{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--bd);border-radius:var(--r);overflow:hidden}
.adm-tbl th{background:var(--bg3);padding:.75rem 1rem;text-align:left;font-family:var(--fm);font-size:.72rem;color:var(--muted);text-transform:uppercase;letter-spacing:.1em;border-bottom:1px solid var(--bd)}
.adm-tbl td{padding:.75rem 1rem;border-bottom:1px solid var(--bd);font-size:.875rem;vertical-align:middle}
.adm-tbl tr:last-child td{border-bottom:none}
.adm-tbl tr:hover td{background:rgba(255,255,255,.02)}
.adm-tbl tr.unread td{font-weight:600}
.tbl-thumb{width:60px;height:40px;object-fit:cover;border-radius:6px}
.badge-y{background:rgba(0,255,136,.1);color:var(--acc);font-size:.72rem;padding:.2rem .5rem;border-radius:4px;font-family:var(--fm)}
.empty{color:var(--muted);text-align:center;padding:2rem;font-size:.9rem}
.empty a{color:var(--acc)}
.acts{display:flex;gap:.4rem;white-space:nowrap}
.act-v,.act-e,.act-d{width:30px;height:30px;border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:.8rem;transition:all .2s;border:none;cursor:pointer}
.act-v{background:rgba(0,212,255,.1);color:#00d4ff}.act-v:hover{background:rgba(0,212,255,.2)}
.act-e{background:rgba(255,165,2,.1);color:var(--warn)}.act-e:hover{background:rgba(255,165,2,.2)}
.act-d{background:rgba(255,71,87,.1);color:var(--danger)}.act-d:hover{background:rgba(255,71,87,.2)}

.btn-a-primary{background:var(--acc);color:#000;border:none;padding:.6rem 1.2rem;border-radius:var(--r);font-family:var(--fm);font-size:.85rem;font-weight:700;cursor:pointer;transition:all .2s;display:inline-flex;align-items:center;gap:.5rem}
.btn-a-primary:hover{background:#00e67a}
.btn-a-outline{background:transparent;color:var(--muted);border:1px solid var(--bd);padding:.6rem 1.2rem;border-radius:var(--r);font-family:var(--fm);font-size:.85rem;cursor:pointer;transition:all .2s;display:inline-flex;align-items:center;gap:.5rem}
.btn-a-outline:hover{border-color:var(--acc);color:var(--acc)}
.adm-form{max-width:760px}
.fg2{display:grid;grid-template-columns:1fr 1fr;gap:1rem}
.fg{display:flex;flex-direction:column;gap:.4rem;margin-bottom:.75rem}
.fg label{font-family:var(--fm);font-size:.78rem;color:var(--muted)}
.fg small{color:var(--muted);font-size:.72rem}
.fg small a{color:var(--acc)}
.fcheck{display:flex;align-items:center;gap:.5rem;margin-bottom:.75rem;font-size:.875rem}
.fcheck input{accent-color:var(--acc);width:16px;height:16px}
.fc{background:var(--bg2);border:1px solid var(--bd);border-radius:var(--r);padding:.7rem 1rem;color:var(--txt);font-family:var(--fn);font-size:.875rem;transition:border-color .2s;width:100%}
.fc:focus{outline:none;border-color:rgba(0,255,136,.4);box-shadow:0 0 0 3px rgba(0,255,136,.06)}
select.fc option{background:var(--bg2)}
.alert{padding:.875rem 1.25rem;border-radius:var(--r);margin-bottom:1rem;font-family:var(--fm);font-size:.85rem}
.alert-success{background:rgba(0,255,136,.1);border:1px solid rgba(0,255,136,.2);color:var(--acc)}
.alert-danger{background:rgba(255,71,87,.1);border:1px solid rgba(255,71,87,.2);color:var(--danger)}
.alert-warning{background:rgba(255,165,2,.1);border:1px solid rgba(255,165,2,.2);color:var(--warn)}

.login-body{display:flex;align-items:center;justify-content:center;min-height:100vh;background:radial-gradient(ellipse at center,#0a1018 0%,#060a10 100%)}
.login-wrap{width:100%;max-width:400px;padding:1.5rem}
.login-card{background:var(--card);border:1px solid var(--bd);border-radius:16px;padding:2.5rem;text-align:center}
.login-logo{font-family:var(--fm);font-size:1.3rem;font-weight:700;margin-bottom:1.5rem}
.login-card h2{font-size:1rem;color:var(--muted);margin-bottom:2rem;font-weight:400}
.login-card .fg{text-align:left}
.btn-login{width:100%;background:var(--acc);color:#000;border:none;padding:.875rem;border-radius:var(--r);font-family:var(--fm);font-weight:700;cursor:pointer;font-size:1rem;margin-top:1rem;transition:all .2s;display:flex;align-items:center;justify-content:center;gap:.5rem}
.btn-login:hover{background:#00e67a;transform:translateY(-1px)}

@media(max-width:768px){.sidebar{transform:translateX(-100%)}.sidebar.open{transform:translateX(0)}.adm-main{margin-left:0}.fg2{grid-template-columns:1fr}.stats-grid{grid-template-columns:1fr 1fr}}
CSSEOF

# MAIN JS
cat > ${APP_DIR}/static/js/main.js << 'JSEOF'
'use strict';
window.addEventListener('scroll',function(){
  var n=document.getElementById('navbar');
  if(n) n.classList.toggle('scrolled',window.scrollY>50);
});
var hbg=document.getElementById('hamburger');
var mm=document.getElementById('mobileMenu');
if(hbg&&mm){
  hbg.addEventListener('click',function(){ mm.classList.toggle('open'); });
  document.addEventListener('click',function(e){
    if(!hbg.contains(e.target)&&!mm.contains(e.target)) mm.classList.remove('open');
  });
}
function showToast(msg,type){
  var t=document.getElementById('toast');
  if(!t) return;
  t.textContent=msg;
  t.className='toast '+type+' show';
  setTimeout(function(){ t.classList.remove('show'); },4000);
}
window.showToast=showToast;
var io=new IntersectionObserver(function(entries){
  entries.forEach(function(e){
    if(e.isIntersecting){
      e.target.style.opacity='1';
      e.target.style.transform='translateY(0)';
    }
  });
},{threshold:0.1});
document.querySelectorAll('.sec-header,.proj-card,.skill-group,.tl-item,.testi-card,.cinfo-item').forEach(function(el){
  el.style.opacity='0';
  el.style.transform='translateY(24px)';
  el.style.transition='opacity .6s ease,transform .6s ease';
  io.observe(el);
});
JSEOF

ok "CSS dan JS dibuat"

# ============================================================
# LANGKAH 8: SETUP GUNICORN SERVICE
# ============================================================
step "LANGKAH 8/10: Setup Gunicorn + Systemd"

WORKERS=$(( $(nproc) * 2 + 1 ))

cat > ${APP_DIR}/gunicorn.conf.py << EOF
bind = "127.0.0.1:5000"
workers = ${WORKERS}
worker_class = "sync"
timeout = 120
accesslog = "/var/log/portfolio/access.log"
errorlog = "/var/log/portfolio/error.log"
loglevel = "info"
preload_app = True
chdir = "${APP_DIR}"
EOF

cat > /etc/systemd/system/portfolio.service << EOF
[Unit]
Description=Portfolio Flask App - rizzdevs.biz.id
After=network.target mysql.service
Wants=mysql.service

[Service]
Type=simple
User=www-data
Group=www-data
WorkingDirectory=${APP_DIR}
Environment="PATH=${APP_DIR}/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
EnvironmentFile=${APP_DIR}/.env
ExecStart=${APP_DIR}/venv/bin/gunicorn --config ${APP_DIR}/gunicorn.conf.py app:app
ExecReload=/bin/kill -s HUP \$MAINPID
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Set permissions
chown -R www-data:www-data ${APP_DIR}
chmod -R 755 ${APP_DIR}
chmod 600 ${APP_DIR}/.env
chmod 777 ${APP_DIR}/static/uploads

# Init database
info "Inisialisasi database..."
cd ${APP_DIR}
sudo -u www-data ${APP_DIR}/venv/bin/python3 -c "from app import init_db; init_db()"
if [ $? -ne 0 ]; then
    warn "init_db via www-data gagal, coba dengan root..."
    ${APP_DIR}/venv/bin/python3 -c "from app import init_db; init_db()"
fi

systemctl daemon-reload
systemctl enable portfolio
systemctl start portfolio
sleep 2

if systemctl is-active --quiet portfolio; then
    ok "Gunicorn service berjalan"
else
    warn "Service belum aktif, cek log: journalctl -u portfolio -n 30"
fi

# ============================================================
# LANGKAH 9: SETUP NGINX
# ============================================================
step "LANGKAH 9/10: Setup Nginx"

rm -f /etc/nginx/sites-enabled/default

cat > /etc/nginx/sites-available/portfolio << EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN} www.${DOMAIN};
    client_max_body_size 20M;
    server_tokens off;

    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml application/json application/javascript application/xml+rss image/svg+xml;

    location /static/ {
        alias ${APP_DIR}/static/;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_connect_timeout 60s;
        proxy_read_timeout 60s;
        proxy_buffering off;
    }

    location ~ /\\.env   { deny all; return 404; }
    location ~ /\\.git   { deny all; return 404; }
    location ~ \\.py\$   { deny all; return 404; }
    location = /favicon.ico { access_log off; log_not_found off; }
    location = /robots.txt  { access_log off; log_not_found off; }
}
EOF

ln -sf /etc/nginx/sites-available/portfolio /etc/nginx/sites-enabled/

nginx -t
if [ $? -eq 0 ]; then
    systemctl reload nginx
    ok "Nginx dikonfigurasi dan direload"
else
    err "Nginx config error!"
fi

# ============================================================
# LANGKAH 10: FIREWALL + SSL
# ============================================================
step "LANGKAH 10/10: Firewall, SSL, dan Fail2ban"

info "Setup UFW..."
ufw --force reset > /dev/null 2>&1
ufw default deny incoming > /dev/null
ufw default allow outgoing > /dev/null
ufw allow ssh > /dev/null
ufw allow 'Nginx Full' > /dev/null
ufw --force enable > /dev/null
ok "UFW firewall aktif"

info "Setup Fail2ban..."
cat > /etc/fail2ban/jail.local << 'F2B'
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true

[nginx-http-auth]
enabled = true
F2B
systemctl restart fail2ban > /dev/null 2>&1 && ok "Fail2ban aktif" || warn "Fail2ban gagal"

info "Mencoba setup SSL dengan Certbot..."
SERVER_IP=$(curl -4 -s --connect-timeout 5 ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
info "IP Server: ${SERVER_IP}"
warn "Pastikan DNS ${DOMAIN} sudah mengarah ke ${SERVER_IP} sebelum SSL!"

if certbot --nginx \
    --non-interactive \
    --agree-tos \
    --email "${ADMIN_EMAIL}" \
    -d "${DOMAIN}" \
    --redirect 2>/dev/null; then
    ok "SSL berhasil dipasang!"
    (crontab -l 2>/dev/null; echo "0 3 * * * certbot renew --quiet && systemctl reload nginx") | crontab -
else
    warn "SSL belum bisa dipasang (DNS mungkin belum arah ke server ini)"
    warn "Jalankan manual nanti: certbot --nginx -d ${DOMAIN}"
fi

# ============================================================
# RINGKASAN AKHIR
# ============================================================
echo ""
echo "============================================================"
echo "   INSTALASI SELESAI!"
echo "============================================================"
echo ""
echo "  Website  : http://${DOMAIN}"
echo "  Admin    : http://${DOMAIN}/secure-panel-7x9k2m"
echo "  Email    : ${ADMIN_EMAIL}"
echo "  Password : reRe2345@#\$@#\$E"
echo ""
echo "  [DATABASE - SIMPAN BAIK-BAIK!]"
echo "  DB Name  : ${DB_NAME}"
echo "  DB User  : ${DB_USER}"
echo "  DB Pass  : ${DB_PASS}"
echo ""
echo "  [PERINTAH BERGUNA]"
echo "  systemctl status portfolio     - cek status app"
echo "  systemctl restart portfolio    - restart app"
echo "  journalctl -u portfolio -f     - lihat log live"
echo "  systemctl reload nginx         - reload nginx"
echo ""
echo "  [CLOUDFLARE - SETELAH DNS AKTIF]"
echo "  1. DNS A record: ${DOMAIN} -> ${SERVER_IP}"
echo "  2. SSL/TLS Mode: Full (strict)"
echo "  3. Always Use HTTPS: ON"
echo "  4. Setelah Cloudflare aktif, jalankan:"
echo "     certbot --nginx -d ${DOMAIN} -d www.${DOMAIN}"
echo ""
echo "  [SECURITY]"
echo "  URL admin panel TERSEMBUNYI: /secure-panel-7x9k2m"
echo "  Route /admin dan lainnya return 404 untuk non-admin"
echo ""
echo "============================================================"
