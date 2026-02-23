#!/bin/bash

# ============================================================
# PORTFOLIO WEBSITE - AUTO INSTALLER
# Domain: rizzdevs.biz.id
# Author: Auto-generated installer
# ============================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

DOMAIN="rizzdevs.biz.id"
APP_DIR="/var/www/portfolio"
DB_NAME="portfolio_db"
DB_USER="portfolio_user"
DB_PASS="P@rtf0l10_$(openssl rand -hex 8)"
SECRET_KEY="$(openssl rand -hex 32)"
ADMIN_EMAIL="riskiardiane@gmail.com"
ADMIN_PASS='reRe2345@#$@#$E'

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
log_error()   { echo -e "${RED}[✗]${NC} $1"; exit 1; }
log_step()    { echo -e "\n${PURPLE}${BOLD}===> $1${NC}"; }

banner() {
cat << 'EOF'
╔═══════════════════════════════════════════════════════════╗
║          PORTFOLIO WEBSITE AUTO INSTALLER                 ║
║          Domain: rizzdevs.biz.id                         ║
║          Dark Theme | Full Stack | Admin Panel            ║
╚═══════════════════════════════════════════════════════════╝
EOF
}

check_root() {
    [[ $EUID -ne 0 ]] && log_error "Run as root: sudo bash install.sh"
}

check_os() {
    if ! command -v apt &>/dev/null; then
        log_error "Requires Ubuntu/Debian"
    fi
    log_success "OS check passed"
}

# ============================================================
# STEP 1: System Update & Dependencies
# ============================================================
install_deps() {
    log_step "Installing system dependencies"
    apt update -y
    apt upgrade -y
    apt install -y \
        python3 python3-pip python3-venv python3-dev \
        nginx certbot python3-certbot-nginx \
        mysql-server default-libmysqlclient-dev \
        git curl wget unzip \
        build-essential \
        ufw fail2ban \
        pkg-config
    log_success "Dependencies installed"
}

# ============================================================
# STEP 2: MySQL Setup
# ============================================================
setup_mysql() {
    log_step "Setting up MySQL database"
    systemctl start mysql
    systemctl enable mysql

    # Ubuntu 24 MySQL uses auth_socket for root - use sudo mysql
    mysql -u root -e "CREATE DATABASE IF NOT EXISTS ${DB_NAME} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
    mysql -u root -e "CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';"
    mysql -u root -e "GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'localhost';"
    mysql -u root -e "FLUSH PRIVILEGES;"

    log_success "MySQL configured: DB=${DB_NAME}, USER=${DB_USER}"
}

# ============================================================
# STEP 3: App Directory & Python Environment
# ============================================================
setup_app() {
    log_step "Setting up application directory"
    mkdir -p ${APP_DIR}/{static/{css,js,img,uploads},templates,instance}

    python3 -m venv ${APP_DIR}/venv

    ${APP_DIR}/venv/bin/pip install --upgrade pip
    ${APP_DIR}/venv/bin/pip install \
        flask \
        flask-sqlalchemy \
        flask-login \
        flask-wtf \
        flask-bcrypt \
        flask-migrate \
        mysqlclient \
        gunicorn \
        pillow \
        python-dotenv \
        werkzeug

    log_success "Python environment ready"
}

# ============================================================
# STEP 4: Create Flask Application
# ============================================================
create_app() {
    log_step "Creating Flask application"

    # .env file - use printf to safely handle special characters in password
    cat > ${APP_DIR}/.env << ENVEOF
SECRET_KEY=${SECRET_KEY}
DATABASE_URL=mysql+mysqldb://${DB_USER}:${DB_PASS}@localhost/${DB_NAME}?charset=utf8mb4
UPLOAD_FOLDER=${APP_DIR}/static/uploads
MAX_CONTENT_LENGTH=16777216
ENVEOF

    # Main app file
    cat > ${APP_DIR}/app.py << 'PYEOF'
import os
import uuid
from datetime import datetime
from functools import wraps
from flask import (Flask, render_template, redirect, url_for, flash,
                   request, jsonify, abort, session)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (LoginManager, UserMixin, login_user,
                         logout_user, login_required, current_user)
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import (StringField, PasswordField, TextAreaField,
                     BooleanField, SelectField)
from wtforms.validators import DataRequired, Length
from werkzeug.utils import secure_filename  # noqa: F401
from PIL import Image
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'fallback-secret')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.environ.get('UPLOAD_FOLDER', 'static/uploads')
app.config['MAX_CONTENT_LENGTH'] = int(os.environ.get('MAX_CONTENT_LENGTH', 16777216))
app.config['WTF_CSRF_TIME_LIMIT'] = 3600
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'svg'}
ALLOWED_EXTENSIONS_LIST = list(ALLOWED_EXTENSIONS)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = None  # No redirect for non-admin

# ============================================================
# MODELS
# ============================================================

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class SiteSettings(db.Model):
    __tablename__ = 'site_settings'
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.Text)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Project(db.Model):
    __tablename__ = 'projects'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    long_description = db.Column(db.Text)
    image = db.Column(db.String(500))
    live_url = db.Column(db.String(500))
    github_url = db.Column(db.String(500))
    tech_stack = db.Column(db.String(500))  # comma separated
    category = db.Column(db.String(100), default='Web Development')
    featured = db.Column(db.Boolean, default=False)
    order = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Skill(db.Model):
    __tablename__ = 'skills'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    level = db.Column(db.Integer, default=80)  # 0-100
    category = db.Column(db.String(100), default='Frontend')
    icon = db.Column(db.String(100))
    order = db.Column(db.Integer, default=0)

class Experience(db.Model):
    __tablename__ = 'experiences'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    company = db.Column(db.String(200), nullable=False)
    location = db.Column(db.String(200))
    start_date = db.Column(db.String(50), nullable=False)
    end_date = db.Column(db.String(50), default='Present')
    description = db.Column(db.Text)
    order = db.Column(db.Integer, default=0)

class Testimonial(db.Model):
    __tablename__ = 'testimonials'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(200))
    company = db.Column(db.String(200))
    content = db.Column(db.Text, nullable=False)
    avatar = db.Column(db.String(500))
    active = db.Column(db.Boolean, default=True)
    order = db.Column(db.Integer, default=0)

class ContactMessage(db.Model):
    __tablename__ = 'contact_messages'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(200), nullable=False)
    subject = db.Column(db.String(300))
    message = db.Column(db.Text, nullable=False)
    read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ============================================================
# HELPERS
# ============================================================

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_image(file, folder='uploads', size=(800, 600)):
    if not file or not allowed_file(file.filename):
        return None
    ext = file.filename.rsplit('.', 1)[1].lower()
    filename = f"{uuid.uuid4().hex}.{ext}"
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if ext in {'jpg', 'jpeg', 'png', 'webp'}:
        img = Image.open(file)
        img.thumbnail(size, Image.LANCZOS)
        img.save(path, optimize=True, quality=85)
    else:
        file.save(path)
    return filename

def get_setting(key, default=''):
    s = SiteSettings.query.filter_by(key=key).first()
    return s.value if s else default

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(404)  # Return 404 not 403 to hide admin pages
        return f(*args, **kwargs)
    return decorated

# ============================================================
# FORMS
# ============================================================

class ProjectForm(FlaskForm):
    name = StringField('Project Name', validators=[DataRequired(), Length(max=200)])
    description = TextAreaField('Short Description', validators=[DataRequired()])
    long_description = TextAreaField('Full Description')
    image = FileField('Image', validators=[FileAllowed(ALLOWED_EXTENSIONS_LIST)])
    live_url = StringField('Live URL')
    github_url = StringField('GitHub URL')
    tech_stack = StringField('Tech Stack (comma separated)')
    category = SelectField('Category', choices=[
        ('Web Development','Web Development'),
        ('Mobile App','Mobile App'),
        ('UI/UX Design','UI/UX Design'),
        ('Backend','Backend'),
        ('DevOps','DevOps'),
        ('Other','Other')
    ])
    featured = BooleanField('Featured')
    order = StringField('Order')

class SkillForm(FlaskForm):
    name = StringField('Skill Name', validators=[DataRequired()])
    level = StringField('Level (0-100)', validators=[DataRequired()])
    category = SelectField('Category', choices=[
        ('Frontend','Frontend'),('Backend','Backend'),
        ('Database','Database'),('DevOps','DevOps'),
        ('Design','Design'),('Other','Other')
    ])
    icon = StringField('Icon Class (devicon)')
    order = StringField('Order')

class ExperienceForm(FlaskForm):
    title = StringField('Job Title', validators=[DataRequired()])
    company = StringField('Company', validators=[DataRequired()])
    location = StringField('Location')
    start_date = StringField('Start Date', validators=[DataRequired()])
    end_date = StringField('End Date')
    description = TextAreaField('Description')
    order = StringField('Order')

class SettingsForm(FlaskForm):
    hero_name = StringField('Your Name')
    hero_tagline = StringField('Tagline')
    hero_bio = TextAreaField('Bio')
    hero_image = FileField('Hero Image', validators=[FileAllowed(ALLOWED_EXTENSIONS_LIST)])
    about_text = TextAreaField('About Text')
    email = StringField('Contact Email')
    phone = StringField('Phone')
    location = StringField('Location')
    github_url = StringField('GitHub URL')
    linkedin_url = StringField('LinkedIn URL')
    twitter_url = StringField('Twitter URL')
    instagram_url = StringField('Instagram URL')
    footer_text = TextAreaField('Footer Text')
    footer_copyright = StringField('Copyright Text')
    meta_description = TextAreaField('Meta Description')
    cv_url = StringField('CV/Resume URL')

class TestimonialForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    role = StringField('Role')
    company = StringField('Company')
    content = TextAreaField('Testimonial', validators=[DataRequired()])
    avatar = FileField('Avatar', validators=[FileAllowed(ALLOWED_EXTENSIONS_LIST)])
    active = BooleanField('Active')
    order = StringField('Order')

class ContactForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired()])
    subject = StringField('Subject')
    message = TextAreaField('Message', validators=[DataRequired()])

# ============================================================
# PUBLIC ROUTES
# ============================================================

@app.route('/')
def index():
    settings = {s.key: s.value for s in SiteSettings.query.all()}
    projects = Project.query.order_by(Project.order, Project.created_at.desc()).limit(6).all()
    featured = Project.query.filter_by(featured=True).order_by(Project.order).limit(3).all()
    skills = Skill.query.order_by(Skill.category, Skill.order).all()
    experiences = Experience.query.order_by(Experience.order).all()
    testimonials = Testimonial.query.filter_by(active=True).order_by(Testimonial.order).all()
    skill_categories = {}
    for skill in skills:
        if skill.category not in skill_categories:
            skill_categories[skill.category] = []
        skill_categories[skill.category].append(skill)
    form = ContactForm()
    return render_template('index.html',
        settings=settings, projects=projects, featured=featured,
        skill_categories=skill_categories, experiences=experiences,
        testimonials=testimonials, form=form)

@app.route('/projects')
def projects():
    settings = {s.key: s.value for s in SiteSettings.query.all()}
    category = request.args.get('category', 'all')
    if category != 'all':
        projs = Project.query.filter_by(category=category).order_by(Project.order, Project.created_at.desc()).all()
    else:
        projs = Project.query.order_by(Project.order, Project.created_at.desc()).all()
    categories = db.session.query(Project.category).distinct().all()
    categories = [c[0] for c in categories]
    return render_template('projects.html', projects=projs, categories=categories,
                           active_cat=category, settings=settings)

@app.route('/project/<int:id>')
def project_detail(id):
    project = db.session.get(Project, id)
    if project is None: abort(404)
    settings = {s.key: s.value for s in SiteSettings.query.all()}
    related = Project.query.filter(Project.category==project.category, Project.id!=project.id).limit(3).all()
    techs = [t.strip() for t in (project.tech_stack or '').split(',') if t.strip()]
    return render_template('project_detail.html', project=project, settings=settings,
                           related=related, techs=techs)

@app.route('/contact', methods=['POST'])
def contact():
    form = ContactForm()
    if form.validate_on_submit():
        msg = ContactMessage(
            name=form.name.data,
            email=form.email.data,
            subject=form.subject.data,
            message=form.message.data
        )
        db.session.add(msg)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Message sent successfully!'})
    return jsonify({'success': False, 'message': 'Please fill all required fields.'})

# ============================================================
# HIDDEN ADMIN LOGIN (returns 404 to non-admins)
# ============================================================

@app.route('/secure-panel-7x9k2m', methods=['GET', 'POST'])
def admin_login():
    if current_user.is_authenticated and current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    
    error = None
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password) and user.is_admin:
            login_user(user, remember=False)
            session.permanent = False
            return redirect(url_for('admin_dashboard'))
        else:
            error = 'Invalid credentials'
    
    return render_template('admin/login.html', error=error)

@app.route('/admin/logout')
def admin_logout():
    if current_user.is_authenticated:
        logout_user()
    return redirect(url_for('index'))

# ============================================================
# ADMIN ROUTES - All return 404 unless admin
# ============================================================

@app.route('/admin')
def admin_dashboard():
    if not current_user.is_authenticated or not current_user.is_admin:
        abort(404)
    projects_count = Project.query.count()
    skills_count = Skill.query.count()
    messages_count = ContactMessage.query.count()
    unread_count = ContactMessage.query.filter_by(read=False).count()
    recent_messages = ContactMessage.query.order_by(ContactMessage.created_at.desc()).limit(5).all()
    return render_template('admin/dashboard.html',
        projects_count=projects_count, skills_count=skills_count,
        messages_count=messages_count, unread_count=unread_count,
        recent_messages=recent_messages)

# --- PROJECTS CRUD ---
@app.route('/admin/projects')
def admin_projects():
    if not current_user.is_authenticated or not current_user.is_admin:
        abort(404)
    projects = Project.query.order_by(Project.order, Project.created_at.desc()).all()
    return render_template('admin/projects.html', projects=projects)

@app.route('/admin/projects/new', methods=['GET', 'POST'])
def admin_project_new():
    if not current_user.is_authenticated or not current_user.is_admin:
        abort(404)
    form = ProjectForm()
    if form.validate_on_submit():
        img = save_image(request.files.get('image'), size=(1200, 800))
        p = Project(
            name=form.name.data,
            description=form.description.data,
            long_description=form.long_description.data,
            image=img,
            live_url=form.live_url.data,
            github_url=form.github_url.data,
            tech_stack=form.tech_stack.data,
            category=form.category.data,
            featured=form.featured.data,
            order=int(form.order.data or 0)
        )
        db.session.add(p)
        db.session.commit()
        flash('Project created!', 'success')
        return redirect(url_for('admin_projects'))
    return render_template('admin/project_form.html', form=form, title='New Project')

@app.route('/admin/projects/<int:id>/edit', methods=['GET', 'POST'])
def admin_project_edit(id):
    if not current_user.is_authenticated or not current_user.is_admin:
        abort(404)
    p = db.session.get(Project, id)
    if p is None: abort(404)
    form = ProjectForm(obj=p)
    if form.validate_on_submit():
        img = save_image(request.files.get('image'), size=(1200, 800))
        p.name = form.name.data
        p.description = form.description.data
        p.long_description = form.long_description.data
        if img: p.image = img
        p.live_url = form.live_url.data
        p.github_url = form.github_url.data
        p.tech_stack = form.tech_stack.data
        p.category = form.category.data
        p.featured = form.featured.data
        p.order = int(form.order.data or 0)
        p.updated_at = datetime.utcnow()
        db.session.commit()
        flash('Project updated!', 'success')
        return redirect(url_for('admin_projects'))
    return render_template('admin/project_form.html', form=form, title='Edit Project', project=p)

@app.route('/admin/projects/<int:id>/delete', methods=['POST'])
def admin_project_delete(id):
    if not current_user.is_authenticated or not current_user.is_admin:
        abort(404)
    p = db.session.get(Project, id)
    if p is None: abort(404)
    db.session.delete(p)
    db.session.commit()
    flash('Project deleted!', 'success')
    return redirect(url_for('admin_projects'))

# --- SKILLS CRUD ---
@app.route('/admin/skills')
def admin_skills():
    if not current_user.is_authenticated or not current_user.is_admin:
        abort(404)
    skills = Skill.query.order_by(Skill.category, Skill.order).all()
    return render_template('admin/skills.html', skills=skills)

@app.route('/admin/skills/new', methods=['GET', 'POST'])
def admin_skill_new():
    if not current_user.is_authenticated or not current_user.is_admin:
        abort(404)
    form = SkillForm()
    if form.validate_on_submit():
        s = Skill(
            name=form.name.data,
            level=int(form.level.data or 80),
            category=form.category.data,
            icon=form.icon.data,
            order=int(form.order.data or 0)
        )
        db.session.add(s)
        db.session.commit()
        flash('Skill added!', 'success')
        return redirect(url_for('admin_skills'))
    return render_template('admin/skill_form.html', form=form, title='New Skill')

@app.route('/admin/skills/<int:id>/edit', methods=['GET', 'POST'])
def admin_skill_edit(id):
    if not current_user.is_authenticated or not current_user.is_admin:
        abort(404)
    s = db.session.get(Skill, id)
    if s is None: abort(404)
    form = SkillForm(obj=s)
    if form.validate_on_submit():
        s.name = form.name.data
        s.level = int(form.level.data or 80)
        s.category = form.category.data
        s.icon = form.icon.data
        s.order = int(form.order.data or 0)
        db.session.commit()
        flash('Skill updated!', 'success')
        return redirect(url_for('admin_skills'))
    return render_template('admin/skill_form.html', form=form, title='Edit Skill', skill=s)

@app.route('/admin/skills/<int:id>/delete', methods=['POST'])
def admin_skill_delete(id):
    if not current_user.is_authenticated or not current_user.is_admin:
        abort(404)
    s = db.session.get(Skill, id)
    if s is None: abort(404)
    db.session.delete(s)
    db.session.commit()
    flash('Skill deleted!', 'success')
    return redirect(url_for('admin_skills'))

# --- EXPERIENCE CRUD ---
@app.route('/admin/experience')
def admin_experience():
    if not current_user.is_authenticated or not current_user.is_admin:
        abort(404)
    exps = Experience.query.order_by(Experience.order).all()
    return render_template('admin/experience.html', experiences=exps)

@app.route('/admin/experience/new', methods=['GET', 'POST'])
def admin_experience_new():
    if not current_user.is_authenticated or not current_user.is_admin:
        abort(404)
    form = ExperienceForm()
    if form.validate_on_submit():
        e = Experience(
            title=form.title.data,
            company=form.company.data,
            location=form.location.data,
            start_date=form.start_date.data,
            end_date=form.end_date.data or 'Present',
            description=form.description.data,
            order=int(form.order.data or 0)
        )
        db.session.add(e)
        db.session.commit()
        flash('Experience added!', 'success')
        return redirect(url_for('admin_experience'))
    return render_template('admin/experience_form.html', form=form, title='New Experience')

@app.route('/admin/experience/<int:id>/edit', methods=['GET', 'POST'])
def admin_experience_edit(id):
    if not current_user.is_authenticated or not current_user.is_admin:
        abort(404)
    e = db.session.get(Experience, id)
    if e is None: abort(404)
    form = ExperienceForm(obj=e)
    if form.validate_on_submit():
        e.title = form.title.data
        e.company = form.company.data
        e.location = form.location.data
        e.start_date = form.start_date.data
        e.end_date = form.end_date.data or 'Present'
        e.description = form.description.data
        e.order = int(form.order.data or 0)
        db.session.commit()
        flash('Experience updated!', 'success')
        return redirect(url_for('admin_experience'))
    return render_template('admin/experience_form.html', form=form, title='Edit Experience', exp=e)

@app.route('/admin/experience/<int:id>/delete', methods=['POST'])
def admin_experience_delete(id):
    if not current_user.is_authenticated or not current_user.is_admin:
        abort(404)
    e = db.session.get(Experience, id)
    if e is None: abort(404)
    db.session.delete(e)
    db.session.commit()
    flash('Experience deleted!', 'success')
    return redirect(url_for('admin_experience'))

# --- SETTINGS ---
@app.route('/admin/settings', methods=['GET', 'POST'])
def admin_settings():
    if not current_user.is_authenticated or not current_user.is_admin:
        abort(404)
    form = SettingsForm()
    settings = {s.key: s.value for s in SiteSettings.query.all()}

    if form.validate_on_submit():
        fields = ['hero_name','hero_tagline','hero_bio','about_text','email','phone',
                  'location','github_url','linkedin_url','twitter_url','instagram_url',
                  'footer_text','footer_copyright','meta_description','cv_url']
        for field in fields:
            val = getattr(form, field).data or ''
            s = SiteSettings.query.filter_by(key=field).first()
            if s:
                s.value = val
            else:
                db.session.add(SiteSettings(key=field, value=val))

        img = save_image(request.files.get('hero_image'), size=(600, 600))
        if img:
            s = SiteSettings.query.filter_by(key='hero_image').first()
            if s: s.value = img
            else: db.session.add(SiteSettings(key='hero_image', value=img))

        db.session.commit()
        flash('Settings saved!', 'success')
        return redirect(url_for('admin_settings'))

    for field in form:
        if field.name in settings:
            field.data = settings[field.name]

    return render_template('admin/settings.html', form=form, settings=settings)

# --- TESTIMONIALS CRUD ---
@app.route('/admin/testimonials')
def admin_testimonials():
    if not current_user.is_authenticated or not current_user.is_admin:
        abort(404)
    items = Testimonial.query.order_by(Testimonial.order).all()
    return render_template('admin/testimonials.html', testimonials=items)

@app.route('/admin/testimonials/new', methods=['GET', 'POST'])
def admin_testimonial_new():
    if not current_user.is_authenticated or not current_user.is_admin:
        abort(404)
    form = TestimonialForm()
    if form.validate_on_submit():
        avatar = save_image(request.files.get('avatar'), size=(200, 200))
        t = Testimonial(
            name=form.name.data,
            role=form.role.data,
            company=form.company.data,
            content=form.content.data,
            avatar=avatar,
            active=form.active.data,
            order=int(form.order.data or 0)
        )
        db.session.add(t)
        db.session.commit()
        flash('Testimonial added!', 'success')
        return redirect(url_for('admin_testimonials'))
    return render_template('admin/testimonial_form.html', form=form, title='New Testimonial')

@app.route('/admin/testimonials/<int:id>/edit', methods=['GET', 'POST'])
def admin_testimonial_edit(id):
    if not current_user.is_authenticated or not current_user.is_admin:
        abort(404)
    t = db.session.get(Testimonial, id)
    if t is None: abort(404)
    form = TestimonialForm(obj=t)
    if form.validate_on_submit():
        avatar = save_image(request.files.get('avatar'), size=(200, 200))
        t.name = form.name.data
        t.role = form.role.data
        t.company = form.company.data
        t.content = form.content.data
        if avatar: t.avatar = avatar
        t.active = form.active.data
        t.order = int(form.order.data or 0)
        db.session.commit()
        flash('Testimonial updated!', 'success')
        return redirect(url_for('admin_testimonials'))
    return render_template('admin/testimonial_form.html', form=form, title='Edit Testimonial', item=t)

@app.route('/admin/testimonials/<int:id>/delete', methods=['POST'])
def admin_testimonial_delete(id):
    if not current_user.is_authenticated or not current_user.is_admin:
        abort(404)
    t = db.session.get(Testimonial, id)
    if t is None: abort(404)
    db.session.delete(t)
    db.session.commit()
    flash('Testimonial deleted!', 'success')
    return redirect(url_for('admin_testimonials'))

# --- MESSAGES ---
@app.route('/admin/messages')
def admin_messages():
    if not current_user.is_authenticated or not current_user.is_admin:
        abort(404)
    msgs = ContactMessage.query.order_by(ContactMessage.created_at.desc()).all()
    ContactMessage.query.filter_by(read=False).update({'read': True})
    db.session.commit()
    return render_template('admin/messages.html', messages=msgs)

@app.route('/admin/messages/<int:id>/delete', methods=['POST'])
def admin_message_delete(id):
    if not current_user.is_authenticated or not current_user.is_admin:
        abort(404)
    m = db.session.get(ContactMessage, id)
    if m is None: abort(404)
    db.session.delete(m)
    db.session.commit()
    flash('Message deleted!', 'success')
    return redirect(url_for('admin_messages'))

# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(404)
def not_found(e):
    settings = {s.key: s.value for s in SiteSettings.query.all()}
    return render_template('404.html', settings=settings), 404

@app.errorhandler(500)
def server_error(e):
    settings = {s.key: s.value for s in SiteSettings.query.all()}
    return render_template('404.html', settings=settings), 500

# ============================================================
# INIT DB & SEED
# ============================================================

def init_db():
    with app.app_context():
        db.create_all()
        
        # Create admin user
        if not User.query.filter_by(email='riskiardiane@gmail.com').first():
            admin = User(
                email='riskiardiane@gmail.com',
                password=bcrypt.generate_password_hash('reRe2345@#$@#$E').decode('utf-8'),
                is_admin=True
            )
            db.session.add(admin)

        # Default settings
        defaults = {
            'hero_name': 'Riski Ardiane',
            'hero_tagline': 'Full Stack Developer & Creative Technologist',
            'hero_bio': 'I craft digital experiences that blend elegant design with powerful functionality. Passionate about building scalable web applications and bringing ideas to life through code.',
            'about_text': 'I am a passionate Full Stack Developer with expertise in modern web technologies. I love creating elegant solutions to complex problems and am always eager to learn new things.',
            'email': 'riskiardiane@gmail.com',
            'phone': '+62 xxx xxxx xxxx',
            'location': 'Indonesia',
            'github_url': 'https://github.com/rizzdevs',
            'linkedin_url': '#',
            'twitter_url': '#',
            'instagram_url': '#',
            'footer_text': 'Building the web, one line at a time.',
            'footer_copyright': f'© {datetime.utcnow().year} Riski Ardiane. All rights reserved.',
            'meta_description': 'Full Stack Developer portfolio - Riski Ardiane | rizzdevs.biz.id',
            'cv_url': '#',
        }
        for key, val in defaults.items():
            if not SiteSettings.query.filter_by(key=key).first():
                db.session.add(SiteSettings(key=key, value=val))

        # Sample projects
        if Project.query.count() == 0:
            projects = [
                Project(name='E-Commerce Platform', description='Full-featured online store with payment integration, inventory management, and real-time analytics dashboard.',
                        tech_stack='Python,Flask,React,MySQL,Redis,Stripe', category='Web Development', featured=True, order=1,
                        live_url='#', github_url='#',
                        long_description='A complete e-commerce solution built with Flask and React. Features include user authentication, product management, shopping cart, Stripe payment processing, order tracking, and an admin dashboard with real-time analytics.'),
                Project(name='DevOps Dashboard', description='Real-time infrastructure monitoring dashboard with alerts, logs aggregation, and deployment pipeline visualization.',
                        tech_stack='Python,Flask,Docker,Grafana,PostgreSQL', category='DevOps', featured=True, order=2,
                        live_url='#', github_url='#'),
                Project(name='Mobile Task Manager', description='Cross-platform task management app with team collaboration, kanban boards, and productivity analytics.',
                        tech_stack='React Native,Node.js,MongoDB,Socket.io', category='Mobile App', featured=True, order=3,
                        live_url='#', github_url='#'),
                Project(name='AI Content Generator', description='GPT-powered content creation tool for blogs, social media, and marketing copy with SEO optimization.',
                        tech_stack='Python,OpenAI,FastAPI,React,PostgreSQL', category='Backend', order=4,
                        live_url='#', github_url='#'),
                Project(name='Portfolio CMS', description='Custom content management system built for creative professionals with drag-and-drop interface.',
                        tech_stack='Python,Flask,MySQL,JavaScript,CSS3', category='Web Development', order=5,
                        live_url='#', github_url='#'),
            ]
            db.session.add_all(projects)

        # Sample skills
        if Skill.query.count() == 0:
            skills = [
                Skill(name='Python', level=92, category='Backend', icon='devicon-python-plain', order=1),
                Skill(name='Flask', level=90, category='Backend', icon='devicon-flask-plain', order=2),
                Skill(name='Django', level=82, category='Backend', icon='devicon-django-plain', order=3),
                Skill(name='JavaScript', level=88, category='Frontend', icon='devicon-javascript-plain', order=1),
                Skill(name='React', level=85, category='Frontend', icon='devicon-react-original', order=2),
                Skill(name='Vue.js', level=75, category='Frontend', icon='devicon-vuejs-plain', order=3),
                Skill(name='HTML/CSS', level=95, category='Frontend', icon='devicon-html5-plain', order=4),
                Skill(name='MySQL', level=88, category='Database', icon='devicon-mysql-plain', order=1),
                Skill(name='PostgreSQL', level=82, category='Database', icon='devicon-postgresql-plain', order=2),
                Skill(name='MongoDB', level=78, category='Database', icon='devicon-mongodb-plain', order=3),
                Skill(name='Docker', level=80, category='DevOps', icon='devicon-docker-plain', order=1),
                Skill(name='Linux', level=85, category='DevOps', icon='devicon-linux-plain', order=2),
                Skill(name='Nginx', level=82, category='DevOps', icon='devicon-nginx-plain', order=3),
                Skill(name='Git', level=90, category='DevOps', icon='devicon-git-plain', order=4),
            ]
            db.session.add_all(skills)

        # Sample experience
        if Experience.query.count() == 0:
            exps = [
                Experience(title='Senior Full Stack Developer', company='Tech Solutions Co.', location='Remote',
                           start_date='Jan 2022', end_date='Present',
                           description='Leading development of enterprise web applications. Architecting microservices, mentoring junior devs, and driving technical decisions.',
                           order=1),
                Experience(title='Full Stack Developer', company='Digital Agency XYZ', location='Jakarta, Indonesia',
                           start_date='Mar 2020', end_date='Dec 2021',
                           description='Built responsive web applications for various clients. Worked with React, Node.js, and various databases.',
                           order=2),
                Experience(title='Junior Web Developer', company='Startup Hub', location='Bandung, Indonesia',
                           start_date='Jun 2018', end_date='Feb 2020',
                           description='Developed frontend features and REST APIs. Learned best practices in agile development.',
                           order=3),
            ]
            db.session.add_all(exps)

        # Sample testimonials
        if Testimonial.query.count() == 0:
            tests = [
                Testimonial(name='Ahmad Fauzi', role='CTO', company='TechCorp Indonesia',
                           content='Working with Riski was an absolute pleasure. His technical skills and attention to detail are outstanding. Delivered our project on time and exceeded expectations.',
                           active=True, order=1),
                Testimonial(name='Sarah Dewi', role='Product Manager', company='Digital Startup',
                           content='Riski has a rare combination of technical excellence and communication skills. He understood our requirements perfectly and built exactly what we needed.',
                           active=True, order=2),
                Testimonial(name='Budi Santoso', role='Founder', company='E-Commerce Brand',
                           content='Our e-commerce platform performance improved dramatically after Riski optimized our backend. Highly recommend!',
                           active=True, order=3),
            ]
            db.session.add_all(tests)

        db.session.commit()
        print("Database initialized successfully!")

if __name__ == '__main__':
    init_db()
    app.run(debug=False)
PYEOF

    log_success "Flask app created"
}

# ============================================================
# STEP 5: Create HTML Templates
# ============================================================
create_templates() {
    log_step "Creating HTML templates"

    mkdir -p ${APP_DIR}/templates/{admin}

    # ---- BASE TEMPLATE ----
    cat > ${APP_DIR}/templates/base.html << 'HTMLEOF'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="description" content="{{ settings.get('meta_description', 'Portfolio') }}">
<title>{% block title %}{{ settings.get('hero_name', 'Portfolio') }}{% endblock %} | rizzdevs</title>
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>⚡</text></svg>">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Space+Mono:ital,wght@0,400;0,700;1,400&family=Syne:wght@400;600;700;800&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/devicons/devicon@latest/devicon.min.css">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
{% block extra_head %}{% endblock %}
</head>
<body>
<div class="noise-overlay"></div>
<nav class="navbar" id="navbar">
  <div class="container nav-inner">
    <a href="{{ url_for('index') }}" class="nav-logo">
      <span class="logo-bracket">[</span>rizz<span class="logo-accent">devs</span><span class="logo-bracket">]</span>
    </a>
    <ul class="nav-links">
      <li><a href="{{ url_for('index') }}#about">About</a></li>
      <li><a href="{{ url_for('index') }}#projects">Projects</a></li>
      <li><a href="{{ url_for('index') }}#skills">Skills</a></li>
      <li><a href="{{ url_for('index') }}#experience">Experience</a></li>
      <li><a href="{{ url_for('index') }}#contact">Contact</a></li>
      <li><a href="{{ settings.get('cv_url', '#') }}" class="btn-nav" target="_blank">Resume ↗</a></li>
    </ul>
    <button class="hamburger" id="hamburger" aria-label="Menu">
      <span></span><span></span><span></span>
    </button>
  </div>
</nav>
<div class="mobile-menu" id="mobileMenu">
  <ul>
    <li><a href="{{ url_for('index') }}#about" class="mobile-link">About</a></li>
    <li><a href="{{ url_for('index') }}#projects" class="mobile-link">Projects</a></li>
    <li><a href="{{ url_for('index') }}#skills" class="mobile-link">Skills</a></li>
    <li><a href="{{ url_for('index') }}#experience" class="mobile-link">Experience</a></li>
    <li><a href="{{ url_for('index') }}#contact" class="mobile-link">Contact</a></li>
    <li><a href="{{ settings.get('cv_url', '#') }}" target="_blank">Resume ↗</a></li>
  </ul>
</div>

{% block content %}{% endblock %}

<footer class="footer">
  <div class="container">
    <div class="footer-grid">
      <div class="footer-brand">
        <a href="{{ url_for('index') }}" class="nav-logo">
          <span class="logo-bracket">[</span>rizz<span class="logo-accent">devs</span><span class="logo-bracket">]</span>
        </a>
        <p>{{ settings.get('footer_text', 'Building the web, one line at a time.') }}</p>
        <div class="social-links">
          {% if settings.get('github_url') %}<a href="{{ settings.get('github_url') }}" target="_blank"><i class="fab fa-github"></i></a>{% endif %}
          {% if settings.get('linkedin_url') %}<a href="{{ settings.get('linkedin_url') }}" target="_blank"><i class="fab fa-linkedin"></i></a>{% endif %}
          {% if settings.get('twitter_url') %}<a href="{{ settings.get('twitter_url') }}" target="_blank"><i class="fab fa-twitter"></i></a>{% endif %}
          {% if settings.get('instagram_url') %}<a href="{{ settings.get('instagram_url') }}" target="_blank"><i class="fab fa-instagram"></i></a>{% endif %}
        </div>
      </div>
      <div class="footer-links">
        <h4>Navigation</h4>
        <ul>
          <li><a href="{{ url_for('index') }}#about">About</a></li>
          <li><a href="{{ url_for('index') }}#projects">Projects</a></li>
          <li><a href="{{ url_for('index') }}#skills">Skills</a></li>
          <li><a href="{{ url_for('index') }}#contact">Contact</a></li>
        </ul>
      </div>
      <div class="footer-contact">
        <h4>Contact</h4>
        <p><i class="fas fa-envelope"></i> {{ settings.get('email', '') }}</p>
        <p><i class="fas fa-map-marker-alt"></i> {{ settings.get('location', '') }}</p>
        {% if settings.get('phone') %}<p><i class="fas fa-phone"></i> {{ settings.get('phone') }}</p>{% endif %}
      </div>
    </div>
    <div class="footer-bottom">
      <p>{{ settings.get('footer_copyright', '© 2024 All rights reserved.') }}</p>
      <p class="footer-credit">Crafted with <span class="accent">♥</span> & Python</p>
    </div>
  </div>
</footer>

<div id="toast" class="toast"></div>
<script src="{{ url_for('static', filename='js/main.js') }}"></script>
{% block extra_scripts %}{% endblock %}
</body>
</html>
HTMLEOF

    # ---- INDEX TEMPLATE ----
    cat > ${APP_DIR}/templates/index.html << 'HTMLEOF'
{% extends "base.html" %}
{% block content %}

<!-- HERO -->
<section class="hero" id="home">
  <div class="hero-bg">
    <div class="hero-grid"></div>
    <div class="hero-glow"></div>
  </div>
  <div class="container hero-inner">
    <div class="hero-text">
      <div class="hero-badge animate-in" style="animation-delay:.1s">
        <span class="badge-dot"></span> Available for hire
      </div>
      <h1 class="hero-title animate-in" style="animation-delay:.2s">
        <span class="greeting">Hello, I'm</span>
        <span class="name">{{ settings.get('hero_name', 'Developer') }}</span>
      </h1>
      <p class="hero-tagline animate-in" style="animation-delay:.3s">{{ settings.get('hero_tagline', '') }}</p>
      <p class="hero-bio animate-in" style="animation-delay:.4s">{{ settings.get('hero_bio', '') }}</p>
      <div class="hero-cta animate-in" style="animation-delay:.5s">
        <a href="#projects" class="btn btn-primary">View Work <i class="fas fa-arrow-right"></i></a>
        <a href="#contact" class="btn btn-outline">Get In Touch</a>
      </div>
      <div class="hero-stats animate-in" style="animation-delay:.6s">
        <div class="stat"><span class="stat-num">{{ projects|length }}+</span><span class="stat-label">Projects</span></div>
        <div class="stat-divider"></div>
        <div class="stat"><span class="stat-num">5+</span><span class="stat-label">Years Exp.</span></div>
        <div class="stat-divider"></div>
        <div class="stat"><span class="stat-num">{{ skill_categories|length * 4 }}+</span><span class="stat-label">Technologies</span></div>
      </div>
    </div>
    <div class="hero-visual animate-in" style="animation-delay:.3s">
      <div class="hero-image-wrap">
        {% if settings.get('hero_image') %}
        <img src="{{ url_for('static', filename='uploads/' + settings.get('hero_image')) }}" alt="{{ settings.get('hero_name') }}" class="hero-img">
        {% else %}
        <div class="hero-placeholder">
          <i class="fas fa-code"></i>
        </div>
        {% endif %}
        <div class="hero-ring ring-1"></div>
        <div class="hero-ring ring-2"></div>
        <div class="hero-ring ring-3"></div>
      </div>
      <div class="float-card card-1"><i class="fab fa-python"></i> Python</div>
      <div class="float-card card-2"><i class="fab fa-react"></i> React</div>
      <div class="float-card card-3"><i class="fas fa-server"></i> DevOps</div>
    </div>
  </div>
  <a href="#about" class="scroll-indicator">
    <div class="scroll-mouse"><div class="scroll-dot"></div></div>
    <span>scroll</span>
  </a>
</section>

<!-- ABOUT -->
<section class="section" id="about">
  <div class="container">
    <div class="section-header">
      <span class="section-tag">// 01</span>
      <h2 class="section-title">About <span class="accent">Me</span></h2>
    </div>
    <div class="about-grid">
      <div class="about-text">
        <p>{{ settings.get('about_text', '') }}</p>
        <div class="about-info">
          <div class="info-item"><i class="fas fa-envelope"></i><span>{{ settings.get('email', '') }}</span></div>
          <div class="info-item"><i class="fas fa-map-marker-alt"></i><span>{{ settings.get('location', '') }}</span></div>
        </div>
        <a href="{{ settings.get('cv_url', '#') }}" class="btn btn-primary" target="_blank">
          <i class="fas fa-download"></i> Download CV
        </a>
      </div>
      <div class="about-code">
        <div class="code-block">
          <div class="code-header">
            <span class="dot red"></span><span class="dot yellow"></span><span class="dot green"></span>
            <span class="code-filename">developer.py</span>
          </div>
          <pre class="code-content"><code><span class="c-kw">class</span> <span class="c-cl">Developer</span>:
    <span class="c-fn">def</span> <span class="c-fn">__init__</span>(self):
        self.name = <span class="c-str">"{{ settings.get('hero_name', 'Dev') }}"</span>
        self.role = <span class="c-str">"Full Stack Dev"</span>
        self.location = <span class="c-str">"{{ settings.get('location', 'Indonesia') }}"</span>
        self.skills = [
            <span class="c-str">"Python"</span>, <span class="c-str">"Flask"</span>,
            <span class="c-str">"React"</span>, <span class="c-str">"MySQL"</span>,
            <span class="c-str">"Docker"</span>, <span class="c-str">"Nginx"</span>
        ]

    <span class="c-fn">def</span> <span class="c-fn">get_passion</span>(self):
        <span class="c-kw">return</span> <span class="c-str">"Building amazing things"</span></code></pre>
        </div>
      </div>
    </div>
  </div>
</section>

<!-- FEATURED PROJECTS -->
{% if featured %}
<section class="section section-dark" id="featured">
  <div class="container">
    <div class="section-header">
      <span class="section-tag">// 02</span>
      <h2 class="section-title">Featured <span class="accent">Work</span></h2>
    </div>
    <div class="featured-grid">
      {% for project in featured %}
      <article class="featured-card {% if loop.first %}featured-main{% endif %}">
        <div class="feat-image">
          {% if project.image %}
          <img src="{{ url_for('static', filename='uploads/' + project.image) }}" alt="{{ project.name }}" loading="lazy">
          {% else %}
          <div class="feat-placeholder"><i class="fas fa-code"></i></div>
          {% endif %}
          <div class="feat-overlay">
            <div class="feat-links">
              {% if project.live_url and project.live_url != '#' %}<a href="{{ project.live_url }}" target="_blank" class="feat-link"><i class="fas fa-external-link-alt"></i></a>{% endif %}
              {% if project.github_url and project.github_url != '#' %}<a href="{{ project.github_url }}" target="_blank" class="feat-link"><i class="fab fa-github"></i></a>{% endif %}
            </div>
          </div>
        </div>
        <div class="feat-content">
          <span class="feat-cat">{{ project.category }}</span>
          <h3><a href="{{ url_for('project_detail', id=project.id) }}">{{ project.name }}</a></h3>
          <p>{{ project.description }}</p>
          {% if project.tech_stack %}
          <div class="feat-tech">
            {% for tech in project.tech_stack.split(',')[:4] %}
            <span>{{ tech.strip() }}</span>
            {% endfor %}
          </div>
          {% endif %}
        </div>
      </article>
      {% endfor %}
    </div>
    <div class="section-footer">
      <a href="{{ url_for('projects') }}" class="btn btn-outline">View All Projects <i class="fas fa-arrow-right"></i></a>
    </div>
  </div>
</section>
{% endif %}

<!-- ALL PROJECTS -->
<section class="section" id="projects">
  <div class="container">
    <div class="section-header">
      <span class="section-tag">// 03</span>
      <h2 class="section-title">All <span class="accent">Projects</span></h2>
    </div>
    <div class="projects-grid">
      {% for project in projects %}
      <article class="project-card" data-category="{{ project.category }}">
        <div class="proj-image">
          {% if project.image %}
          <img src="{{ url_for('static', filename='uploads/' + project.image) }}" alt="{{ project.name }}" loading="lazy">
          {% else %}
          <div class="proj-placeholder"><i class="fas fa-code"></i></div>
          {% endif %}
          {% if project.featured %}<span class="proj-badge">Featured</span>{% endif %}
        </div>
        <div class="proj-content">
          <span class="proj-cat">{{ project.category }}</span>
          <h3><a href="{{ url_for('project_detail', id=project.id) }}">{{ project.name }}</a></h3>
          <p>{{ project.description[:120] }}{% if project.description|length > 120 %}...{% endif %}</p>
          {% if project.tech_stack %}
          <div class="proj-tech">
            {% for tech in project.tech_stack.split(',')[:3] %}
            <span>{{ tech.strip() }}</span>
            {% endfor %}
          </div>
          {% endif %}
          <div class="proj-links">
            <a href="{{ url_for('project_detail', id=project.id) }}" class="proj-link-main">Details <i class="fas fa-arrow-right"></i></a>
            {% if project.github_url and project.github_url != '#' %}<a href="{{ project.github_url }}" target="_blank" class="proj-link-icon"><i class="fab fa-github"></i></a>{% endif %}
            {% if project.live_url and project.live_url != '#' %}<a href="{{ project.live_url }}" target="_blank" class="proj-link-icon"><i class="fas fa-external-link-alt"></i></a>{% endif %}
          </div>
        </div>
      </article>
      {% endfor %}
    </div>
  </div>
</section>

<!-- SKILLS -->
<section class="section section-dark" id="skills">
  <div class="container">
    <div class="section-header">
      <span class="section-tag">// 04</span>
      <h2 class="section-title">Tech <span class="accent">Stack</span></h2>
    </div>
    {% for category, skills in skill_categories.items() %}
    <div class="skill-group">
      <h3 class="skill-cat-title">{{ category }}</h3>
      <div class="skills-grid">
        {% for skill in skills %}
        <div class="skill-card">
          {% if skill.icon %}
          <i class="{{ skill.icon }} skill-icon"></i>
          {% else %}
          <span class="skill-letter">{{ skill.name[0] }}</span>
          {% endif %}
          <span class="skill-name">{{ skill.name }}</span>
          <div class="skill-bar-wrap">
            <div class="skill-bar" data-level="{{ skill.level }}">
              <div class="skill-fill" style="width:0%" data-target="{{ skill.level }}"></div>
            </div>
            <span class="skill-pct">{{ skill.level }}%</span>
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
<section class="section" id="experience">
  <div class="container">
    <div class="section-header">
      <span class="section-tag">// 05</span>
      <h2 class="section-title">Work <span class="accent">Experience</span></h2>
    </div>
    <div class="timeline">
      {% for exp in experiences %}
      <div class="timeline-item">
        <div class="timeline-dot"></div>
        <div class="timeline-content">
          <div class="timeline-header">
            <div>
              <h3>{{ exp.title }}</h3>
              <p class="timeline-company"><i class="fas fa-building"></i> {{ exp.company }}
                {% if exp.location %} · <i class="fas fa-map-marker-alt"></i> {{ exp.location }}{% endif %}
              </p>
            </div>
            <span class="timeline-date">{{ exp.start_date }} — {{ exp.end_date }}</span>
          </div>
          {% if exp.description %}<p class="timeline-desc">{{ exp.description }}</p>{% endif %}
        </div>
      </div>
      {% endfor %}
    </div>
  </div>
</section>
{% endif %}

<!-- TESTIMONIALS -->
{% if testimonials %}
<section class="section section-dark" id="testimonials">
  <div class="container">
    <div class="section-header">
      <span class="section-tag">// 06</span>
      <h2 class="section-title">Client <span class="accent">Words</span></h2>
    </div>
    <div class="testimonial-grid">
      {% for t in testimonials %}
      <div class="testimonial-card">
        <div class="testimonial-stars">★★★★★</div>
        <p class="testimonial-text">"{{ t.content }}"</p>
        <div class="testimonial-author">
          {% if t.avatar %}
          <img src="{{ url_for('static', filename='uploads/' + t.avatar) }}" alt="{{ t.name }}">
          {% else %}
          <div class="testimonial-avatar-placeholder">{{ t.name[0] }}</div>
          {% endif %}
          <div>
            <strong>{{ t.name }}</strong>
            <span>{{ t.role }}{% if t.company %} · {{ t.company }}{% endif %}</span>
          </div>
        </div>
      </div>
      {% endfor %}
    </div>
  </div>
</section>
{% endif %}

<!-- CONTACT -->
<section class="section" id="contact">
  <div class="container">
    <div class="section-header">
      <span class="section-tag">// 07</span>
      <h2 class="section-title">Get In <span class="accent">Touch</span></h2>
      <p class="section-sub">Have a project in mind? Let's talk.</p>
    </div>
    <div class="contact-grid">
      <div class="contact-info">
        <div class="contact-item">
          <div class="contact-icon"><i class="fas fa-envelope"></i></div>
          <div><h4>Email</h4><a href="mailto:{{ settings.get('email', '') }}">{{ settings.get('email', '') }}</a></div>
        </div>
        {% if settings.get('phone') %}
        <div class="contact-item">
          <div class="contact-icon"><i class="fas fa-phone"></i></div>
          <div><h4>Phone</h4><p>{{ settings.get('phone') }}</p></div>
        </div>
        {% endif %}
        <div class="contact-item">
          <div class="contact-icon"><i class="fas fa-map-marker-alt"></i></div>
          <div><h4>Location</h4><p>{{ settings.get('location', '') }}</p></div>
        </div>
        <div class="contact-social">
          {% if settings.get('github_url') %}<a href="{{ settings.get('github_url') }}" target="_blank" class="social-btn"><i class="fab fa-github"></i> GitHub</a>{% endif %}
          {% if settings.get('linkedin_url') %}<a href="{{ settings.get('linkedin_url') }}" target="_blank" class="social-btn"><i class="fab fa-linkedin"></i> LinkedIn</a>{% endif %}
        </div>
      </div>
      <form class="contact-form" id="contactForm">
        <input type="hidden" name="csrf_token" value="{{ form.csrf_token._value() }}">
        <div class="form-row">
          <div class="form-group">
            <label>Name *</label>
            <input type="text" name="name" required placeholder="John Doe">
          </div>
          <div class="form-group">
            <label>Email *</label>
            <input type="email" name="email" required placeholder="john@example.com">
          </div>
        </div>
        <div class="form-group">
          <label>Subject</label>
          <input type="text" name="subject" placeholder="Project inquiry...">
        </div>
        <div class="form-group">
          <label>Message *</label>
          <textarea name="message" rows="6" required placeholder="Tell me about your project..."></textarea>
        </div>
        <button type="submit" class="btn btn-primary btn-full">
          <span class="btn-text">Send Message <i class="fas fa-paper-plane"></i></span>
          <span class="btn-loading" style="display:none"><i class="fas fa-spinner fa-spin"></i> Sending...</span>
        </button>
      </form>
    </div>
  </div>
</section>
{% endblock %}

{% block extra_scripts %}
<script>
// Animate skill bars on scroll
const observer = new IntersectionObserver((entries) => {
  entries.forEach(e => {
    if(e.isIntersecting) {
      e.target.querySelectorAll('.skill-fill').forEach(bar => {
        bar.style.width = bar.dataset.target + '%';
      });
    }
  });
}, {threshold: 0.3});
document.querySelectorAll('.skill-group').forEach(g => observer.observe(g));

// Contact form
document.getElementById('contactForm').addEventListener('submit', async function(e) {
  e.preventDefault();
  const btn = this.querySelector('button[type=submit]');
  btn.querySelector('.btn-text').style.display = 'none';
  btn.querySelector('.btn-loading').style.display = 'inline';
  btn.disabled = true;
  const formData = new FormData(this);
  try {
    const r = await fetch('/contact', {method:'POST', body: formData});
    const data = await r.json();
    showToast(data.message, data.success ? 'success' : 'error');
    if(data.success) this.reset();
  } catch(err) {
    showToast('Something went wrong. Please try again.', 'error');
  }
  btn.querySelector('.btn-text').style.display = 'inline';
  btn.querySelector('.btn-loading').style.display = 'none';
  btn.disabled = false;
});
</script>
{% endblock %}
HTMLEOF

    # ---- PROJECT DETAIL ----
    cat > ${APP_DIR}/templates/project_detail.html << 'HTMLEOF'
{% extends "base.html" %}
{% block title %}{{ project.name }}{% endblock %}
{% block content %}
<div class="project-detail">
  <div class="proj-detail-hero">
    <div class="container">
      <a href="{{ url_for('projects') }}" class="back-btn"><i class="fas fa-arrow-left"></i> All Projects</a>
      <span class="feat-cat">{{ project.category }}</span>
      <h1>{{ project.name }}</h1>
      <p class="proj-detail-sub">{{ project.description }}</p>
      <div class="proj-detail-links">
        {% if project.live_url and project.live_url != '#' %}
        <a href="{{ project.live_url }}" target="_blank" class="btn btn-primary"><i class="fas fa-external-link-alt"></i> Live Demo</a>
        {% endif %}
        {% if project.github_url and project.github_url != '#' %}
        <a href="{{ project.github_url }}" target="_blank" class="btn btn-outline"><i class="fab fa-github"></i> Source Code</a>
        {% endif %}
      </div>
    </div>
  </div>
  <div class="container proj-detail-body">
    {% if project.image %}
    <div class="proj-detail-image">
      <img src="{{ url_for('static', filename='uploads/' + project.image) }}" alt="{{ project.name }}">
    </div>
    {% endif %}
    <div class="proj-detail-grid">
      <div class="proj-detail-main">
        {% if project.long_description %}
        <h2>About This Project</h2>
        <p>{{ project.long_description }}</p>
        {% endif %}
      </div>
      <aside class="proj-detail-aside">
        <div class="aside-card">
          <h4>Tech Stack</h4>
          <div class="tech-tags">
            {% for tech in techs %}
            <span class="tech-tag">{{ tech }}</span>
            {% endfor %}
          </div>
        </div>
        {% if project.live_url or project.github_url %}
        <div class="aside-card">
          <h4>Links</h4>
          {% if project.live_url and project.live_url != '#' %}<a href="{{ project.live_url }}" target="_blank" class="aside-link"><i class="fas fa-external-link-alt"></i> Live Demo</a>{% endif %}
          {% if project.github_url and project.github_url != '#' %}<a href="{{ project.github_url }}" target="_blank" class="aside-link"><i class="fab fa-github"></i> GitHub</a>{% endif %}
        </div>
        {% endif %}
      </aside>
    </div>
    {% if related %}
    <div class="related-projects">
      <h2>Related Projects</h2>
      <div class="projects-grid">
        {% for p in related %}
        <article class="project-card">
          <div class="proj-image">
            {% if p.image %}<img src="{{ url_for('static', filename='uploads/' + p.image) }}" alt="{{ p.name }}" loading="lazy">
            {% else %}<div class="proj-placeholder"><i class="fas fa-code"></i></div>{% endif %}
          </div>
          <div class="proj-content">
            <h3><a href="{{ url_for('project_detail', id=p.id) }}">{{ p.name }}</a></h3>
            <p>{{ p.description[:100] }}...</p>
          </div>
        </article>
        {% endfor %}
      </div>
    </div>
    {% endif %}
  </div>
</div>
{% endblock %}
HTMLEOF

    # ---- PROJECTS PAGE ----
    cat > ${APP_DIR}/templates/projects.html << 'HTMLEOF'
{% extends "base.html" %}
{% block title %}Projects{% endblock %}
{% block content %}
<div class="page-hero">
  <div class="container">
    <h1>All <span class="accent">Projects</span></h1>
    <p>A collection of things I've built</p>
  </div>
</div>
<section class="section">
  <div class="container">
    {% if categories %}
    <div class="filter-bar">
      <button class="filter-btn {% if active_cat == 'all' %}active{% endif %}" onclick="window.location='{{ url_for('projects') }}'">All</button>
      {% for cat in categories %}
      <button class="filter-btn {% if active_cat == cat %}active{% endif %}" onclick="window.location='{{ url_for('projects') }}?category={{ cat }}'">{{ cat }}</button>
      {% endfor %}
    </div>
    {% endif %}
    <div class="projects-grid">
      {% for project in projects %}
      <article class="project-card">
        <div class="proj-image">
          {% if project.image %}<img src="{{ url_for('static', filename='uploads/' + project.image) }}" alt="{{ project.name }}" loading="lazy">
          {% else %}<div class="proj-placeholder"><i class="fas fa-code"></i></div>{% endif %}
          {% if project.featured %}<span class="proj-badge">Featured</span>{% endif %}
        </div>
        <div class="proj-content">
          <span class="proj-cat">{{ project.category }}</span>
          <h3><a href="{{ url_for('project_detail', id=project.id) }}">{{ project.name }}</a></h3>
          <p>{{ project.description[:120] }}{% if project.description|length > 120 %}...{% endif %}</p>
          {% if project.tech_stack %}
          <div class="proj-tech">
            {% for tech in project.tech_stack.split(',')[:3] %}<span>{{ tech.strip() }}</span>{% endfor %}
          </div>
          {% endif %}
          <div class="proj-links">
            <a href="{{ url_for('project_detail', id=project.id) }}" class="proj-link-main">Details <i class="fas fa-arrow-right"></i></a>
            {% if project.github_url and project.github_url != '#' %}<a href="{{ project.github_url }}" target="_blank" class="proj-link-icon"><i class="fab fa-github"></i></a>{% endif %}
            {% if project.live_url and project.live_url != '#' %}<a href="{{ project.live_url }}" target="_blank" class="proj-link-icon"><i class="fas fa-external-link-alt"></i></a>{% endif %}
          </div>
        </div>
      </article>
      {% endfor %}
    </div>
  </div>
</section>
{% endblock %}
HTMLEOF

    # ---- 404 ----
    cat > ${APP_DIR}/templates/404.html << 'HTMLEOF'
{% extends "base.html" %}
{% block content %}
<div class="error-page">
  <div class="container">
    <div class="error-code">404</div>
    <h1>Page Not Found</h1>
    <p>The page you're looking for doesn't exist or has been moved.</p>
    <a href="{{ url_for('index') }}" class="btn btn-primary">Go Home</a>
  </div>
</div>
{% endblock %}
HTMLEOF

    # ---- ADMIN BASE ----
    cat > ${APP_DIR}/templates/admin/base.html << 'HTMLEOF'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Admin Panel | rizzdevs</title>
<meta name="robots" content="noindex, nofollow">
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700&family=Space+Mono:wght@400;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<link rel="stylesheet" href="{{ url_for('static', filename='css/admin.css') }}">
</head>
<body class="admin-body">
<div class="admin-layout">
  <aside class="admin-sidebar">
    <div class="admin-logo">
      <span class="logo-bracket">[</span>admin<span class="logo-accent">panel</span><span class="logo-bracket">]</span>
    </div>
    <nav class="admin-nav">
      <a href="{{ url_for('admin_dashboard') }}" class="admin-link {% if request.endpoint == 'admin_dashboard' %}active{% endif %}">
        <i class="fas fa-tachometer-alt"></i> Dashboard
      </a>
      <a href="{{ url_for('admin_projects') }}" class="admin-link {% if 'project' in request.endpoint %}active{% endif %}">
        <i class="fas fa-folder-open"></i> Projects
      </a>
      <a href="{{ url_for('admin_skills') }}" class="admin-link {% if 'skill' in request.endpoint %}active{% endif %}">
        <i class="fas fa-code"></i> Skills
      </a>
      <a href="{{ url_for('admin_experience') }}" class="admin-link {% if 'experience' in request.endpoint %}active{% endif %}">
        <i class="fas fa-briefcase"></i> Experience
      </a>
      <a href="{{ url_for('admin_testimonials') }}" class="admin-link {% if 'testimonial' in request.endpoint %}active{% endif %}">
        <i class="fas fa-quote-left"></i> Testimonials
      </a>
      <a href="{{ url_for('admin_messages') }}" class="admin-link {% if 'message' in request.endpoint %}active{% endif %}">
        <i class="fas fa-envelope"></i> Messages
      </a>
      <a href="{{ url_for('admin_settings') }}" class="admin-link {% if 'settings' in request.endpoint %}active{% endif %}">
        <i class="fas fa-cog"></i> Settings
      </a>
      <div class="admin-sep"></div>
      <a href="{{ url_for('index') }}" class="admin-link" target="_blank">
        <i class="fas fa-globe"></i> View Site
      </a>
      <a href="{{ url_for('admin_logout') }}" class="admin-link admin-logout">
        <i class="fas fa-sign-out-alt"></i> Logout
      </a>
    </nav>
  </aside>
  <main class="admin-main">
    <div class="admin-topbar">
      <button class="sidebar-toggle" id="sidebarToggle"><i class="fas fa-bars"></i></button>
      <div class="admin-user"><i class="fas fa-user-circle"></i> {{ current_user.email }}</div>
    </div>
    <div class="admin-content">
      {% with messages = get_flashed_messages(with_categories=true) %}
      {% for cat, msg in messages %}
      <div class="alert alert-{{ cat }}">{{ msg }}</div>
      {% endfor %}
      {% endwith %}
      {% block content %}{% endblock %}
    </div>
  </main>
</div>
<script>
document.getElementById('sidebarToggle').addEventListener('click', () => {
  document.querySelector('.admin-sidebar').classList.toggle('open');
});
</script>
</body>
</html>
HTMLEOF

    # ---- ADMIN LOGIN ----
    cat > ${APP_DIR}/templates/admin/login.html << 'HTMLEOF'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Login</title>
<meta name="robots" content="noindex, nofollow">
<link href="https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=Syne:wght@700;800&display=swap" rel="stylesheet">
<link rel="stylesheet" href="{{ url_for('static', filename='css/admin.css') }}">
</head>
<body class="admin-body login-body">
<div class="login-wrap">
  <div class="login-card">
    <div class="login-logo">
      <span class="logo-bracket">[</span>rizz<span class="logo-accent">devs</span><span class="logo-bracket">]</span>
    </div>
    <h2>Admin Access</h2>
    {% if error %}<div class="alert alert-danger">{{ error }}</div>{% endif %}
    <form method="POST" autocomplete="off">
      <div class="form-group">
        <label>Email</label>
        <input type="email" name="email" required autofocus placeholder="admin@example.com">
      </div>
      <div class="form-group">
        <label>Password</label>
        <input type="password" name="password" required placeholder="••••••••">
      </div>
      <button type="submit" class="btn-login">Sign In <i class="fas fa-arrow-right"></i></button>
    </form>
  </div>
</div>
</body>
</html>
HTMLEOF

    # ---- ADMIN DASHBOARD ----
    cat > ${APP_DIR}/templates/admin/dashboard.html << 'HTMLEOF'
{% extends "admin/base.html" %}
{% block content %}
<h1 class="page-title">Dashboard</h1>
<div class="stats-grid">
  <div class="stat-card"><div class="stat-icon"><i class="fas fa-folder-open"></i></div><div class="stat-info"><span class="stat-num">{{ projects_count }}</span><span class="stat-label">Projects</span></div></div>
  <div class="stat-card"><div class="stat-icon"><i class="fas fa-code"></i></div><div class="stat-info"><span class="stat-num">{{ skills_count }}</span><span class="stat-label">Skills</span></div></div>
  <div class="stat-card"><div class="stat-icon"><i class="fas fa-envelope"></i></div><div class="stat-info"><span class="stat-num">{{ messages_count }}</span><span class="stat-label">Messages</span></div></div>
  <div class="stat-card {% if unread_count > 0 %}stat-highlight{% endif %}"><div class="stat-icon"><i class="fas fa-bell"></i></div><div class="stat-info"><span class="stat-num">{{ unread_count }}</span><span class="stat-label">Unread</span></div></div>
</div>
<div class="admin-section">
  <div class="admin-section-header"><h2>Recent Messages</h2><a href="{{ url_for('admin_messages') }}">View All</a></div>
  {% if recent_messages %}
  <table class="admin-table">
    <thead><tr><th>Name</th><th>Email</th><th>Subject</th><th>Date</th></tr></thead>
    <tbody>
      {% for msg in recent_messages %}
      <tr {% if not msg.read %}class="unread"{% endif %}>
        <td>{{ msg.name }}</td>
        <td>{{ msg.email }}</td>
        <td>{{ msg.subject or '—' }}</td>
        <td>{{ msg.created_at.strftime('%Y-%m-%d %H:%M') }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}<p class="empty-state">No messages yet.</p>{% endif %}
</div>
<div class="quick-actions">
  <h2>Quick Actions</h2>
  <div class="action-grid">
    <a href="{{ url_for('admin_project_new') }}" class="action-card"><i class="fas fa-plus"></i> New Project</a>
    <a href="{{ url_for('admin_skill_new') }}" class="action-card"><i class="fas fa-plus"></i> Add Skill</a>
    <a href="{{ url_for('admin_experience_new') }}" class="action-card"><i class="fas fa-plus"></i> Add Experience</a>
    <a href="{{ url_for('admin_settings') }}" class="action-card"><i class="fas fa-cog"></i> Site Settings</a>
  </div>
</div>
{% endblock %}
HTMLEOF

    # ADMIN PROJECTS LIST
    cat > ${APP_DIR}/templates/admin/projects.html << 'HTMLEOF'
{% extends "admin/base.html" %}
{% block content %}
<div class="page-header">
  <h1 class="page-title">Projects</h1>
  <a href="{{ url_for('admin_project_new') }}" class="btn-admin-primary"><i class="fas fa-plus"></i> New Project</a>
</div>
<table class="admin-table">
  <thead><tr><th>Image</th><th>Name</th><th>Category</th><th>Featured</th><th>Order</th><th>Actions</th></tr></thead>
  <tbody>
    {% for p in projects %}
    <tr>
      <td>{% if p.image %}<img src="{{ url_for('static', filename='uploads/' + p.image) }}" class="table-thumb">{% else %}—{% endif %}</td>
      <td><strong>{{ p.name }}</strong></td>
      <td>{{ p.category }}</td>
      <td>{% if p.featured %}<span class="badge-yes">Yes</span>{% else %}No{% endif %}</td>
      <td>{{ p.order }}</td>
      <td class="actions">
        <a href="{{ url_for('project_detail', id=p.id) }}" target="_blank" class="action-view"><i class="fas fa-eye"></i></a>
        <a href="{{ url_for('admin_project_edit', id=p.id) }}" class="action-edit"><i class="fas fa-edit"></i></a>
        <form method="POST" action="{{ url_for('admin_project_delete', id=p.id) }}" style="display:inline" onsubmit="return confirm('Delete this project?')">
          <button type="submit" class="action-delete"><i class="fas fa-trash"></i></button>
        </form>
      </td>
    </tr>
    {% else %}
    <tr><td colspan="6" class="empty-state">No projects yet. <a href="{{ url_for('admin_project_new') }}">Add one!</a></td></tr>
    {% endfor %}
  </tbody>
</table>
{% endblock %}
HTMLEOF

    # ADMIN PROJECT FORM
    cat > ${APP_DIR}/templates/admin/project_form.html << 'HTMLEOF'
{% extends "admin/base.html" %}
{% block content %}
<div class="page-header">
  <h1 class="page-title">{{ title }}</h1>
  <a href="{{ url_for('admin_projects') }}" class="btn-admin-outline"><i class="fas fa-arrow-left"></i> Back</a>
</div>
<form method="POST" enctype="multipart/form-data" class="admin-form">
  {{ form.hidden_tag() }}
  <div class="form-grid">
    <div class="form-group">{{ form.name.label }}<br>{{ form.name(class='form-control') }}</div>
    <div class="form-group">{{ form.category.label }}<br>{{ form.category(class='form-control') }}</div>
  </div>
  <div class="form-group">{{ form.description.label }}<br>{{ form.description(class='form-control', rows=3) }}</div>
  <div class="form-group">{{ form.long_description.label }}<br>{{ form.long_description(class='form-control', rows=6) }}</div>
  <div class="form-group">
    {{ form.image.label }}<br>{{ form.image(class='form-control') }}
    {% if project and project.image %}<img src="{{ url_for('static', filename='uploads/' + project.image) }}" class="preview-img" style="margin-top:8px;max-height:150px;border-radius:8px">{% endif %}
  </div>
  <div class="form-grid">
    <div class="form-group">{{ form.live_url.label }}<br>{{ form.live_url(class='form-control', placeholder='https://...') }}</div>
    <div class="form-group">{{ form.github_url.label }}<br>{{ form.github_url(class='form-control', placeholder='https://github.com/...') }}</div>
  </div>
  <div class="form-group">{{ form.tech_stack.label }}<br>{{ form.tech_stack(class='form-control', placeholder='Python, Flask, React, MySQL') }}</div>
  <div class="form-grid">
    <div class="form-group">{{ form.order.label }}<br>{{ form.order(class='form-control', placeholder='0') }}</div>
    <div class="form-check">{{ form.featured() }} {{ form.featured.label }}</div>
  </div>
  <button type="submit" class="btn-admin-primary">Save Project</button>
</form>
{% endblock %}
HTMLEOF

    # ADMIN SKILLS
    cat > ${APP_DIR}/templates/admin/skills.html << 'HTMLEOF'
{% extends "admin/base.html" %}
{% block content %}
<div class="page-header">
  <h1 class="page-title">Skills</h1>
  <a href="{{ url_for('admin_skill_new') }}" class="btn-admin-primary"><i class="fas fa-plus"></i> Add Skill</a>
</div>
<table class="admin-table">
  <thead><tr><th>Name</th><th>Category</th><th>Level</th><th>Icon</th><th>Order</th><th>Actions</th></tr></thead>
  <tbody>
    {% for s in skills %}
    <tr>
      <td><strong>{{ s.name }}</strong></td>
      <td>{{ s.category }}</td>
      <td><div style="background:#333;border-radius:4px;height:8px;width:100px"><div style="background:#00ff88;height:8px;border-radius:4px;width:{{ s.level }}%"></div></div> {{ s.level }}%</td>
      <td>{% if s.icon %}<i class="{{ s.icon }}"></i>{% else %}—{% endif %}</td>
      <td>{{ s.order }}</td>
      <td class="actions">
        <a href="{{ url_for('admin_skill_edit', id=s.id) }}" class="action-edit"><i class="fas fa-edit"></i></a>
        <form method="POST" action="{{ url_for('admin_skill_delete', id=s.id) }}" style="display:inline" onsubmit="return confirm('Delete?')">
          <button type="submit" class="action-delete"><i class="fas fa-trash"></i></button>
        </form>
      </td>
    </tr>
    {% else %}<tr><td colspan="6" class="empty-state">No skills yet.</td></tr>
    {% endfor %}
  </tbody>
</table>
{% endblock %}
HTMLEOF

    cat > ${APP_DIR}/templates/admin/skill_form.html << 'HTMLEOF'
{% extends "admin/base.html" %}
{% block content %}
<div class="page-header"><h1 class="page-title">{{ title }}</h1><a href="{{ url_for('admin_skills') }}" class="btn-admin-outline"><i class="fas fa-arrow-left"></i> Back</a></div>
<form method="POST" class="admin-form">
  {{ form.hidden_tag() }}
  <div class="form-grid">
    <div class="form-group">{{ form.name.label }}<br>{{ form.name(class='form-control') }}</div>
    <div class="form-group">{{ form.category.label }}<br>{{ form.category(class='form-control') }}</div>
  </div>
  <div class="form-grid">
    <div class="form-group">{{ form.level.label }}<br>{{ form.level(class='form-control', placeholder='0-100') }}</div>
    <div class="form-group">{{ form.order.label }}<br>{{ form.order(class='form-control', placeholder='0') }}</div>
  </div>
  <div class="form-group">{{ form.icon.label }}<br>{{ form.icon(class='form-control', placeholder='devicon-python-plain') }}<small>From <a href="https://devicon.dev" target="_blank">devicon.dev</a></small></div>
  <button type="submit" class="btn-admin-primary">Save Skill</button>
</form>
{% endblock %}
HTMLEOF

    cat > ${APP_DIR}/templates/admin/experience.html << 'HTMLEOF'
{% extends "admin/base.html" %}
{% block content %}
<div class="page-header"><h1 class="page-title">Experience</h1><a href="{{ url_for('admin_experience_new') }}" class="btn-admin-primary"><i class="fas fa-plus"></i> Add Experience</a></div>
<table class="admin-table">
  <thead><tr><th>Title</th><th>Company</th><th>Period</th><th>Order</th><th>Actions</th></tr></thead>
  <tbody>
    {% for e in experiences %}
    <tr>
      <td><strong>{{ e.title }}</strong></td>
      <td>{{ e.company }}</td>
      <td>{{ e.start_date }} — {{ e.end_date }}</td>
      <td>{{ e.order }}</td>
      <td class="actions">
        <a href="{{ url_for('admin_experience_edit', id=e.id) }}" class="action-edit"><i class="fas fa-edit"></i></a>
        <form method="POST" action="{{ url_for('admin_experience_delete', id=e.id) }}" style="display:inline" onsubmit="return confirm('Delete?')">
          <button type="submit" class="action-delete"><i class="fas fa-trash"></i></button>
        </form>
      </td>
    </tr>
    {% else %}<tr><td colspan="5" class="empty-state">No experience entries yet.</td></tr>
    {% endfor %}
  </tbody>
</table>
{% endblock %}
HTMLEOF

    cat > ${APP_DIR}/templates/admin/experience_form.html << 'HTMLEOF'
{% extends "admin/base.html" %}
{% block content %}
<div class="page-header"><h1 class="page-title">{{ title }}</h1><a href="{{ url_for('admin_experience') }}" class="btn-admin-outline"><i class="fas fa-arrow-left"></i> Back</a></div>
<form method="POST" class="admin-form">
  {{ form.hidden_tag() }}
  <div class="form-grid">
    <div class="form-group">{{ form.title.label }}<br>{{ form.title(class='form-control') }}</div>
    <div class="form-group">{{ form.company.label }}<br>{{ form.company(class='form-control') }}</div>
  </div>
  <div class="form-grid">
    <div class="form-group">{{ form.location.label }}<br>{{ form.location(class='form-control') }}</div>
    <div class="form-group">{{ form.order.label }}<br>{{ form.order(class='form-control') }}</div>
  </div>
  <div class="form-grid">
    <div class="form-group">{{ form.start_date.label }}<br>{{ form.start_date(class='form-control', placeholder='Jan 2022') }}</div>
    <div class="form-group">{{ form.end_date.label }}<br>{{ form.end_date(class='form-control', placeholder='Present') }}</div>
  </div>
  <div class="form-group">{{ form.description.label }}<br>{{ form.description(class='form-control', rows=5) }}</div>
  <button type="submit" class="btn-admin-primary">Save</button>
</form>
{% endblock %}
HTMLEOF

    cat > ${APP_DIR}/templates/admin/testimonials.html << 'HTMLEOF'
{% extends "admin/base.html" %}
{% block content %}
<div class="page-header"><h1 class="page-title">Testimonials</h1><a href="{{ url_for('admin_testimonial_new') }}" class="btn-admin-primary"><i class="fas fa-plus"></i> Add Testimonial</a></div>
<table class="admin-table">
  <thead><tr><th>Name</th><th>Role / Company</th><th>Active</th><th>Order</th><th>Actions</th></tr></thead>
  <tbody>
    {% for t in testimonials %}
    <tr>
      <td><strong>{{ t.name }}</strong></td>
      <td>{{ t.role }}{% if t.company %} · {{ t.company }}{% endif %}</td>
      <td>{% if t.active %}<span class="badge-yes">Yes</span>{% else %}No{% endif %}</td>
      <td>{{ t.order }}</td>
      <td class="actions">
        <a href="{{ url_for('admin_testimonial_edit', id=t.id) }}" class="action-edit"><i class="fas fa-edit"></i></a>
        <form method="POST" action="{{ url_for('admin_testimonial_delete', id=t.id) }}" style="display:inline" onsubmit="return confirm('Delete?')">
          <button type="submit" class="action-delete"><i class="fas fa-trash"></i></button>
        </form>
      </td>
    </tr>
    {% else %}<tr><td colspan="5" class="empty-state">No testimonials yet.</td></tr>
    {% endfor %}
  </tbody>
</table>
{% endblock %}
HTMLEOF

    cat > ${APP_DIR}/templates/admin/testimonial_form.html << 'HTMLEOF'
{% extends "admin/base.html" %}
{% block content %}
<div class="page-header"><h1 class="page-title">{{ title }}</h1><a href="{{ url_for('admin_testimonials') }}" class="btn-admin-outline"><i class="fas fa-arrow-left"></i> Back</a></div>
<form method="POST" enctype="multipart/form-data" class="admin-form">
  {{ form.hidden_tag() }}
  <div class="form-grid">
    <div class="form-group">{{ form.name.label }}<br>{{ form.name(class='form-control') }}</div>
    <div class="form-group">{{ form.role.label }}<br>{{ form.role(class='form-control') }}</div>
  </div>
  <div class="form-grid">
    <div class="form-group">{{ form.company.label }}<br>{{ form.company(class='form-control') }}</div>
    <div class="form-group">{{ form.order.label }}<br>{{ form.order(class='form-control') }}</div>
  </div>
  <div class="form-group">{{ form.content.label }}<br>{{ form.content(class='form-control', rows=5) }}</div>
  <div class="form-group">{{ form.avatar.label }}<br>{{ form.avatar(class='form-control') }}
    {% if item and item.avatar %}<img src="{{ url_for('static', filename='uploads/' + item.avatar) }}" style="margin-top:8px;max-height:80px;border-radius:50%">{% endif %}
  </div>
  <div class="form-check">{{ form.active() }} {{ form.active.label }}</div>
  <button type="submit" class="btn-admin-primary">Save</button>
</form>
{% endblock %}
HTMLEOF

    cat > ${APP_DIR}/templates/admin/messages.html << 'HTMLEOF'
{% extends "admin/base.html" %}
{% block content %}
<h1 class="page-title">Messages</h1>
<table class="admin-table">
  <thead><tr><th>Name</th><th>Email</th><th>Subject</th><th>Message</th><th>Date</th><th>Actions</th></tr></thead>
  <tbody>
    {% for m in messages %}
    <tr {% if not m.read %}class="unread"{% endif %}>
      <td><strong>{{ m.name }}</strong></td>
      <td><a href="mailto:{{ m.email }}">{{ m.email }}</a></td>
      <td>{{ m.subject or '—' }}</td>
      <td>{{ m.message[:80] }}{% if m.message|length > 80 %}...{% endif %}</td>
      <td>{{ m.created_at.strftime('%Y-%m-%d %H:%M') }}</td>
      <td class="actions">
        <form method="POST" action="{{ url_for('admin_message_delete', id=m.id) }}" style="display:inline" onsubmit="return confirm('Delete?')">
          <button type="submit" class="action-delete"><i class="fas fa-trash"></i></button>
        </form>
      </td>
    </tr>
    {% else %}<tr><td colspan="6" class="empty-state">No messages yet.</td></tr>
    {% endfor %}
  </tbody>
</table>
{% endblock %}
HTMLEOF

    cat > ${APP_DIR}/templates/admin/settings.html << 'HTMLEOF'
{% extends "admin/base.html" %}
{% block content %}
<h1 class="page-title">Site Settings</h1>
<form method="POST" enctype="multipart/form-data" class="admin-form">
  {{ form.hidden_tag() }}
  <div class="admin-section"><h3>Hero Section</h3>
    <div class="form-grid">
      <div class="form-group">{{ form.hero_name.label }}<br>{{ form.hero_name(class='form-control') }}</div>
      <div class="form-group">{{ form.hero_tagline.label }}<br>{{ form.hero_tagline(class='form-control') }}</div>
    </div>
    <div class="form-group">{{ form.hero_bio.label }}<br>{{ form.hero_bio(class='form-control', rows=4) }}</div>
    <div class="form-group">{{ form.hero_image.label }}<br>{{ form.hero_image(class='form-control') }}
      {% if settings.get('hero_image') %}<img src="{{ url_for('static', filename='uploads/' + settings.get('hero_image')) }}" style="margin-top:8px;max-height:120px;border-radius:12px">{% endif %}
    </div>
  </div>
  <div class="admin-section"><h3>About</h3>
    <div class="form-group">{{ form.about_text.label }}<br>{{ form.about_text(class='form-control', rows=5) }}</div>
    <div class="form-group">{{ form.cv_url.label }}<br>{{ form.cv_url(class='form-control') }}</div>
  </div>
  <div class="admin-section"><h3>Contact Info</h3>
    <div class="form-grid">
      <div class="form-group">{{ form.email.label }}<br>{{ form.email(class='form-control') }}</div>
      <div class="form-group">{{ form.phone.label }}<br>{{ form.phone(class='form-control') }}</div>
    </div>
    <div class="form-group">{{ form.location.label }}<br>{{ form.location(class='form-control') }}</div>
  </div>
  <div class="admin-section"><h3>Social Links</h3>
    <div class="form-grid">
      <div class="form-group">{{ form.github_url.label }}<br>{{ form.github_url(class='form-control') }}</div>
      <div class="form-group">{{ form.linkedin_url.label }}<br>{{ form.linkedin_url(class='form-control') }}</div>
    </div>
    <div class="form-grid">
      <div class="form-group">{{ form.twitter_url.label }}<br>{{ form.twitter_url(class='form-control') }}</div>
      <div class="form-group">{{ form.instagram_url.label }}<br>{{ form.instagram_url(class='form-control') }}</div>
    </div>
  </div>
  <div class="admin-section"><h3>Footer</h3>
    <div class="form-group">{{ form.footer_text.label }}<br>{{ form.footer_text(class='form-control', rows=3) }}</div>
    <div class="form-group">{{ form.footer_copyright.label }}<br>{{ form.footer_copyright(class='form-control') }}</div>
  </div>
  <div class="admin-section"><h3>SEO</h3>
    <div class="form-group">{{ form.meta_description.label }}<br>{{ form.meta_description(class='form-control', rows=3) }}</div>
  </div>
  <button type="submit" class="btn-admin-primary">Save Settings</button>
</form>
{% endblock %}
HTMLEOF

    log_success "Templates created"
}

# ============================================================
# STEP 6: Create CSS & JS
# ============================================================
create_static() {
    log_step "Creating static assets (CSS & JS)"

    cat > ${APP_DIR}/static/css/style.css << 'CSSEOF'
/* ============================================================
   RIZZDEVS PORTFOLIO — MAIN STYLESHEET
   Dark cyberpunk-minimal aesthetic
   ============================================================ */

:root {
  --bg: #080c12;
  --bg-2: #0d1320;
  --bg-3: #111927;
  --border: rgba(255,255,255,.07);
  --text: #e2e8f0;
  --text-muted: #64748b;
  --accent: #00ff88;
  --accent-2: #00d4ff;
  --accent-3: #ff006e;
  --accent-dim: rgba(0,255,136,.08);
  --card: #0f1923;
  --card-hover: #141f2e;
  --radius: 12px;
  --radius-lg: 20px;
  --shadow: 0 20px 60px rgba(0,0,0,.5);
  --font-display: 'Syne', sans-serif;
  --font-mono: 'Space Mono', monospace;
  --transition: all .3s cubic-bezier(.4,0,.2,1);
}

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

html { scroll-behavior: smooth; font-size: 16px; }

body {
  background: var(--bg);
  color: var(--text);
  font-family: var(--font-display);
  line-height: 1.7;
  overflow-x: hidden;
}

.noise-overlay {
  position: fixed; inset: 0; z-index: 1000; pointer-events: none;
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='300' height='300'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.75' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='300' height='300' filter='url(%23n)' opacity='0.04'/%3E%3C/svg%3E");
  opacity: .6;
}

a { color: inherit; text-decoration: none; }
img { max-width: 100%; display: block; }
.container { max-width: 1200px; margin: 0 auto; padding: 0 1.5rem; }
.accent { color: var(--accent); }

/* ---- NAVBAR ---- */
.navbar {
  position: fixed; top: 0; left: 0; right: 0; z-index: 100;
  padding: 1rem 0; transition: var(--transition);
}
.navbar.scrolled {
  background: rgba(8,12,18,.95);
  backdrop-filter: blur(20px);
  border-bottom: 1px solid var(--border);
  padding: .75rem 0;
}
.nav-inner { display: flex; align-items: center; justify-content: space-between; }
.nav-logo {
  font-family: var(--font-mono);
  font-size: 1.2rem; font-weight: 700;
}
.logo-bracket { color: var(--text-muted); }
.logo-accent { color: var(--accent); }
.nav-links {
  display: flex; align-items: center; gap: 2rem; list-style: none;
}
.nav-links a {
  font-family: var(--font-mono); font-size: .875rem;
  color: var(--text-muted); transition: var(--transition);
  position: relative;
}
.nav-links a:not(.btn-nav):hover { color: var(--text); }
.nav-links a:not(.btn-nav)::after {
  content: ''; position: absolute; bottom: -2px; left: 0; width: 0; height: 1px;
  background: var(--accent); transition: var(--transition);
}
.nav-links a:not(.btn-nav):hover::after { width: 100%; }
.btn-nav {
  border: 1px solid var(--accent); color: var(--accent) !important;
  padding: .5rem 1rem; border-radius: 6px;
}
.btn-nav:hover { background: var(--accent); color: var(--bg) !important; }
.hamburger { display: none; background: none; border: none; cursor: pointer; flex-direction: column; gap: 5px; padding: 4px; }
.hamburger span { width: 24px; height: 2px; background: var(--text); display: block; transition: var(--transition); }

.mobile-menu {
  display: none; position: fixed; top: 0; right: -100%; width: min(80vw,320px); height: 100vh;
  background: var(--bg-2); border-left: 1px solid var(--border);
  z-index: 99; padding: 5rem 2rem 2rem; transition: right .3s ease;
}
.mobile-menu.open { right: 0; display: block; }
.mobile-menu ul { list-style: none; display: flex; flex-direction: column; gap: 1.5rem; }
.mobile-menu a { font-family: var(--font-mono); font-size: 1.1rem; color: var(--text-muted); }
.mobile-menu a:hover { color: var(--accent); }

/* ---- HERO ---- */
.hero {
  min-height: 100vh; display: flex; align-items: center;
  position: relative; overflow: hidden; padding: 8rem 0 4rem;
}
.hero-bg { position: absolute; inset: 0; z-index: 0; }
.hero-grid {
  position: absolute; inset: 0;
  background-image:
    linear-gradient(rgba(0,255,136,.04) 1px, transparent 1px),
    linear-gradient(90deg, rgba(0,255,136,.04) 1px, transparent 1px);
  background-size: 50px 50px;
}
.hero-glow {
  position: absolute; top: -200px; right: -200px; width: 800px; height: 800px;
  background: radial-gradient(circle, rgba(0,255,136,.06) 0%, transparent 70%);
}
.hero-inner {
  position: relative; z-index: 1;
  display: grid; grid-template-columns: 1fr 1fr; gap: 4rem; align-items: center;
}
.hero-badge {
  display: inline-flex; align-items: center; gap: .5rem;
  border: 1px solid rgba(0,255,136,.3); background: rgba(0,255,136,.05);
  color: var(--accent); font-family: var(--font-mono); font-size: .8rem;
  padding: .4rem 1rem; border-radius: 100px; margin-bottom: 1.5rem;
}
.badge-dot {
  width: 8px; height: 8px; border-radius: 50%;
  background: var(--accent); animation: pulse 2s infinite;
}
@keyframes pulse { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:.5;transform:scale(.8)} }
.hero-title { font-size: clamp(2.5rem,5vw,4rem); font-weight: 800; line-height: 1.1; margin-bottom: 1rem; }
.greeting { display: block; font-size: .6em; color: var(--text-muted); font-weight: 400; }
.name { display: block; background: linear-gradient(135deg, #fff 0%, var(--accent) 50%, var(--accent-2) 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; }
.hero-tagline { font-size: 1.1rem; color: var(--accent); font-family: var(--font-mono); margin-bottom: .75rem; }
.hero-bio { color: var(--text-muted); max-width: 480px; margin-bottom: 2rem; }
.hero-cta { display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 3rem; }
.hero-stats { display: flex; align-items: center; gap: 2rem; }
.stat { text-align: center; }
.stat-num { display: block; font-family: var(--font-mono); font-size: 1.8rem; font-weight: 700; color: var(--accent); }
.stat-label { font-size: .75rem; color: var(--text-muted); font-family: var(--font-mono); text-transform: uppercase; letter-spacing: .1em; }
.stat-divider { width: 1px; height: 40px; background: var(--border); }

.hero-visual { position: relative; display: flex; justify-content: center; }
.hero-image-wrap { position: relative; width: 300px; height: 300px; }
.hero-img { width: 100%; height: 100%; object-fit: cover; border-radius: 50%; position: relative; z-index: 2; border: 3px solid rgba(0,255,136,.3); }
.hero-placeholder {
  width: 100%; height: 100%; border-radius: 50%;
  background: var(--bg-3); display: flex; align-items: center; justify-content: center;
  font-size: 5rem; color: var(--accent); position: relative; z-index: 2;
  border: 3px solid rgba(0,255,136,.3);
}
.hero-ring {
  position: absolute; border-radius: 50%; border: 1px solid rgba(0,255,136,.1);
  animation: rotate 20s linear infinite;
}
.ring-1 { inset: -20px; animation-duration: 20s; }
.ring-2 { inset: -40px; animation-duration: 30s; animation-direction: reverse; }
.ring-3 { inset: -60px; animation-duration: 40s; }
@keyframes rotate { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }

.float-card {
  position: absolute; background: var(--card); border: 1px solid var(--border);
  padding: .6rem 1rem; border-radius: 10px; font-size: .8rem; font-family: var(--font-mono);
  display: flex; align-items: center; gap: .5rem; z-index: 3;
  backdrop-filter: blur(10px); white-space: nowrap;
  animation: float 4s ease-in-out infinite;
}
.float-card i { color: var(--accent); }
.card-1 { top: 0; right: -20px; animation-delay: 0s; }
.card-2 { bottom: 20%; left: -30px; animation-delay: 1.5s; }
.card-3 { bottom: 0; right: -10px; animation-delay: 3s; }
@keyframes float { 0%,100%{transform:translateY(0)} 50%{transform:translateY(-12px)} }

.scroll-indicator {
  position: absolute; bottom: 2rem; left: 50%; transform: translateX(-50%);
  display: flex; flex-direction: column; align-items: center; gap: .5rem;
  color: var(--text-muted); font-size: .75rem; font-family: var(--font-mono); z-index: 1;
}
.scroll-mouse {
  width: 24px; height: 38px; border: 2px solid var(--text-muted);
  border-radius: 12px; display: flex; justify-content: center; padding-top: 6px;
}
.scroll-dot {
  width: 4px; height: 8px; background: var(--accent); border-radius: 2px;
  animation: scroll 2s ease infinite;
}
@keyframes scroll { 0%{transform:translateY(0);opacity:1} 100%{transform:translateY(14px);opacity:0} }

/* ---- BUTTONS ---- */
.btn {
  display: inline-flex; align-items: center; gap: .5rem;
  padding: .75rem 1.75rem; border-radius: var(--radius); font-weight: 600;
  font-family: var(--font-mono); font-size: .9rem; border: none; cursor: pointer;
  transition: var(--transition); text-decoration: none; white-space: nowrap;
}
.btn-primary {
  background: var(--accent); color: var(--bg);
}
.btn-primary:hover { background: #00e67a; transform: translateY(-2px); box-shadow: 0 8px 30px rgba(0,255,136,.3); }
.btn-outline {
  background: transparent; color: var(--accent); border: 1px solid rgba(0,255,136,.4);
}
.btn-outline:hover { background: rgba(0,255,136,.08); transform: translateY(-2px); }
.btn-full { width: 100%; justify-content: center; }

/* ---- SECTIONS ---- */
.section { padding: 6rem 0; }
.section-dark { background: var(--bg-2); }
.section-header { margin-bottom: 3rem; }
.section-tag { font-family: var(--font-mono); font-size: .8rem; color: var(--accent); letter-spacing: .2em; }
.section-title { font-size: clamp(2rem,4vw,3rem); font-weight: 800; margin-top: .5rem; }
.section-sub { color: var(--text-muted); margin-top: .75rem; }
.section-footer { text-align: center; margin-top: 3rem; }

/* ---- ABOUT ---- */
.about-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 4rem; align-items: start; }
.about-text p { color: var(--text-muted); margin-bottom: 1.5rem; line-height: 1.8; }
.about-info { display: flex; flex-direction: column; gap: .75rem; margin-bottom: 1.5rem; }
.info-item { display: flex; align-items: center; gap: .75rem; font-family: var(--font-mono); font-size: .875rem; color: var(--text-muted); }
.info-item i { color: var(--accent); width: 16px; }

.code-block {
  background: #040810; border: 1px solid var(--border);
  border-radius: var(--radius-lg); overflow: hidden; font-family: var(--font-mono); font-size: .85rem;
}
.code-header {
  background: var(--bg-3); padding: .75rem 1rem;
  display: flex; align-items: center; gap: .5rem; border-bottom: 1px solid var(--border);
}
.dot { width: 12px; height: 12px; border-radius: 50%; }
.dot.red { background: #ff5f57; }
.dot.yellow { background: #febc2e; }
.dot.green { background: #28c840; }
.code-filename { margin-left: auto; color: var(--text-muted); font-size: .8rem; }
.code-content { padding: 1.5rem; overflow-x: auto; }
code { white-space: pre; }
.c-kw { color: #ff79c6; }
.c-cl { color: #8be9fd; }
.c-fn { color: #50fa7b; }
.c-str { color: #f1fa8c; }

/* ---- FEATURED ---- */
.featured-grid {
  display: grid; grid-template-columns: repeat(3, 1fr); gap: 1.5rem;
}
.featured-main {
  grid-column: 1 / 3;
}
.featured-card {
  background: var(--card); border: 1px solid var(--border);
  border-radius: var(--radius-lg); overflow: hidden;
  transition: var(--transition);
  display: grid;
}
.featured-main {
  grid-template-columns: 1.2fr 1fr;
}
.featured-card:hover { border-color: rgba(0,255,136,.2); transform: translateY(-4px); box-shadow: 0 20px 60px rgba(0,0,0,.4); }
.feat-image { position: relative; overflow: hidden; aspect-ratio: 16/10; }
.featured-main .feat-image { aspect-ratio: auto; }
.feat-image img { width: 100%; height: 100%; object-fit: cover; transition: transform .5s ease; }
.featured-card:hover .feat-image img { transform: scale(1.05); }
.feat-placeholder { width: 100%; height: 100%; background: var(--bg-3); display: flex; align-items: center; justify-content: center; font-size: 3rem; color: var(--text-muted); }
.feat-overlay {
  position: absolute; inset: 0; background: rgba(0,0,0,.6);
  display: flex; align-items: center; justify-content: center;
  opacity: 0; transition: var(--transition);
}
.featured-card:hover .feat-overlay { opacity: 1; }
.feat-links { display: flex; gap: 1rem; }
.feat-link {
  width: 44px; height: 44px; border-radius: 50%;
  background: rgba(255,255,255,.1); backdrop-filter: blur(10px);
  display: flex; align-items: center; justify-content: center;
  color: #fff; font-size: 1.1rem;
  transition: var(--transition);
}
.feat-link:hover { background: var(--accent); color: var(--bg); }
.feat-content { padding: 1.5rem; }
.feat-cat { font-family: var(--font-mono); font-size: .75rem; color: var(--accent); letter-spacing: .1em; text-transform: uppercase; }
.feat-content h3 { font-size: 1.2rem; margin: .5rem 0; }
.feat-content h3 a:hover { color: var(--accent); }
.feat-content p { color: var(--text-muted); font-size: .9rem; margin-bottom: 1rem; }
.feat-tech { display: flex; flex-wrap: wrap; gap: .5rem; }
.feat-tech span { font-family: var(--font-mono); font-size: .75rem; background: var(--accent-dim); color: var(--accent); padding: .25rem .625rem; border-radius: 4px; }

/* ---- PROJECTS GRID ---- */
.projects-grid { display: grid; grid-template-columns: repeat(auto-fill,minmax(320px,1fr)); gap: 1.5rem; }
.project-card {
  background: var(--card); border: 1px solid var(--border);
  border-radius: var(--radius-lg); overflow: hidden; transition: var(--transition);
}
.project-card:hover { border-color: rgba(0,255,136,.2); transform: translateY(-4px); box-shadow: var(--shadow); }
.proj-image { position: relative; aspect-ratio: 16/9; overflow: hidden; }
.proj-image img { width: 100%; height: 100%; object-fit: cover; transition: transform .5s ease; }
.project-card:hover .proj-image img { transform: scale(1.05); }
.proj-placeholder { width: 100%; height: 100%; background: var(--bg-3); display: flex; align-items: center; justify-content: center; font-size: 2.5rem; color: var(--text-muted); }
.proj-badge {
  position: absolute; top: .75rem; left: .75rem;
  background: var(--accent); color: var(--bg); font-size: .7rem; font-weight: 700;
  font-family: var(--font-mono); padding: .25rem .6rem; border-radius: 4px;
}
.proj-content { padding: 1.25rem; }
.proj-cat { font-family: var(--font-mono); font-size: .75rem; color: var(--accent); }
.proj-content h3 { margin: .4rem 0 .5rem; font-size: 1.1rem; }
.proj-content h3 a:hover { color: var(--accent); }
.proj-content p { color: var(--text-muted); font-size: .875rem; margin-bottom: 1rem; line-height: 1.6; }
.proj-tech { display: flex; flex-wrap: wrap; gap: .4rem; margin-bottom: 1rem; }
.proj-tech span { font-family: var(--font-mono); font-size: .7rem; background: var(--accent-dim); color: var(--accent); padding: .2rem .5rem; border-radius: 4px; }
.proj-links { display: flex; align-items: center; gap: .75rem; }
.proj-link-main {
  font-family: var(--font-mono); font-size: .8rem; color: var(--accent);
  display: flex; align-items: center; gap: .4rem;
}
.proj-link-main:hover { gap: .75rem; }
.proj-link-icon {
  width: 32px; height: 32px; border-radius: 8px;
  background: var(--bg-3); display: flex; align-items: center; justify-content: center;
  font-size: .9rem; color: var(--text-muted); transition: var(--transition);
}
.proj-link-icon:hover { background: var(--accent-dim); color: var(--accent); }

/* ---- SKILLS ---- */
.skill-group { margin-bottom: 2.5rem; }
.skill-cat-title { font-family: var(--font-mono); font-size: .875rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: .15em; margin-bottom: 1.5rem; padding-bottom: .5rem; border-bottom: 1px solid var(--border); }
.skills-grid { display: grid; grid-template-columns: repeat(auto-fill,minmax(240px,1fr)); gap: 1rem; }
.skill-card {
  background: var(--card); border: 1px solid var(--border);
  border-radius: var(--radius); padding: 1.25rem;
  display: flex; flex-direction: column; gap: .75rem;
  transition: var(--transition);
}
.skill-card:hover { border-color: rgba(0,255,136,.2); background: var(--card-hover); }
.skill-icon { font-size: 2rem; color: var(--accent); }
.skill-letter {
  width: 40px; height: 40px; border-radius: 10px;
  background: var(--accent-dim); color: var(--accent);
  display: flex; align-items: center; justify-content: center;
  font-weight: 700; font-size: 1.2rem;
}
.skill-name { font-weight: 600; font-size: .9rem; }
.skill-bar-wrap { display: flex; align-items: center; gap: .75rem; }
.skill-bar { flex: 1; height: 4px; background: var(--bg-3); border-radius: 2px; overflow: hidden; }
.skill-fill { height: 100%; background: linear-gradient(90deg, var(--accent), var(--accent-2)); border-radius: 2px; transition: width 1.2s cubic-bezier(.4,0,.2,1); }
.skill-pct { font-family: var(--font-mono); font-size: .75rem; color: var(--accent); width: 36px; text-align: right; }

/* ---- TIMELINE ---- */
.timeline { position: relative; padding-left: 2rem; }
.timeline::before { content: ''; position: absolute; left: 8px; top: 0; bottom: 0; width: 1px; background: var(--border); }
.timeline-item { position: relative; margin-bottom: 2.5rem; }
.timeline-dot {
  position: absolute; left: -2rem; top: 4px;
  width: 16px; height: 16px; border-radius: 50%;
  background: var(--bg); border: 2px solid var(--accent);
  box-shadow: 0 0 12px rgba(0,255,136,.3);
}
.timeline-content {
  background: var(--card); border: 1px solid var(--border);
  border-radius: var(--radius); padding: 1.5rem;
  transition: var(--transition);
}
.timeline-content:hover { border-color: rgba(0,255,136,.2); }
.timeline-header { display: flex; justify-content: space-between; align-items: flex-start; gap: 1rem; margin-bottom: .75rem; flex-wrap: wrap; }
.timeline-header h3 { font-size: 1.1rem; }
.timeline-company { font-size: .875rem; color: var(--text-muted); margin-top: .25rem; }
.timeline-company i { color: var(--accent); margin-right: .25rem; }
.timeline-date { font-family: var(--font-mono); font-size: .8rem; color: var(--accent); white-space: nowrap; }
.timeline-desc { color: var(--text-muted); font-size: .9rem; line-height: 1.7; }

/* ---- TESTIMONIALS ---- */
.testimonial-grid { display: grid; grid-template-columns: repeat(auto-fill,minmax(300px,1fr)); gap: 1.5rem; }
.testimonial-card {
  background: var(--card); border: 1px solid var(--border);
  border-radius: var(--radius-lg); padding: 1.75rem;
  transition: var(--transition);
}
.testimonial-card:hover { border-color: rgba(0,255,136,.2); }
.testimonial-stars { color: #fbbf24; font-size: 1rem; margin-bottom: 1rem; }
.testimonial-text { color: var(--text-muted); font-style: italic; line-height: 1.8; margin-bottom: 1.5rem; }
.testimonial-author { display: flex; align-items: center; gap: 1rem; }
.testimonial-author img { width: 48px; height: 48px; border-radius: 50%; object-fit: cover; }
.testimonial-avatar-placeholder {
  width: 48px; height: 48px; border-radius: 50%;
  background: var(--accent-dim); color: var(--accent);
  display: flex; align-items: center; justify-content: center;
  font-weight: 700; flex-shrink: 0;
}
.testimonial-author strong { display: block; font-size: .9rem; }
.testimonial-author span { font-size: .8rem; color: var(--text-muted); font-family: var(--font-mono); }

/* ---- CONTACT ---- */
.contact-grid { display: grid; grid-template-columns: 1fr 1.5fr; gap: 4rem; }
.contact-item { display: flex; align-items: flex-start; gap: 1rem; margin-bottom: 1.5rem; }
.contact-icon {
  width: 48px; height: 48px; border-radius: 12px;
  background: var(--accent-dim); color: var(--accent);
  display: flex; align-items: center; justify-content: center;
  font-size: 1.1rem; flex-shrink: 0;
}
.contact-item h4 { font-size: .875rem; color: var(--text-muted); margin-bottom: .2rem; font-family: var(--font-mono); }
.contact-item a, .contact-item p { color: var(--text); font-size: .9rem; }
.contact-item a:hover { color: var(--accent); }
.contact-social { display: flex; gap: .75rem; margin-top: 2rem; }
.social-btn {
  display: flex; align-items: center; gap: .5rem;
  border: 1px solid var(--border); background: var(--card);
  padding: .6rem 1.2rem; border-radius: 8px;
  font-family: var(--font-mono); font-size: .8rem; color: var(--text-muted);
  transition: var(--transition);
}
.social-btn:hover { border-color: var(--accent); color: var(--accent); }

.contact-form { display: flex; flex-direction: column; gap: 1rem; }
.form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
.form-group { display: flex; flex-direction: column; gap: .5rem; }
.form-group label { font-size: .85rem; color: var(--text-muted); font-family: var(--font-mono); }
.form-group input, .form-group textarea {
  background: var(--bg-2); border: 1px solid var(--border);
  border-radius: var(--radius); padding: .875rem 1rem;
  color: var(--text); font-family: var(--font-display); font-size: .9rem;
  transition: var(--transition); resize: vertical;
}
.form-group input:focus, .form-group textarea:focus {
  outline: none; border-color: rgba(0,255,136,.4);
  box-shadow: 0 0 0 3px rgba(0,255,136,.08);
}
.form-group input::placeholder, .form-group textarea::placeholder { color: var(--text-muted); }

/* ---- FOOTER ---- */
.footer { background: var(--bg-2); border-top: 1px solid var(--border); padding: 4rem 0 2rem; }
.footer-grid { display: grid; grid-template-columns: 1.5fr 1fr 1.2fr; gap: 3rem; margin-bottom: 3rem; }
.footer-brand .nav-logo { display: inline-block; margin-bottom: 1rem; }
.footer-brand p { color: var(--text-muted); font-size: .9rem; margin-bottom: 1.5rem; }
.social-links { display: flex; gap: .75rem; }
.social-links a {
  width: 38px; height: 38px; border-radius: 8px;
  background: var(--bg-3); border: 1px solid var(--border);
  display: flex; align-items: center; justify-content: center;
  color: var(--text-muted); transition: var(--transition);
}
.social-links a:hover { background: var(--accent-dim); color: var(--accent); border-color: rgba(0,255,136,.2); }
.footer-links h4, .footer-contact h4 { font-family: var(--font-mono); font-size: .8rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: .1em; margin-bottom: 1rem; }
.footer-links ul { list-style: none; display: flex; flex-direction: column; gap: .6rem; }
.footer-links a { color: var(--text-muted); font-size: .9rem; transition: var(--transition); }
.footer-links a:hover { color: var(--accent); }
.footer-contact p { color: var(--text-muted); font-size: .875rem; margin-bottom: .5rem; display: flex; align-items: center; gap: .5rem; }
.footer-contact i { color: var(--accent); }
.footer-bottom {
  display: flex; justify-content: space-between; align-items: center;
  border-top: 1px solid var(--border); padding-top: 2rem;
  color: var(--text-muted); font-size: .85rem; font-family: var(--font-mono); flex-wrap: wrap; gap: 1rem;
}
.footer-credit .accent { color: var(--accent-3); }

/* ---- TOAST ---- */
.toast {
  position: fixed; bottom: 2rem; right: 2rem; z-index: 9999;
  background: var(--card); border: 1px solid var(--border);
  padding: 1rem 1.5rem; border-radius: var(--radius);
  font-family: var(--font-mono); font-size: .875rem;
  transform: translateY(100px); opacity: 0; transition: var(--transition);
  max-width: 350px;
}
.toast.show { transform: translateY(0); opacity: 1; }
.toast.success { border-color: var(--accent); color: var(--accent); }
.toast.error { border-color: var(--accent-3); color: var(--accent-3); }

/* ---- PROJECT DETAIL ---- */
.proj-detail-hero {
  background: var(--bg-2); padding: 8rem 0 4rem;
  border-bottom: 1px solid var(--border);
}
.back-btn {
  display: inline-flex; align-items: center; gap: .5rem;
  color: var(--text-muted); font-family: var(--font-mono); font-size: .875rem;
  margin-bottom: 1.5rem; transition: var(--transition);
}
.back-btn:hover { color: var(--accent); }
.proj-detail-hero h1 { font-size: clamp(2rem,4vw,3rem); font-weight: 800; margin: .5rem 0 1rem; }
.proj-detail-sub { color: var(--text-muted); max-width: 600px; margin-bottom: 2rem; }
.proj-detail-links { display: flex; gap: 1rem; }
.proj-detail-body { padding: 4rem 0; }
.proj-detail-image { border-radius: var(--radius-lg); overflow: hidden; margin-bottom: 3rem; border: 1px solid var(--border); }
.proj-detail-image img { width: 100%; }
.proj-detail-grid { display: grid; grid-template-columns: 1fr 300px; gap: 3rem; margin-bottom: 4rem; }
.proj-detail-main h2 { font-size: 1.5rem; margin-bottom: 1rem; }
.proj-detail-main p { color: var(--text-muted); line-height: 1.8; }
.aside-card { background: var(--card); border: 1px solid var(--border); border-radius: var(--radius); padding: 1.25rem; margin-bottom: 1rem; }
.aside-card h4 { font-family: var(--font-mono); font-size: .8rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: .1em; margin-bottom: 1rem; }
.tech-tags { display: flex; flex-wrap: wrap; gap: .5rem; }
.tech-tag { font-family: var(--font-mono); font-size: .75rem; background: var(--accent-dim); color: var(--accent); padding: .3rem .7rem; border-radius: 6px; }
.aside-link { display: flex; align-items: center; gap: .5rem; color: var(--text-muted); font-size: .9rem; padding: .5rem 0; border-bottom: 1px solid var(--border); transition: var(--transition); }
.aside-link:last-child { border-bottom: none; }
.aside-link:hover { color: var(--accent); }
.related-projects h2 { font-size: 1.5rem; margin-bottom: 2rem; }

/* ---- MISC ---- */
.page-hero { background: var(--bg-2); padding: 8rem 0 4rem; border-bottom: 1px solid var(--border); }
.page-hero h1 { font-size: clamp(2rem,4vw,3rem); font-weight: 800; }
.page-hero p { color: var(--text-muted); margin-top: .5rem; font-family: var(--font-mono); }
.filter-bar { display: flex; flex-wrap: wrap; gap: .75rem; margin-bottom: 2.5rem; }
.filter-btn {
  background: var(--card); border: 1px solid var(--border);
  color: var(--text-muted); font-family: var(--font-mono); font-size: .8rem;
  padding: .5rem 1.25rem; border-radius: 100px; cursor: pointer; transition: var(--transition);
}
.filter-btn.active, .filter-btn:hover { background: var(--accent-dim); color: var(--accent); border-color: rgba(0,255,136,.3); }
.error-page { display: flex; align-items: center; justify-content: center; min-height: 80vh; text-align: center; padding: 4rem 1rem; }
.error-code { font-size: 8rem; font-weight: 800; font-family: var(--font-mono); color: var(--accent); opacity: .3; line-height: 1; }
.error-page h1 { font-size: 2rem; margin: 1rem 0 .5rem; }
.error-page p { color: var(--text-muted); margin-bottom: 2rem; }

/* ---- ANIMATE IN ---- */
.animate-in { opacity: 0; transform: translateY(30px); animation: fadeUp .7s forwards; }
@keyframes fadeUp { to{opacity:1;transform:translateY(0)} }

/* ---- RESPONSIVE ---- */
@media (max-width: 1024px) {
  .hero-inner { grid-template-columns: 1fr; text-align: center; }
  .hero-visual { order: -1; }
  .hero-badge, .hero-cta, .hero-stats { justify-content: center; }
  .hero-bio { margin-inline: auto; }
  .featured-grid { grid-template-columns: 1fr; }
  .featured-main { grid-column: auto; grid-template-columns: 1fr; }
  .about-grid, .contact-grid, .proj-detail-grid { grid-template-columns: 1fr; }
  .footer-grid { grid-template-columns: 1fr 1fr; }
}
@media (max-width: 768px) {
  .nav-links { display: none; }
  .hamburger { display: flex; }
  .hero { padding: 6rem 0 4rem; }
  .float-card { display: none; }
  .form-row { grid-template-columns: 1fr; }
  .footer-grid { grid-template-columns: 1fr; }
  .footer-bottom { flex-direction: column; text-align: center; }
  .timeline-header { flex-direction: column; }
}
CSSEOF

    # ADMIN CSS
    cat > ${APP_DIR}/static/css/admin.css << 'CSSEOF'
:root {
  --bg: #060a10;
  --bg-2: #0a1018;
  --bg-3: #0e1620;
  --sidebar: #080d14;
  --card: #0f1923;
  --border: rgba(255,255,255,.07);
  --text: #e2e8f0;
  --text-muted: #64748b;
  --accent: #00ff88;
  --danger: #ff4757;
  --warning: #ffa502;
  --radius: 10px;
  --font-display: 'Syne', sans-serif;
  --font-mono: 'Space Mono', monospace;
  --sidebar-w: 240px;
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body.admin-body { background: var(--bg); color: var(--text); font-family: var(--font-display); min-height: 100vh; }
a { color: inherit; text-decoration: none; }
img { max-width: 100%; }

.admin-layout { display: flex; min-height: 100vh; }
.admin-sidebar {
  width: var(--sidebar-w); background: var(--sidebar);
  border-right: 1px solid var(--border);
  display: flex; flex-direction: column; position: fixed;
  left: 0; top: 0; bottom: 0; z-index: 50; overflow-y: auto;
  transition: transform .3s ease;
}
.admin-logo {
  padding: 1.5rem; font-family: var(--font-mono); font-size: 1rem; font-weight: 700;
  border-bottom: 1px solid var(--border);
}
.logo-bracket { color: var(--text-muted); }
.logo-accent { color: var(--accent); }
.admin-nav { display: flex; flex-direction: column; padding: 1rem 0; flex: 1; }
.admin-link {
  display: flex; align-items: center; gap: .75rem;
  padding: .75rem 1.5rem; color: var(--text-muted);
  font-size: .875rem; transition: all .2s; border-left: 3px solid transparent;
}
.admin-link:hover, .admin-link.active {
  color: var(--text); background: rgba(0,255,136,.05);
  border-left-color: var(--accent);
}
.admin-link i { width: 16px; text-align: center; }
.admin-sep { height: 1px; background: var(--border); margin: .5rem 1rem; }
.admin-logout:hover { color: var(--danger) !important; background: rgba(255,71,87,.05) !important; }

.admin-main { margin-left: var(--sidebar-w); flex: 1; display: flex; flex-direction: column; }
.admin-topbar {
  position: sticky; top: 0; z-index: 40;
  background: rgba(8,13,20,.95); backdrop-filter: blur(20px);
  border-bottom: 1px solid var(--border);
  padding: .875rem 1.5rem; display: flex; justify-content: space-between; align-items: center;
}
.sidebar-toggle {
  background: none; border: none; color: var(--text-muted); cursor: pointer;
  font-size: 1.1rem; padding: .25rem;
}
.admin-user { font-family: var(--font-mono); font-size: .8rem; color: var(--text-muted); display: flex; align-items: center; gap: .5rem; }
.admin-content { padding: 2rem 1.5rem; flex: 1; }
.page-title { font-size: 1.5rem; font-weight: 700; margin-bottom: 1.5rem; }
.page-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem; flex-wrap: wrap; gap: 1rem; }
.page-header .page-title { margin-bottom: 0; }

.stats-grid { display: grid; grid-template-columns: repeat(auto-fill,minmax(180px,1fr)); gap: 1rem; margin-bottom: 2rem; }
.stat-card {
  background: var(--card); border: 1px solid var(--border);
  border-radius: var(--radius); padding: 1.25rem;
  display: flex; align-items: center; gap: 1rem;
  transition: border-color .2s;
}
.stat-card:hover, .stat-highlight { border-color: rgba(0,255,136,.2); }
.stat-icon { font-size: 1.5rem; color: var(--accent); }
.stat-num { display: block; font-size: 1.75rem; font-weight: 700; font-family: var(--font-mono); color: var(--accent); }
.stat-label { font-size: .75rem; color: var(--text-muted); }

.admin-section { background: var(--card); border: 1px solid var(--border); border-radius: var(--radius); padding: 1.5rem; margin-bottom: 1.5rem; }
.admin-section-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; }
.admin-section-header h2 { font-size: 1rem; }
.admin-section-header a { font-family: var(--font-mono); font-size: .8rem; color: var(--accent); }
.admin-section h3 { font-size: .95rem; color: var(--text-muted); font-family: var(--font-mono); margin-bottom: 1.25rem; padding-bottom: .5rem; border-bottom: 1px solid var(--border); }

.admin-table { width: 100%; border-collapse: collapse; background: var(--card); border: 1px solid var(--border); border-radius: var(--radius); overflow: hidden; }
.admin-table th { background: var(--bg-3); padding: .875rem 1rem; text-align: left; font-family: var(--font-mono); font-size: .75rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: .1em; border-bottom: 1px solid var(--border); }
.admin-table td { padding: .875rem 1rem; border-bottom: 1px solid var(--border); font-size: .875rem; vertical-align: middle; }
.admin-table tr:last-child td { border-bottom: none; }
.admin-table tr:hover td { background: rgba(255,255,255,.02); }
.admin-table tr.unread td { font-weight: 600; }
.table-thumb { width: 60px; height: 40px; object-fit: cover; border-radius: 6px; }
.badge-yes { background: rgba(0,255,136,.1); color: var(--accent); font-size: .75rem; padding: .2rem .6rem; border-radius: 4px; font-family: var(--font-mono); }
.empty-state { color: var(--text-muted); text-align: center; padding: 2rem; font-size: .9rem; }
.empty-state a { color: var(--accent); }
.actions { display: flex; gap: .5rem; white-space: nowrap; }
.action-view, .action-edit { width: 32px; height: 32px; border-radius: 6px; display: flex; align-items: center; justify-content: center; font-size: .85rem; transition: all .2s; }
.action-view { background: rgba(0,212,255,.1); color: #00d4ff; }
.action-view:hover { background: rgba(0,212,255,.2); }
.action-edit { background: rgba(255,165,2,.1); color: var(--warning); }
.action-edit:hover { background: rgba(255,165,2,.2); }
.action-delete { background: rgba(255,71,87,.1); color: var(--danger); border: none; cursor: pointer; width: 32px; height: 32px; border-radius: 6px; font-size: .85rem; transition: all .2s; }
.action-delete:hover { background: rgba(255,71,87,.2); }

.btn-admin-primary {
  background: var(--accent); color: #000; border: none;
  padding: .625rem 1.25rem; border-radius: var(--radius); font-family: var(--font-mono);
  font-size: .85rem; font-weight: 700; cursor: pointer; transition: all .2s;
  display: inline-flex; align-items: center; gap: .5rem;
}
.btn-admin-primary:hover { background: #00e67a; }
.btn-admin-outline {
  background: transparent; color: var(--text-muted); border: 1px solid var(--border);
  padding: .625rem 1.25rem; border-radius: var(--radius); font-family: var(--font-mono);
  font-size: .85rem; cursor: pointer; transition: all .2s;
  display: inline-flex; align-items: center; gap: .5rem;
}
.btn-admin-outline:hover { border-color: var(--accent); color: var(--accent); }

.admin-form { max-width: 760px; }
.form-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
.form-group { display: flex; flex-direction: column; gap: .4rem; margin-bottom: .75rem; }
.form-group label { font-family: var(--font-mono); font-size: .8rem; color: var(--text-muted); }
.form-group small { color: var(--text-muted); font-size: .75rem; }
.form-group small a { color: var(--accent); }
.form-control {
  background: var(--bg-2); border: 1px solid var(--border);
  border-radius: var(--radius); padding: .75rem 1rem;
  color: var(--text); font-family: var(--font-display); font-size: .875rem;
  transition: border-color .2s; width: 100%;
}
.form-control:focus { outline: none; border-color: rgba(0,255,136,.4); box-shadow: 0 0 0 3px rgba(0,255,136,.06); }
select.form-control option { background: var(--bg-2); }
.form-check { display: flex; align-items: center; gap: .5rem; margin-bottom: .75rem; font-size: .875rem; }
.form-check input { accent-color: var(--accent); width: 16px; height: 16px; }

.alert {
  padding: .875rem 1.25rem; border-radius: var(--radius); margin-bottom: 1rem;
  font-family: var(--font-mono); font-size: .85rem;
}
.alert-success { background: rgba(0,255,136,.1); border: 1px solid rgba(0,255,136,.2); color: var(--accent); }
.alert-danger { background: rgba(255,71,87,.1); border: 1px solid rgba(255,71,87,.2); color: var(--danger); }
.alert-warning { background: rgba(255,165,2,.1); border: 1px solid rgba(255,165,2,.2); color: var(--warning); }

.quick-actions { margin-bottom: 1.5rem; }
.quick-actions h2 { font-size: 1rem; margin-bottom: 1rem; font-family: var(--font-mono); color: var(--text-muted); text-transform: uppercase; letter-spacing: .1em; }
.action-grid { display: grid; grid-template-columns: repeat(auto-fill,minmax(160px,1fr)); gap: .75rem; }
.action-card {
  background: var(--card); border: 1px solid var(--border);
  border-radius: var(--radius); padding: 1rem;
  text-align: center; font-family: var(--font-mono); font-size: .8rem;
  color: var(--text-muted); transition: all .2s;
  display: flex; flex-direction: column; align-items: center; gap: .5rem;
}
.action-card i { font-size: 1.25rem; color: var(--accent); }
.action-card:hover { border-color: rgba(0,255,136,.2); color: var(--text); background: var(--bg-3); }

/* Login */
.login-body { display: flex; align-items: center; justify-content: center; min-height: 100vh;
  background: radial-gradient(ellipse at center, #0a1018 0%, #060a10 100%); }
.login-wrap { width: 100%; max-width: 420px; padding: 1.5rem; }
.login-card {
  background: var(--card); border: 1px solid var(--border);
  border-radius: 16px; padding: 2.5rem; text-align: center;
}
.login-logo { font-family: var(--font-mono); font-size: 1.4rem; font-weight: 700; margin-bottom: 1.5rem; }
.login-card h2 { font-size: 1.1rem; color: var(--text-muted); margin-bottom: 2rem; font-weight: 400; }
.login-card .form-group { text-align: left; }
.btn-login {
  width: 100%; background: var(--accent); color: #000;
  border: none; padding: .875rem; border-radius: var(--radius);
  font-family: var(--font-mono); font-weight: 700; cursor: pointer;
  font-size: 1rem; margin-top: 1rem; transition: all .2s;
  display: flex; align-items: center; justify-content: center; gap: .5rem;
}
.btn-login:hover { background: #00e67a; transform: translateY(-1px); }

@media (max-width: 768px) {
  .admin-sidebar { transform: translateX(-100%); }
  .admin-sidebar.open { transform: translateX(0); }
  .admin-main { margin-left: 0; }
  .form-grid { grid-template-columns: 1fr; }
  .stats-grid { grid-template-columns: 1fr 1fr; }
}
CSSEOF

    # MAIN JS
    cat > ${APP_DIR}/static/js/main.js << 'JSEOF'
'use strict';

// Navbar scroll
window.addEventListener('scroll', () => {
  document.getElementById('navbar')?.classList.toggle('scrolled', window.scrollY > 50);
});

// Hamburger menu
const hamburger = document.getElementById('hamburger');
const mobileMenu = document.getElementById('mobileMenu');
hamburger?.addEventListener('click', () => {
  mobileMenu?.classList.toggle('open');
});
document.querySelectorAll('.mobile-link').forEach(link => {
  link.addEventListener('click', () => mobileMenu?.classList.remove('open'));
});
document.addEventListener('click', e => {
  if (!hamburger?.contains(e.target) && !mobileMenu?.contains(e.target)) {
    mobileMenu?.classList.remove('open');
  }
});

// Toast
function showToast(msg, type = 'success') {
  const toast = document.getElementById('toast');
  if (!toast) return;
  toast.textContent = msg;
  toast.className = `toast ${type} show`;
  setTimeout(() => toast.classList.remove('show'), 4000);
}
window.showToast = showToast;

// Intersection Observer for fade-in sections
const fadeObserver = new IntersectionObserver(entries => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      entry.target.style.opacity = '1';
      entry.target.style.transform = 'translateY(0)';
    }
  });
}, { threshold: 0.1 });

document.querySelectorAll('.section-header, .project-card, .skill-group, .timeline-item, .testimonial-card, .contact-item').forEach(el => {
  el.style.opacity = '0';
  el.style.transform = 'translateY(30px)';
  el.style.transition = 'opacity .6s ease, transform .6s ease';
  fadeObserver.observe(el);
});

// Active nav on scroll
const sections = document.querySelectorAll('section[id]');
window.addEventListener('scroll', () => {
  const scrollY = window.pageYOffset;
  sections.forEach(section => {
    const height = section.offsetHeight;
    const top = section.offsetTop - 100;
    if (scrollY >= top && scrollY < top + height) {
      document.querySelectorAll('.nav-links a').forEach(a => {
        a.classList.remove('active');
        if (a.getAttribute('href')?.includes(section.id)) a.classList.add('active');
      });
    }
  });
});
JSEOF

    log_success "Static assets created"
}

# ============================================================
# STEP 7: Gunicorn & Systemd Service
# ============================================================
setup_gunicorn() {
    log_step "Setting up Gunicorn service"

    cat > ${APP_DIR}/gunicorn.conf.py << EOF
bind = "127.0.0.1:5000"
workers = $(( $(nproc) * 2 + 1 ))
worker_class = "sync"
timeout = 120
accesslog = "/var/log/portfolio/access.log"
errorlog = "/var/log/portfolio/error.log"
loglevel = "info"
preload_app = True
chdir = "${APP_DIR}"
EOF

    mkdir -p /var/log/portfolio

    cat > /etc/systemd/system/portfolio.service << EOF
[Unit]
Description=Portfolio Flask App
After=network.target mysql.service

[Service]
User=www-data
Group=www-data
WorkingDirectory=${APP_DIR}
Environment="PATH=${APP_DIR}/venv/bin"
EnvironmentFile=${APP_DIR}/.env
ExecStart=${APP_DIR}/venv/bin/gunicorn --config ${APP_DIR}/gunicorn.conf.py app:app
ExecReload=/bin/kill -s HUP \$MAINPID
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    # Permissions
    chown -R www-data:www-data ${APP_DIR}
    chmod -R 755 ${APP_DIR}
    chmod 600 ${APP_DIR}/.env

    # Initialize DB
    cd ${APP_DIR}
    ${APP_DIR}/venv/bin/python3 -c "from app import init_db; init_db()"

    systemctl daemon-reload
    systemctl enable portfolio
    systemctl start portfolio

    log_success "Gunicorn service started"
}

# ============================================================
# STEP 8: Nginx Configuration
# ============================================================
setup_nginx() {
    log_step "Configuring Nginx"

    rm -f /etc/nginx/sites-enabled/default

    cat > /etc/nginx/sites-available/portfolio << EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN} www.${DOMAIN};

    client_max_body_size 20M;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;

    # Hide nginx version
    server_tokens off;

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml application/json application/javascript application/xml+rss application/atom+xml image/svg+xml;

    # Static files
    location /static/ {
        alias ${APP_DIR}/static/;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }

    # Main app
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        proxy_buffering off;
    }

    # Block access to sensitive files
    location ~ /\\.env { deny all; return 404; }
    location ~ /\\.git { deny all; return 404; }
    location ~ __pycache__ { deny all; return 404; }
    location ~ \\.py\$ { deny all; return 404; }
    location = /favicon.ico { access_log off; log_not_found off; }
    location = /robots.txt  { access_log off; log_not_found off; }
}
EOF

    ln -sf /etc/nginx/sites-available/portfolio /etc/nginx/sites-enabled/
    nginx -t && systemctl reload nginx

    log_success "Nginx configured"
}

# ============================================================
# STEP 9: Firewall (UFW)
# ============================================================
setup_firewall() {
    log_step "Setting up UFW firewall"
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw allow 'Nginx Full'
    ufw --force enable
    log_success "Firewall configured"
}

# ============================================================
# STEP 10: SSL/TLS with Certbot
# ============================================================
setup_ssl() {
    log_step "Setting up SSL/TLS with Certbot"

    log_warn "Attempting to obtain SSL certificate for ${DOMAIN}..."
    log_warn "Make sure DNS is pointing to this server before continuing!"
    log_warn "Cloudflare: Disable proxy (grey cloud) temporarily for Certbot validation"
    echo ""

    # Try certbot
    if certbot --nginx \
        --non-interactive \
        --agree-tos \
        --email "${ADMIN_EMAIL}" \
        -d "${DOMAIN}" \
        -d "www.${DOMAIN}" \
        --redirect 2>/dev/null; then
        log_success "SSL certificate obtained!"
        # Setup auto-renewal
        (crontab -l 2>/dev/null; echo "0 3 * * * certbot renew --quiet && systemctl reload nginx") | crontab -
    else
        log_warn "SSL setup failed. This is normal if DNS isn't pointing here yet."
        log_warn "Run manually later: certbot --nginx -d ${DOMAIN} -d www.${DOMAIN}"
    fi
}

# ============================================================
# STEP 11: Fail2ban
# ============================================================
setup_fail2ban() {
    log_step "Configuring Fail2ban"
    cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true

[nginx-http-auth]
enabled = true

[nginx-botsearch]
enabled = true
logpath  = /var/log/nginx/access.log
maxretry = 2
EOF
    systemctl restart fail2ban
    log_success "Fail2ban configured"
}

# ============================================================
# STEP 12: Cloudflare Instructions
# ============================================================
show_cloudflare_instructions() {
    log_step "Cloudflare Configuration Instructions"
    SERVER_IP=$(curl -4 -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')

    cat << EOF

${CYAN}${BOLD}╔═══════════════════════════════════════════════════════════╗
║           CLOUDFLARE SETUP INSTRUCTIONS                   ║
╚═══════════════════════════════════════════════════════════╝${NC}

Your server IP: ${YELLOW}${SERVER_IP}${NC}

${BOLD}1. Login to Cloudflare → Select your domain (rizzdevs.biz.id)${NC}

${BOLD}2. DNS Records:${NC}
   Type  | Name           | Value            | Proxy
   ------+----------------+------------------+--------
   A     | rizzdevs.biz.id| ${SERVER_IP}     | ✓ (orange)
   A     | www            | ${SERVER_IP}     | ✓ (orange)
   CNAME | @              | rizzdevs.biz.id  | ✓

${BOLD}3. SSL/TLS Settings:${NC}
   → SSL/TLS tab → Overview → Mode: ${YELLOW}Full (strict)${NC}
   → Edge Certificates → Always use HTTPS: ${YELLOW}ON${NC}
   → Edge Certificates → HSTS: ${YELLOW}Enable (6 months, include subdomains)${NC}
   → Edge Certificates → Minimum TLS: ${YELLOW}1.2${NC}

${BOLD}4. Security Settings:${NC}
   → Security → Settings → Security Level: ${YELLOW}Medium or High${NC}
   → Security → Bot Fight Mode: ${YELLOW}ON${NC}

${BOLD}5. Performance Settings:${NC}
   → Speed → Optimization → Auto Minify: ${YELLOW}JS, CSS, HTML${NC}
   → Caching → Configuration → Browser Cache TTL: ${YELLOW}1 year${NC}

${BOLD}6. Firewall Rules (optional but recommended):${NC}
   Block countries you don't need traffic from.

EOF
}

# ============================================================
# FINAL SUMMARY
# ============================================================
show_summary() {
    SERVER_IP=$(curl -4 -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')

    cat << EOF

${GREEN}${BOLD}╔═══════════════════════════════════════════════════════════╗
║          INSTALLATION COMPLETE! ✓                         ║
╚═══════════════════════════════════════════════════════════╝${NC}

${BOLD}Website:${NC}      http://${DOMAIN} (or https:// after SSL)
${BOLD}Admin URL:${NC}    http://${DOMAIN}/secure-panel-7x9k2m
${BOLD}Admin Email:${NC}  ${ADMIN_EMAIL}
${BOLD}Admin Pass:${NC}   [as configured]

${YELLOW}${BOLD}DATABASE CREDENTIALS (save securely!):${NC}
DB Name:   ${DB_NAME}
DB User:   ${DB_USER}
DB Pass:   ${DB_PASS}

${BOLD}File Locations:${NC}
App:       ${APP_DIR}
Uploads:   ${APP_DIR}/static/uploads
Logs:      /var/log/portfolio/

${BOLD}Service Commands:${NC}
  systemctl status portfolio       # Check app status
  systemctl restart portfolio      # Restart app
  journalctl -u portfolio -f       # View logs
  systemctl reload nginx           # Reload nginx

${BOLD}SSL Setup (if not done):${NC}
  certbot --nginx -d ${DOMAIN} -d www.${DOMAIN}

${YELLOW}IMPORTANT SECURITY NOTES:${NC}
  1. The admin panel URL is: /secure-panel-7x9k2m
     Keep this URL secret — it returns 404 to non-admins
  2. Save DB credentials above to a secure location
  3. Enable Cloudflare proxy after SSL is configured

EOF
}

# ============================================================
# MAIN EXECUTION
# ============================================================
main() {
    clear
    banner
    echo ""

    check_root
    check_os

    install_deps
    setup_mysql
    setup_app
    create_app
    create_templates
    create_static
    setup_gunicorn
    setup_nginx
    setup_firewall
    setup_ssl
    setup_fail2ban
    show_cloudflare_instructions
    show_summary
}

main "$@"
