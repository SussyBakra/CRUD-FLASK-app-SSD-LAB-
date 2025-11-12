from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect
import os
from werkzeug.security import generate_password_hash, check_password_hash
try:
    from .forms import LoginForm, PersonForm, ContactForm
except Exception:
    from forms import LoginForm, PersonForm, ContactForm

app = Flask(__name__)
# NOTE: change SECRET_KEY in production; keep this for local dev
app.config['SECRET_KEY'] = 'dev-secret-key'

basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'firstapp.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# CSRF Protection - enabled globally via Flask-WTF
csrf = CSRFProtect(app)
bcrypt = Bcrypt(app)

# Secure Session Configuration
app.config['SESSION_PERMANENT'] = False  # Non-persistent sessions by default
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to session cookie
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection via SameSite attribute
# Note: SESSION_COOKIE_SECURE should be True in production (HTTPS only)
# Set to False for local development (HTTP)
app.config['SESSION_COOKIE_SECURE'] = False  # Set True in production when using HTTPS
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour session timeout (in seconds)

db = SQLAlchemy(app)

@app.errorhandler(404)
def not_found_error(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(e):
    # avoid leaking exception details to users
    return render_template('500.html'), 500

class Person(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100))
    email = db.Column(db.String(120))
    phone = db.Column(db.String(30))
    message = db.Column(db.Text)

    def __repr__(self):
        return f'<Person {self.id} {self.first_name}>'

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    def set_password(self, password):
        # Store bcrypt hash
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        # Primary: bcrypt
        try:
            if bcrypt.check_password_hash(self.password_hash, password):
                return True
        except Exception:
            pass
        # Fallback: legacy Werkzeug PBKDF2 hash
        try:
            return check_password_hash(self.password_hash, password)
        except Exception:
            return False

@app.route('/', methods=['GET', 'POST'])
def index():
    form = PersonForm()
    if form.validate_on_submit():
        p = Person(
            first_name=form.first_name.data.strip(),
            last_name=(form.last_name.data or '').strip(),
            email=(form.email.data or '').strip(),
            phone=''  # phone deprecated for contact; leave empty here
        )
        db.session.add(p)
        db.session.commit()
        flash('Record added successfully.', 'success')
        return redirect(url_for('index'))

    people = Person.query.order_by(Person.id.asc()).all()
    return render_template('index.html', people=people, form=form)

@app.route('/update/<int:id>', methods=['GET', 'POST'])
def update(id):
    person = Person.query.get_or_404(id)
    form = PersonForm(obj=person)
    if form.validate_on_submit():
        person.first_name = form.first_name.data.strip()
        person.last_name = (form.last_name.data or '').strip()
        person.email = (form.email.data or '').strip()
        db.session.commit()
        flash('Record updated.', 'success')
        return redirect(url_for('index'))
    return render_template('update.html', person=person, form=form)

@app.route('/delete/<int:id>', methods=['GET'])
def delete(id):
    person = Person.query.get_or_404(id)
    db.session.delete(person)
    db.session.commit()
    flash('Record deleted.', 'warning')
    return redirect(url_for('index'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data.strip()
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            # If legacy hash matched, upgrade to bcrypt on-the-fly
            if not bcrypt.check_password_hash(user.password_hash, password):
                user.set_password(password)
                db.session.commit()
            session['user_id'] = user.id
            session['username'] = user.username
            session.permanent = True  # Enable persistent session with lifetime
            flash('Logged in successfully.', 'success')
            return redirect(url_for('index'))
        flash('Invalid username or password.', 'danger')
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/contact', methods=['GET', 'POST'])
def contact():
    form = ContactForm()
    if form.validate_on_submit():
        p = Person(
            first_name=form.first_name.data.strip(),
            last_name=(form.last_name.data or '').strip(),
            email=(form.email.data or '').strip(),
            message=(form.message.data or '').strip(),
            phone=''  # deprecated
        )
        db.session.add(p)
        db.session.commit()
        flash('Contact saved successfully.', 'success')
        return redirect(url_for('contact'))
    return render_template('contact.html', form=form)


if __name__ == '__main__':
    # Create DB file and tables if they don't exist
    with app.app_context():
        db.create_all()
        # ensure 'message' column exists on 'person' (SQLite lacks auto migrations)
        from sqlalchemy import text
        info = db.session.execute(text("PRAGMA table_info(person);")).all()
        existing_cols = {row[1] for row in info}
        if 'message' not in existing_cols:
            db.session.execute(text("ALTER TABLE person ADD COLUMN message TEXT"))
            db.session.commit()
        # seed a default user if none exists (demo only)
        if User.query.count() == 0:
            demo = User(username='admin')
            demo.set_password('admin123')
            db.session.add(demo)
            db.session.commit()
    # Start dev server
    app.run(debug=True)