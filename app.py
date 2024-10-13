from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, send_from_directory, abort
from werkzeug.utils import secure_filename
import sqlite3
from urllib.parse import urlparse
import qrcode
import io
import re
from datetime import timedelta
from werkzeug.security import check_password_hash
import os
from random import choice
import string

# Configuration
app = Flask(__name__)
app.secret_key = "your_secret_key"
app.permanent_session_lifetime = timedelta(days=7)

DATABASE = 'urls.db'
UPLOAD_FOLDER = 'uploads'
PASSWORD_HASH = '' # Enter your SHA256 password here
BLACKLIST_EXTENSIONS = {'exe', 'bat', 'sh', 'msi', 'com', 'js', 'jar', 'py'}

# Ensure the upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def is_blacklisted(filename):
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    return ext in BLACKLIST_EXTENSIONS

def generate_short_url():
    return ''.join(choice(string.ascii_letters + string.digits) for _ in range(6))

def get_db_connection():
    """Create a new database connection."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Access rows as dictionaries
    return conn

def init_db():
    """Initialize the database if it doesn't exist."""
    if not os.path.exists(DATABASE):
        print("Initializing database...")
        conn = get_db_connection()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS urls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_url TEXT NOT NULL,
                short_url TEXT NOT NULL UNIQUE
            )
        """)
        conn.commit()
        conn.close()
        print("Database initialized.")

# Call the init_db() function when the app starts
init_db()

def get_user_ip():
    """Get the client's real IP address."""
    if request.headers.get('X-Forwarded-For'):
        # Get the first IP in the chain (the real client IP)
        ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    else:
        ip = request.remote_addr
    return ip

@app.route('/logout')
def logout():
    session.pop('authenticated', None)
    flash('You have been logged out.')
    return redirect(url_for('index'))

@app.route('/', methods=['GET', 'POST'])
def index():
    # If the user is already authenticated, show the main page
    if session.get('authenticated'):
        if request.method == 'POST':
            original_url = request.form['original_url'].strip()
            custom_alias = request.form.get('custom_alias', '').strip()

            # Ensure the URL is valid and properly formatted
            original_url = ensure_scheme(original_url)
            if not is_valid_url(original_url):
                flash('Please enter a valid URL.')
                return redirect(url_for('index'))

            conn = get_db_connection()
            if custom_alias:
                alias_exists = conn.execute('SELECT 1 FROM urls WHERE short_url = ?', (custom_alias,)).fetchone()
                if alias_exists:
                    conn.close()
                    flash('Custom alias already taken. Please choose another.')
                    return redirect(url_for('index'))
                short_url = custom_alias
            else:
                short_url = generate_short_url()

            # Insert the short URL into the database
            conn.execute('INSERT INTO urls (original_url, short_url) VALUES (?, ?)', (original_url, short_url))
            conn.commit()
            conn.close()

            flash(f'Short URL created: {request.host_url}{short_url}')
            return render_template('success.html', short_url=short_url)

        return render_template('index.html', user_ip=get_user_ip())

    # If not authenticated, show the login form
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        password = request.form['password']
        remember = 'remember' in request.form  # Check if "Remember Me" was selected

        if check_password(password):
            session['authenticated'] = True
            if remember:
                session.permanent = True  # Session will last according to lifetime
            else:
                session.permanent = False  # Session ends when browser closes
            flash('Successfully logged in!')
            return redirect(url_for('index'))
        else:
            flash('Invalid password! Please try again.')
            return redirect(url_for('login'))

    user_ip = get_user_ip()
    return render_template('login.html', user_ip=user_ip)



@app.route('/<short_url>')
def redirect_url(short_url):
    """Redirect to the original URL using the short URL."""
    conn = get_db_connection()
    url_data = conn.execute('SELECT original_url FROM urls WHERE short_url = ?', (short_url,)).fetchone()
    conn.close()

    if url_data:
        return redirect(url_data['original_url'])
    else:
        # Raise a 404 error if the short URL is not found
        abort(404)
    
@app.route('/qr/<short_url>')
def generate_qr(short_url):
    """Generate and return a QR code image for the shortened URL."""
    full_url = f"{request.host_url}{short_url}"

    # Create a QRCode object with custom size settings
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=10,
        border=2,
    )
    qr.add_data(full_url)
    qr.make(fit=True)

    # Create an image from the QRCode instance
    img = qr.make_image(fill_color="black", back_color="white")

    # Save the image to an in-memory buffer
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)

    return send_file(buffer, mimetype='image/png')

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    """Serve the uploaded file."""
    # Ensure the uploads folder path is correct
    uploads_dir = os.path.join(app.root_path, 'uploads')

    # Serve the file from the uploads directory
    return send_from_directory(uploads_dir, filename, as_attachment=False)


@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if 'authenticated' not in session or not session['authenticated']:
        flash('Please log in to upload files.')
        return redirect(url_for('index'))
    
    user_ip = get_user_ip()  # Get the user's IP address

    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)

        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)

        if is_blacklisted(file.filename):
            flash(f'The file type "{file.filename}" is not allowed.')
            return redirect(request.url)

        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        custom_alias = request.form.get('custom_alias', '').strip()
        conn = get_db_connection()
        if custom_alias:
            alias_exists = conn.execute('SELECT 1 FROM urls WHERE short_url = ?', (custom_alias,)).fetchone()
            if alias_exists:
                conn.close()
                flash('Custom alias already taken. Please choose another.')
                return redirect(request.url)
            short_url = custom_alias
        else:
            short_url = generate_short_url()

        conn.execute('INSERT INTO urls (original_url, short_url) VALUES (?, ?)', (f'/uploads/{filename}', short_url))
        conn.commit()
        conn.close()

        flash(f'File uploaded successfully! Short link: {request.host_url}{short_url}')
        return render_template('success.html', short_url=short_url)

    return render_template('upload.html', user_ip=user_ip)

def ensure_scheme(url):
    parsed_url = urlparse(url)
    if not parsed_url.scheme:
        return f'https://{url}'
    return url

def is_valid_url(url):
    regex = re.compile(r'^(https?://)?(([a-zA-Z0-9_-]+\.)+[a-zA-Z]{2,})(:\d+)?(/.*)?$', re.IGNORECASE)
    return re.match(regex, url) is not None

def check_password(input_password):
    return check_password_hash(PASSWORD_HASH, input_password)

@app.errorhandler(404)
def page_not_found(e):
    """Custom 404 page."""
    user_ip = get_user_ip()  # Get the user's IP address
    return render_template('404.html', user_ip=user_ip), 404

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8084, debug=True)