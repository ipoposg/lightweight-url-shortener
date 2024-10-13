from flask import Flask, render_template, request, redirect, url_for, flash
import sqlite3
from urllib.parse import urlparse
import re

app = Flask(__name__)
app.secret_key = "your_secret_key"

DATABASE = 'urls.db'
PASSWORD_HASH = ''  # Replace with your actual hash

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # Verify password
        password = request.form['password']
        if not check_password(password):
            flash('Invalid password!')
            return redirect(url_for('index'))

        original_url = request.form['original_url'].strip()
        custom_alias = request.form['custom_alias'].strip()

        # Ensure the URL is valid and has a scheme
        original_url = ensure_scheme(original_url)

        if not is_valid_url(original_url):
            flash('Please enter a valid URL.')
            return redirect(url_for('index'))

        # Check if the URL is recursive (s.keechun.me)
        if is_recursive(original_url):
            flash('You cannot shorten URLs from this domain.')
            return redirect(url_for('index'))

        conn = get_db_connection()
        if custom_alias:
            # Check if alias is already in use
            alias_exists = conn.execute('SELECT * FROM urls WHERE short_url = ?', (custom_alias,)).fetchone()
            if alias_exists:
                flash('Custom alias is already taken. Please choose another.')
                conn.close()
                return redirect(url_for('index'))

            short_url = custom_alias
        else:
            short_url = generate_short_url()

        conn.execute('INSERT INTO urls (original_url, short_url) VALUES (?, ?)', (original_url, short_url))
        conn.commit()
        conn.close()

        return render_template('success.html', short_url=short_url)

    return render_template('index.html')

@app.route('/<short_url>')
def redirect_url(short_url):
    conn = get_db_connection()
    url_data = conn.execute('SELECT original_url FROM urls WHERE short_url = ?', (short_url,)).fetchone()
    conn.close()
    if url_data:
        return redirect(url_data['original_url'])
    else:
        flash('Invalid URL')
        return redirect(url_for('index'))

def generate_short_url():
    from random import choice
    import string
    return ''.join(choice(string.ascii_letters + string.digits) for _ in range(6))

def is_recursive(url):
    """Check if the URL belongs to s.keechun.me to prevent recursion."""
    parsed_url = urlparse(url)
    return parsed_url.netloc == 's.keechun.me'

def ensure_scheme(url):
    """Ensure the URL has http:// or https://. If missing, add https:// by default."""
    parsed_url = urlparse(url)
    if not parsed_url.scheme:
        return f'https://{url}'
    return url

def is_valid_url(url):
    """Validate the given URL using a regex pattern."""
    regex = re.compile(
        r'^(https?://)?'  # http:// or https:// (optional, already handled)
        r'(([a-zA-Z0-9_-]+\.)+[a-zA-Z]{2,})'  # Domain name
        r'(:\d+)?'  # Optional port
        r'(/.*)?$'  # Optional path
    )
    return re.match(regex, url) is not None

def check_password(input_password):
    """Verify if the input password matches the stored hash."""
    from werkzeug.security import check_password_hash
    return check_password_hash(PASSWORD_HASH, input_password)

if __name__ == "__main__":
    app.run(host='127.0.0.1', port=8084)
