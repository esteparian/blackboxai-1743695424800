from flask import Flask, request, jsonify, session, redirect, url_for, render_template, abort
import sqlite3
import bcrypt
import secrets
import smtplib
from email.mime.text import MIMEText
import os
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Database setup
def get_db_connection():
    conn = sqlite3.connect('alerta_vecinos.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db_connection() as conn:
        # Users table
        conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fullname TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            phone TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            verified BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Password resets table
        conn.execute('''
        CREATE TABLE IF NOT EXISTS password_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            token TEXT NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            used BOOLEAN DEFAULT FALSE
        )
        ''')
        
        # Social logins table
        conn.execute('''
        CREATE TABLE IF NOT EXISTS social_logins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            provider TEXT NOT NULL,
            provider_id TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        ''')
        
        conn.commit()

init_db()

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            data = request.get_json()
            identifier = data.get('identifier')
            password = data.get('password').encode('utf-8')
            
            with get_db_connection() as conn:
                user = conn.execute(
                    'SELECT * FROM users WHERE email = ? OR phone = ?', 
                    (identifier, identifier)
                ).fetchone()
                
                if user and bcrypt.checkpw(password, user['password']):
                    session['user_id'] = user['id']
                    session['user_email'] = user['email']
                    session['user_name'] = user['fullname']
                    return jsonify({
                        'status': 'success', 
                        'redirect': '/dashboard',
                        'user': {
                            'name': user['fullname'],
                            'email': user['email']
                        }
                    })
                return jsonify({
                    'status': 'error', 
                    'message': 'Correo/telefono o contraseña incorrectos'
                }), 401
                
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': 'Error en el servidor'
            }), 500
    
    return render_template('user_login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.form
        fullname = data.get('fullname')
        email = data.get('email')
        phone = data.get('phone')
        password = bcrypt.hashpw(data.get('password').encode('utf-8'), bcrypt.gensalt())
        
        try:
            with get_db_connection() as conn:
                conn.execute(
                    'INSERT INTO users (fullname, email, phone, password) VALUES (?, ?, ?, ?)',
                    (fullname, email, phone, password)
                )
                # Send verification email
                send_verification_email(email)
                return redirect(url_for('verify_email'))
        except sqlite3.IntegrityError:
            return jsonify({'status': 'error', 'message': 'El correo o teléfono ya está registrado'}), 400
    
    return render_template('register.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        token = secrets.token_urlsafe(32)
        
        with get_db_connection() as conn:
            # Delete any existing tokens for this email
            conn.execute('DELETE FROM password_resets WHERE email = ?', (email,))
            # Insert new token (expires in 1 hour)
            conn.execute(
                'INSERT INTO password_resets (email, token, expires_at) VALUES (?, ?, ?)',
                (email, token, datetime.now() + timedelta(hours=1))
            )
        
        # Send password reset email
        send_password_reset_email(email, token)
        return jsonify({'status': 'success'})
    
    return render_template('forgot-password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    with get_db_connection() as conn:
        reset = conn.execute(
            'SELECT * FROM password_resets WHERE token = ? AND expires_at > ? AND used = FALSE',
            (token, datetime.now())
        ).fetchone()
        
        if not reset:
            return render_template('error.html', message='Enlace inválido o expirado')
        
        if request.method == 'POST':
            new_password = bcrypt.hashpw(request.form.get('password').encode('utf-8'), bcrypt.gensalt())
            # Update user password
            conn.execute(
                'UPDATE users SET password = ? WHERE email = ?',
                (new_password, reset['email'])
            )
            # Mark token as used
            conn.execute(
                'UPDATE password_resets SET used = TRUE WHERE token = ?',
                (token,)
            )
            return jsonify({'status': 'success', 'redirect': '/login'})
    
    return render_template('reset-password.html', token=token)

@app.route('/social-login/<provider>')
def social_login(provider):
    # This would redirect to the provider's OAuth page
    # Implementation depends on the social provider (Google, Facebook, etc.)
    pass

@app.route('/social-login/callback/<provider>')
def social_login_callback(provider):
    # Handle OAuth callback
    # Verify token, get user info, create/update user in database
    pass

# Test routes for error pages
@app.route('/test/404')
def test_404():
    abort(404)

@app.route('/test/500')
def test_500():
    abort(500)

@app.route('/test/db-error')
def test_db_error():
    # Simulate DB connection error
    original_get_db = get_db_connection
    def mock_get_db():
        raise sqlite3.Error("Simulated DB error")
    get_db_connection = mock_get_db
    try:
        return check_db_connection()
    finally:
        get_db_connection = original_get_db

# Protected routes
# Add this before the existing profile route
@app.route('/profile/setup', methods=['GET', 'POST'])
@login_required 
def profile_setup():
    if request.method == 'POST':
        try:
            # Get form data
            first_name = request.form.get('first_name')
            last_name = request.form.get('last_name')
            address = request.form.get('address')
            neighborhood = request.form.get('neighborhood')
            block = request.form.get('block')
            
            # Process emergency contacts
            emergency_contacts = []
            names = request.form.getlist('emergency_contact_name')
            phones = request.form.getlist('emergency_contact_phone')
            for name, phone in zip(names, phones):
                if name and phone:
                    emergency_contacts.append({'name': name, 'phone': phone})
            
            # Process profile photo
            profile_photo = None
            if 'profile_photo' in request.files:
                file = request.files['profile_photo']
                if file.filename:
                    filename = f"profile_{session['user_id']}_{datetime.now().strftime('%Y%m%d%H%M%S')}{os.path.splitext(file.filename)[1]}"
                    file.save(os.path.join('static/uploads/profiles', filename))
                    profile_photo = filename
            
            # Update user profile in database
            with get_db_connection() as conn:
                # Create profile table if not exists
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS user_profiles (
                        user_id INTEGER PRIMARY KEY,
                        first_name TEXT NOT NULL,
                        last_name TEXT NOT NULL,
                        address TEXT NOT NULL,
                        neighborhood TEXT NOT NULL,
                        block TEXT,
                        profile_photo TEXT,
                        emergency_contacts TEXT,
                        FOREIGN KEY(user_id) REFERENCES users(id)
                    )
                ''')
                
                # Insert or update profile
                conn.execute('''
                    INSERT OR REPLACE INTO user_profiles 
                    (user_id, first_name, last_name, address, neighborhood, block, profile_photo, emergency_contacts)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    session['user_id'],
                    first_name,
                    last_name,
                    address,
                    neighborhood,
                    block,
                    profile_photo,
                    json.dumps(emergency_contacts)
                ))
                conn.commit()
            
            return jsonify({'status': 'success', 'redirect': '/dashboard'})
            
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)}), 500
    
    # GET request - show profile setup form
    return render_template('profile-setup.html')

@app.route('/health')
def health_check():
    """Endpoint de verificación de salud"""
    try:
        # Verificar conexión a la base de datos
        with get_db_connection() as conn:
            conn.execute('SELECT 1')
        return jsonify({'status': 'healthy'}), 200
    except Exception as e:
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 500

@app.route('/dashboard') 
@login_required
def dashboard():
    # Check if profile is complete
    with get_db_connection() as conn:
        profile = conn.execute(
            'SELECT * FROM user_profiles WHERE user_id = ?',
            (session['user_id'],)
        ).fetchone()
        
        if not profile:
            return redirect('/profile/setup')
    
    return render_template('dashboard.html')

@app.route('/profile')
@login_required
def profile():
    with get_db_connection() as conn:
        user = conn.execute(
            'SELECT * FROM users WHERE id = ?',
            (session['user_id'],)
        ).fetchone()
        
        profile = conn.execute(
            'SELECT * FROM user_profiles WHERE user_id = ?',
            (session['user_id'],)
        ).fetchone()
        
        if not profile:
            return redirect('/profile/setup')
            
        # Parse emergency contacts
        emergency_contacts = []
        if profile['emergency_contacts']:
            emergency_contacts = json.loads(profile['emergency_contacts'])
    
    return render_template('profile.html', 
                         user=user, 
                         profile=profile,
                         emergency_contacts=emergency_contacts)

# Helper functions
def send_verification_email(email):
    # Implementation for sending verification email
    pass

def send_password_reset_email(email, token):
    # Implementation for sending password reset email
    pass

# Error handlers
@app.route('/')
def index():
    try:
        return redirect(url_for('login'))
    except Exception as e:
        app.logger.error(f"Error en redirección: {str(e)}")
        return render_template('user_login.html')

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

# Database connection check middleware
@app.before_request
def check_db_connection():
    try:
        conn = get_db_connection()
        conn.execute('SELECT 1')
        conn.close()
    except Exception as e:
        return render_template('database_error.html'), 503

# Track first request
app._got_first_request = False

# Ensure all required templates exist
@app.before_request
def check_templates():
    if app._got_first_request:
        return
    app._got_first_request = True
    required_templates = [
        '404.html',
        '500.html', 
        'database_error.html'
    ]
    for template in required_templates:
        try:
            render_template(template)
        except:
            create_default_error_template(template)

def create_default_error_template(template_name):
    """Create default error templates if missing"""
    template_path = os.path.join('templates', template_name)
    with open(template_path, 'w') as f:
        if template_name == '404.html':
            f.write('''<!DOCTYPE html>
<html>
<head>
    <title>Página no encontrada</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 flex items-center justify-center min-h-screen">
    <div class="text-center">
        <h1 class="text-6xl font-bold text-blue-600 mb-4">404</h1>
        <p class="text-xl mb-8">La página que buscas no existe.</p>
        <a href="/" class="bg-blue-600 text-white px-6 py-3 rounded-lg hover:bg-blue-700 transition">
            Volver al inicio
        </a>
    </div>
</body>
</html>''')
        elif template_name == '500.html':
            f.write('''<!DOCTYPE html>
<html>
<head>
    <title>Error del servidor</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 flex items-center justify-center min-h-screen">
    <div class="text-center">
        <h1 class="text-6xl font-bold text-red-600 mb-4">500</h1>
        <p class="text-xl mb-8">Ocurrió un error en el servidor.</p>
        <a href="/" class="bg-blue-600 text-white px-6 py-3 rounded-lg hover:bg-blue-700 transition">
            Volver al inicio
        </a>
    </div>
</body>
</html>''')
        else:
            f.write('''<!DOCTYPE html>
<html>
<head>
    <title>Error de conexión</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 flex items-center justify-center min-h-screen">
    <div class="text-center">
        <h1 class="text-6xl font-bold text-yellow-600 mb-4">503</h1>
        <p class="text-xl mb-8">Problemas de conexión con la base de datos.</p>
        <a href="/" class="bg-blue-600 text-white px-6 py-3 rounded-lg hover:bg-blue-700 transition">
            Volver al inicio
        </a>
    </div>
</body>
</html>''')

if __name__ == '__main__':
    from waitress import serve
    import logging
    import socket
    
    # Configuración avanzada de logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        handlers=[
            logging.FileHandler('app.log', mode='a'),
            logging.StreamHandler()
        ]
    )
    
    logger = logging.getLogger(__name__)
    
    # Verificar disponibilidad del puerto
    def check_port(port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            return s.connect_ex(('localhost', port)) != 0
    
    PORT = 8001
    if not check_port(PORT):
        logger.error(f'El puerto {PORT} está en uso')
        PORT = 8002  # Puerto alternativo
    
    # Configuración optimizada para IPv4
    from waitress import serve
    logger.info(f'Iniciando servidor en puerto {PORT} para IPv4')
    serve(
        app,
        host='0.0.0.0',
        port=PORT,
        threads=8,
        channel_timeout=120,
        connection_limit=2000,
        cleanup_interval=60,
        asyncore_use_poll=True,
        expose_tracebacks=False,
        ident='AlertaVecinosServer'
    )
    logger.info(f'Servidor iniciado en puerto {PORT} (IPv4 e IPv6)')
