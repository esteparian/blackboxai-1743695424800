from flask import Flask, request, redirect, url_for, render_template, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
from datetime import datetime
import uuid
from functools import wraps
import json

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['DATABASE'] = 'denuncias.db'

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def get_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with app.app_context():
        db = get_db()
        # Submissions table
        db.execute('''
            CREATE TABLE IF NOT EXISTS submissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT,
                category TEXT NOT NULL,
                description TEXT,
                location TEXT,
                files TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Admin users table
        db.execute('''
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT CHECK(role IN ('superuser', 'admin')) NOT NULL,
                email TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Activity logs table
        db.execute('''
            CREATE TABLE IF NOT EXISTS activity_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                admin_id INTEGER,
                action TEXT NOT NULL,
                details TEXT,
                ip_address TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(admin_id) REFERENCES admins(id)
            )
        ''')
        
        # Create default superuser if not exists
        from werkzeug.security import generate_password_hash
        superuser = db.execute(
            'SELECT * FROM admins WHERE username = ?', ('superU',)
        ).fetchone()
        
        if not superuser:
            db.execute(
                'INSERT INTO admins (username, password_hash, role, email) VALUES (?, ?, ?, ?)',
                ('superU', generate_password_hash('80w44$$9i'), 'superuser', 'superadmin@alerta24vecinos.com')
            )
        
        db.commit()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/submit-denuncia', methods=['POST'])
def submit_denuncia():
    try:
        # Get form data
        category = request.form.get('category')
        description = request.form.get('description')
        coordinates = request.form.get('coordinates')
        
        # Handle file uploads
        uploaded_files = []
        
        # Process photos
        if 'photos' in request.files:
            photos = request.files.getlist('photos')
            for photo in photos:
                if photo.filename:
                    filename = f"photo_{uuid.uuid4().hex}{os.path.splitext(photo.filename)[1]}"
                    photo.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    uploaded_files.append({
                        'type': 'photo',
                        'path': filename,
                        'timestamp': datetime.now().isoformat()
                    })

        # Process videos
        if 'videos' in request.files:
            videos = request.files.getlist('videos')
            for video in videos:
                if video.filename:
                    filename = f"video_{uuid.uuid4().hex}{os.path.splitext(video.filename)[1]}"
                    video.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    uploaded_files.append({
                        'type': 'video', 
                        'path': filename,
                        'timestamp': datetime.now().isoformat()
                    })

        # Process audio
        if 'audio' in request.files:
            audio = request.files['audio']
            if audio.filename:
                filename = f"audio_{uuid.uuid4().hex}{os.path.splitext(audio.filename)[1]}"
                audio.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                uploaded_files.append({
                    'type': 'audio',
                    'path': filename,
                    'timestamp': datetime.now().isoformat()
                })

        # Save to database
        db = get_db()
        db.execute('''
            INSERT INTO submissions (user_id, category, description, location, files)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            'demo_user',  # In production, get from session
            category,
            description,
            coordinates,
            json.dumps(uploaded_files)
        ))
        db.commit()

        return jsonify({
            'status': 'success',
            'message': 'Denuncia registrada correctamente'
        })

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/denuncias')
def list_denuncias():
    db = get_db()
    denuncias = db.execute('SELECT * FROM submissions ORDER BY timestamp DESC').fetchall()
    return jsonify([dict(denuncia) for denuncia in denuncias])

# Admin authentication decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated_function

# Admin routes
@app.route('/user/login')
def user_login():
    return render_template('user_login.html')

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        db = get_db()
        admin = db.execute(
            'SELECT * FROM admins WHERE username = ?', (username,)
        ).fetchone()
        
        if admin and check_password_hash(admin['password_hash'], password):
            session['admin_id'] = admin['id']
            session['admin_role'] = admin['role']
            session['admin_username'] = admin['username']
            
            # Log login activity
            db.execute(
                'INSERT INTO activity_logs (admin_id, action, details, ip_address) VALUES (?, ?, ?, ?)',
                (admin['id'], 'login', 'Inicio de sesión exitoso', request.remote_addr)
            )
            db.commit()
            
            return jsonify({
                'status': 'success',
                'role': admin['role']
            })
        return jsonify({'status': 'error', 'message': 'Credenciales inválidas'}), 401
    
    return render_template('login.html')

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    return render_template('index2.html')

@app.route('/admin/logout')
def admin_logout():
    if 'admin_id' in session:
        db = get_db()
        db.execute(
            'INSERT INTO activity_logs (admin_id, action, details, ip_address) VALUES (?, ?, ?, ?)',
            (session['admin_id'], 'logout', 'Cierre de sesión', request.remote_addr)
        )
        db.commit()
    session.clear()
    return redirect(url_for('admin_login'))

@app.route('/api/admin/dashboard')
@admin_required
def admin_dashboard_data():
    db = get_db()
    
    # Get stats
    total_complaints = db.execute('SELECT COUNT(*) FROM submissions').fetchone()[0]
    today_complaints = db.execute(
        'SELECT COUNT(*) FROM submissions WHERE DATE(timestamp) = DATE("now")'
    ).fetchone()[0]
    
    # Get complaints by category
    categories = db.execute(
        'SELECT category, COUNT(*) as count FROM submissions GROUP BY category'
    ).fetchall()
    
    # Get recent complaints
    recent_complaints = db.execute(
        'SELECT * FROM submissions ORDER BY timestamp DESC LIMIT 10'
    ).fetchall()
    
    return jsonify({
        'stats': {
            'total_complaints': total_complaints,
            'today_complaints': today_complaints,
            'admin_count': db.execute('SELECT COUNT(*) FROM admins').fetchone()[0]
        },
        'categories': [dict(cat) for cat in categories],
        'recent_complaints': [dict(comp) for comp in recent_complaints]
    })

# User Management API
@app.route('/api/admin/users', methods=['GET', 'POST'])
@admin_required
def admin_users():
    db = get_db()
    
    if request.method == 'GET':
        # Get all admin users with last login info
        users = db.execute('''
            SELECT a.*, MAX(al.timestamp) as last_login
            FROM admins a
            LEFT JOIN activity_logs al ON al.admin_id = a.id AND al.action = 'login'
            GROUP BY a.id
            ORDER BY a.created_at DESC
        ''').fetchall()
        
        return jsonify([dict(user) for user in users])
    
    elif request.method == 'POST':
        data = request.get_json()
        
        # Validate input
        if not all(k in data for k in ['username', 'email', 'password', 'role']):
            return jsonify({'status': 'error', 'message': 'Datos incompletos'}), 400
            
        if data['password'] != data.get('confirm_password', ''):
            return jsonify({'status': 'error', 'message': 'Las contraseñas no coinciden'}), 400
            
        # Check if username exists
        existing = db.execute(
            'SELECT id FROM admins WHERE username = ?', (data['username'],)
        ).fetchone()
        
        if existing:
            return jsonify({'status': 'error', 'message': 'El nombre de usuario ya existe'}), 400
            
        # Insert new admin
        db.execute(
            'INSERT INTO admins (username, email, password_hash, role) VALUES (?, ?, ?, ?)',
            (data['username'], data['email'], generate_password_hash(data['password']), data['role'])
        )
        db.commit()
        
        # Log the action
        db.execute(
            'INSERT INTO activity_logs (admin_id, action, details, ip_address) VALUES (?, ?, ?, ?)',
            (session['admin_id'], 'create_admin', f'Created admin: {data["username"]}', request.remote_addr)
        )
        db.commit()
        
        return jsonify({'status': 'success'})

@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
@admin_required
def admin_user(user_id):
    if session['admin_role'] != 'superuser':
        return jsonify({'status': 'error', 'message': 'No autorizado'}), 403
        
    db = get_db()
    
    # Get user info before deletion for logging
    user = db.execute(
        'SELECT username FROM admins WHERE id = ?', (user_id,)
    ).fetchone()
    
    if not user:
        return jsonify({'status': 'error', 'message': 'Usuario no encontrado'}), 404
        
    # Don't allow deleting self
    if user_id == session['admin_id']:
        return jsonify({'status': 'error', 'message': 'No puedes eliminarte a ti mismo'}), 400
        
    db.execute('DELETE FROM admins WHERE id = ?', (user_id,))
    db.commit()
    
    # Log the action
    db.execute(
        'INSERT INTO activity_logs (admin_id, action, details, ip_address) VALUES (?, ?, ?, ?)',
        (session['admin_id'], 'delete_admin', f'Deleted admin: {user["username"]}', request.remote_addr)
    )
    db.commit()
    
    return jsonify({'status': 'success'})

# Password Reset
@app.route('/api/admin/reset-password', methods=['POST'])
@admin_required
def reset_password():
    data = request.get_json()
    
    if not all(k in data for k in ['current_password', 'new_password', 'confirm_password']):
        return jsonify({'status': 'error', 'message': 'Datos incompletos'}), 400
        
    if data['new_password'] != data['confirm_password']:
        return jsonify({'status': 'error', 'message': 'Las contraseñas no coinciden'}), 400
        
    db = get_db()
    admin = db.execute(
        'SELECT password_hash FROM admins WHERE id = ?', (session['admin_id'],)
    ).fetchone()
    
    if not admin or not check_password_hash(admin['password_hash'], data['current_password']):
        return jsonify({'status': 'error', 'message': 'Contraseña actual incorrecta'}), 400
        
    # Update password
    db.execute(
        'UPDATE admins SET password_hash = ? WHERE id = ?',
        (generate_password_hash(data['new_password']), session['admin_id'])
    )
    db.commit()
    
    # Log the action
    db.execute(
        'INSERT INTO activity_logs (admin_id, action, details, ip_address) VALUES (?, ?, ?, ?)',
        (session['admin_id'], 'password_reset', 'Password changed', request.remote_addr)
    )
    db.commit()
    
    return jsonify({'status': 'success'})

# Activity Logs API
@app.route('/api/admin/activity-logs')
@admin_required
def activity_logs():
    db = get_db()
    
    # Get query parameters
    action = request.args.get('action')
    date_from = request.args.get('dateFrom')
    date_to = request.args.get('dateTo')
    user_id = request.args.get('userId')
    
    # Build query
    query = '''
        SELECT al.*, a.username 
        FROM activity_logs al
        JOIN admins a ON al.admin_id = a.id
        WHERE 1=1
    '''
    params = []
    
    if action:
        query += ' AND al.action = ?'
        params.append(action)
        
    if date_from:
        query += ' AND DATE(al.timestamp) >= ?'
        params.append(date_from)
        
    if date_to:
        query += ' AND DATE(al.timestamp) <= ?'
        params.append(date_to)
        
    if user_id:
        query += ' AND al.admin_id = ?'
        params.append(user_id)
        
    query += ' ORDER BY al.timestamp DESC LIMIT 100'
    
    logs = db.execute(query, params).fetchall()
    return jsonify([dict(log) for log in logs])

@app.route('/api/admin/activity-logs/export')
@admin_required
def export_activity_logs():
    db = get_db()
    
    # Get filters from query params
    action = request.args.get('action')
    date_from = request.args.get('dateFrom')
    date_to = request.args.get('dateTo')
    user_id = request.args.get('userId')
    
    # Build query
    query = '''
        SELECT al.*, a.username 
        FROM activity_logs al
        JOIN admins a ON al.admin_id = a.id
        WHERE 1=1
    '''
    params = []
    
    if action:
        query += ' AND al.action = ?'
        params.append(action)
        
    if date_from:
        query += ' AND DATE(al.timestamp) >= ?'
        params.append(date_from)
        
    if date_to:
        query += ' AND DATE(al.timestamp) <= ?'
        params.append(date_to)
        
    if user_id:
        query += ' AND al.admin_id = ?'
        params.append(user_id)
        
    query += ' ORDER BY al.timestamp DESC'
    
    logs = db.execute(query, params).fetchall()
    
    # Generate CSV
    import csv
    from io import StringIO
    
    output = StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['Usuario', 'Acción', 'Detalles', 'Dirección IP', 'Fecha'])
    
    # Write data
    for log in logs:
        writer.writerow([
            log['username'],
            log['action'],
            log['details'] or '',
            log['ip_address'],
            log['timestamp']
        ])
    
    from flask import make_response
    response = make_response(output.getvalue())
    response.headers['Content-Disposition'] = 'attachment; filename=registros_actividad.csv'
    response.headers['Content-type'] = 'text/csv'
    return response

# Add secret key for sessions
app.secret_key = os.urandom(24)

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=8000, debug=True)
