from flask import jsonify, session
import secrets
from email_config import SMTP_CONFIG
import smtplib
from email.mime.text import MIMEText

class VerificationHandler:
    def __init__(self, app, db_connector):
        self.app = app
        self.get_db_connection = db_connector
        self.setup_routes()

    def generate_code(self):
        return str(secrets.randbelow(1000000)).zfill(6)

    def send_email(self, email, code):
        try:
            msg = MIMEText(f'Su código de verificación es: {code}')
            msg['Subject'] = 'Verificación Alerta Vecinos'
            msg['From'] = SMTP_CONFIG['FROM']
            msg['To'] = email
            
            with smtplib.SMTP(SMTP_CONFIG['SERVER'], SMTP_CONFIG['PORT']) as server:
                server.starttls()
                server.login(SMTP_CONFIG['USERNAME'], SMTP_CONFIG['PASSWORD'])
                server.send_message(msg)
            return True
        except Exception as e:
            self.app.logger.error(f"Error enviando email: {str(e)}")
            return False

    def setup_routes(self):
        @self.app.route('/resend-code', methods=['POST'])
        def resend_code():
            if 'pending_user' not in session:
                return jsonify({'status': 'error', 'message': 'Solicitud inválida'}), 400
                
            with self.get_db_connection() as conn:
                user = conn.execute(
                    'SELECT email, phone FROM users WHERE id = ?',
                    (session['pending_user'],)
                ).fetchone()
                
            new_code = self.generate_code()
            session['verification_code'] = new_code
            
            if not self.send_email(user['email'], new_code):
                # Implementar fallback a SMS aquí
                pass
            
            return jsonify({
                'status': 'success',
                'message': 'Nuevo código enviado',
                'timer': 60
            })
