from flask import Flask, request, jsonify, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
import os
import pymysql
import requests

app = Flask(__name__)

# Configurations
app.config['SECRET_KEY'] = 'secret_key'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAIL_SERVER'] = 'smtp.example.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'op@gmail.com'
app.config['MAIL_PASSWORD'] = 'op_user'
app.config['MAIL_USE_TLS'] = True

db_connection = pymysql.connect(
    host='localhost',
    user='root',
    password='sumi0407',
    database='file_sharing'
)
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Helper functions
def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'pptx', 'docx', 'xlsx'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def send_verification_email(user_email):
    token = serializer.dumps(user_email, salt='email-confirm')
    verify_url = f"http://localhost:5000/verify/{token}"
    msg = Message('Verify Your Email', sender=app.config['MAIL_USERNAME'], recipients=[user_email])
    msg.body = f"Click the link to verify your email: {verify_url}"
    mail.send(msg)

# Routes
@app.route('/signup', methods=['GET','POST'])
def signup():
    data = request.get_json()
    email = data.get('email')
    password = generate_password_hash(data.get('password'))
    role = 'client'
    print("Content-Type:", request.content_type)
    print("Raw Request Data:", request.data)
    response = requests.post("http://localhost:5000/signup", json=data)

    try:
        with db_connection.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            if cursor.fetchone():
                return jsonify({'message': 'Email already exists.'}), 400

            cursor.execute(
                "INSERT INTO users (email, password, role, verified) VALUES (%s, %s, %s, %s)",
                (email, password, role, False)
            )
            db_connection.commit()

        send_verification_email(email)
        token = serializer.dumps(email, salt='email-confirm')
        return jsonify({'message': 'User created. Please verify your email.', 'encrypted_url': token}), 201
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/verify/<token>', methods=['GET'])
def verify_email(token):
    try:
        email = serializer.loads(token, salt='email-confirm', max_age=3600)
        with db_connection.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()
            if user:
                cursor.execute("UPDATE users SET verified = %s WHERE email = %s", (True, email))
                db_connection.commit()
                return jsonify({'message': 'Email verified successfully.'}), 200
            return jsonify({'message': 'User not found.'}), 404
    except Exception as e:
        return jsonify({'message': 'The token is invalid or has expired.'}), 400

@app.route('/login', methods=['GET','POST'])
def login():
    data = request.json
    email = data['email']
    password = data['password']

    try:
        with db_connection.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()

            if not user or not check_password_hash(user[2], password):
                return jsonify({'message': 'Invalid email or password.'}), 401

            if not user[4]:
                return jsonify({'message': 'Email not verified.'}), 403

            return jsonify({'message': 'Login successful.', 'role': user[3]}), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/upload', methods=['POST'])
def upload_file():
    user_email = request.headers.get('User-Email')

    try:
        with db_connection.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE email = %s", (user_email,))
            user = cursor.fetchone()

            if not user or user[3] != 'ops':
                return jsonify({'message': 'Unauthorized action.'}), 403

            if 'file' not in request.files:
                return jsonify({'message': 'No file part.'}), 400

            file = request.files['file']
            if file.filename == '':
                return jsonify({'message': 'No file selected.'}), 400

            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)

                cursor.execute(
                    "INSERT INTO files (filename, uploaded_by) VALUES (%s, %s)",
                    (filename, user[0])
                )
                db_connection.commit()

                return jsonify({'message': 'File uploaded successfully.'}), 201
            return jsonify({'message': 'Invalid file type.'}), 400
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/files', methods=['GET'])
def list_files():
    try:
        with db_connection.cursor() as cursor:
            cursor.execute("SELECT * FROM files")
            files = cursor.fetchall()
            file_list = [{'id': f[0], 'filename': f[1]} for f in files]
            return jsonify({'files': file_list}), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/download/<int:file_id>', methods=['GET'])
def download_file(file_id):
    try:
        with db_connection.cursor() as cursor:
            cursor.execute("SELECT * FROM files WHERE id = %s", (file_id,))
            file = cursor.fetchone()

            if not file:
                return jsonify({'message': 'File not found.'}), 404

            filepath = os.path.join(app.config['UPLOAD_FOLDER'], file[1])
            if not os.path.exists(filepath):
                return jsonify({'message': 'File not available.'}), 404

            return send_file(filepath, as_attachment=True)
    except Exception as e:
        return jsonify({'message': str(e)}), 500

if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    app.run(debug=True)
