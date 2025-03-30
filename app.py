from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import csv
from io import StringIO
import json
import tempfile
import traceback
from flask import session

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'

# Configure SQLAlchemy for Vercel
if os.environ.get('VERCEL_ENV') == 'production':
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
        'pool_size': 5,
        'connect_args': {'check_same_thread': False}
    }
    # Use temporary directory for uploads in Vercel
    app.config['UPLOAD_FOLDER'] = tempfile.gettempdir()
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///bgmi_keys.db'
    app.config['UPLOAD_FOLDER'] = 'uploads'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Add session configuration
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)  # Session lasts for 7 days
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookie over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to session cookie
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Protect against CSRF
app.config['SESSION_TYPE'] = 'filesystem'  # Use filesystem for session storage

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Key Categories and Durations
KEY_CATEGORIES = ['Lethal', 'Win iOS', 'Vision']
KEY_DURATIONS = {
    '1_day': {'name': '1 Day', 'days': 1},
    '7_days': {'name': '7 Days', 'days': 7},
    '30_days': {'name': '30 Days', 'days': 30}
}

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    registration_date = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())
    purchases = db.relationship('Purchase', backref='user', lazy=True)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

class SerialKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)
    is_used = db.Column(db.Boolean, default=False)
    price = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(20), nullable=False)
    duration = db.Column(db.String(10), nullable=False)  # '1_day', '7_days', '30_days'
    purchases = db.relationship('Purchase', backref='serial_key', lazy=True)

class Purchase(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    serial_key_id = db.Column(db.Integer, db.ForeignKey('serial_key.id'), nullable=False)
    purchase_date = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())
    utr_number = db.Column(db.String(50))
    status = db.Column(db.String(20), default='pending')
    rejection_reason = db.Column(db.String(255))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            password = request.form.get('password')
            
            print(f"Login attempt for user: {username}")  # Debug log
            
            if not username or not password:
                print("Missing username or password")  # Debug log
                flash('Please provide both username and password', 'error')
                return redirect(url_for('login'))
            
            user = User.query.filter_by(username=username).first()
            
            if not user:
                print(f"User not found: {username}")  # Debug log
                flash('Invalid username or password', 'error')
                return redirect(url_for('login'))
            
            if check_password_hash(user.password_hash, password):
                print(f"Login successful for user: {username}")  # Debug log
                login_user(user)
                flash('Logged in successfully!', 'success')
                return redirect(url_for('dashboard'))
            else:
                print(f"Invalid password for user: {username}")  # Debug log
                flash('Invalid username or password', 'error')
                return redirect(url_for('login'))
                
        except Exception as e:
            print(f"Error during login: {str(e)}")  # Debug log
            flash('Error during login. Please try again.', 'error')
            return redirect(url_for('login'))
            
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            password = request.form.get('password')
            
            print(f"Attempting to register user: {username}")  # Debug log
            
            if not username or not password:
                print("Missing username or password")  # Debug log
                flash('Please provide both username and password', 'error')
                return redirect(url_for('register'))
            
            # Check if user exists
            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                print(f"Username already exists: {username}")  # Debug log
                flash('Username already exists', 'error')
                return redirect(url_for('register'))
            
            # Create new user
            print(f"Creating new user: {username}")  # Debug log
            new_user = User(
                username=username,
                password_hash=generate_password_hash(password),
                is_admin=False
            )
            
            try:
                db.session.add(new_user)
                db.session.commit()
                print(f"User {username} created successfully with ID: {new_user.id}")  # Debug log
                
                # Verify user was created
                verify_user = User.query.filter_by(username=username).first()
                if verify_user:
                    print(f"User verified in database: {verify_user.username}, ID: {verify_user.id}")  # Debug log
                    flash('Registration successful! Please login.', 'success')
                    return redirect(url_for('login'))
                else:
                    print("User not found after creation")  # Debug log
                    flash('Error creating user. Please try again.', 'error')
                    return redirect(url_for('register'))
                    
            except Exception as db_error:
                print(f"Database error during registration: {str(db_error)}")  # Debug log
                print(f"Traceback: {traceback.format_exc()}")  # Print full traceback
                db.session.rollback()
                flash('Error creating user. Please try again.', 'error')
                return redirect(url_for('register'))
                
        except Exception as e:
            print(f"General error during registration: {str(e)}")  # Debug log
            print(f"Traceback: {traceback.format_exc()}")  # Print full traceback
            flash('Error during registration. Please try again.', 'error')
            return redirect(url_for('register'))
            
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        if current_user.is_admin:
            keys = SerialKey.query.all()
            pending_purchases = Purchase.query.filter_by(status='pending').all()
            users = User.query.all()  # Get all users for admin dashboard
            return render_template('admin_dashboard.html', 
                                 keys=keys, 
                                 categories=KEY_CATEGORIES, 
                                 durations=KEY_DURATIONS,
                                 pending_purchases=pending_purchases,
                                 users=users)  # Pass users to template
        else:
            # Get available keys by category and duration
            categories = {}
            for category in KEY_CATEGORIES:
                categories[category] = {}
                for duration_key, duration_info in KEY_DURATIONS.items():
                    keys = SerialKey.query.filter_by(
                        category=category,
                        duration=duration_key,
                        is_used=False
                    ).all()
                    categories[category][duration_key] = keys
            
            # Get user's purchased keys
            purchased_keys = SerialKey.query.join(Purchase).filter(
                Purchase.user_id == current_user.id,
                Purchase.status == 'approved'
            ).order_by(Purchase.purchase_date.desc()).all()
            
            # Get user's pending purchases
            pending_purchases = Purchase.query.filter_by(
                user_id=current_user.id,
                status='pending'
            ).order_by(Purchase.purchase_date.desc()).all()
            
            # Get user's rejected purchases
            rejected_purchases = Purchase.query.filter_by(
                user_id=current_user.id,
                status='rejected'
            ).order_by(Purchase.purchase_date.desc()).all()
            
            return render_template('user_dashboard.html', 
                                 categories=categories, 
                                 durations=KEY_DURATIONS,
                                 purchased_keys=purchased_keys,
                                 pending_purchases=pending_purchases,
                                 rejected_purchases=rejected_purchases)
    except Exception as e:
        flash(f'Error accessing dashboard: {str(e)}', 'error')
        return redirect(url_for('login'))

@app.route('/admin/add_key', methods=['POST'])
@login_required
def add_key():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    key = request.form.get('key')
    price = float(request.form.get('price'))
    category = request.form.get('category')
    duration = request.form.get('duration')
    
    if len(key) > 50:
        return jsonify({'error': 'Key too long'}), 400
    
    if category not in KEY_CATEGORIES:
        return jsonify({'error': 'Invalid category'}), 400
    
    if duration not in KEY_DURATIONS:
        return jsonify({'error': 'Invalid duration'}), 400
        
    new_key = SerialKey(
        key=key,
        price=price,
        category=category,
        duration=duration
    )
    db.session.add(new_key)
    db.session.commit()
    return jsonify({'message': 'Key added successfully'})

@app.route('/admin/add_bulk_keys', methods=['POST'])
@login_required
def add_bulk_keys():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    keys_text = request.form.get('keys')
    price = float(request.form.get('price'))
    category = request.form.get('category')
    duration = request.form.get('duration')
    
    if category not in KEY_CATEGORIES:
        return jsonify({'error': 'Invalid category'}), 400
    
    if duration not in KEY_DURATIONS:
        return jsonify({'error': 'Invalid duration'}), 400
    
    keys_list = [k.strip() for k in keys_text.split('\n') if k.strip()]
    for key in keys_list:
        if len(key) > 50:
            continue
        new_key = SerialKey(
            key=key,
            price=price,
            category=category,
            duration=duration
        )
        db.session.add(new_key)
    
    db.session.commit()
    return jsonify({'message': f'Added {len(keys_list)} keys successfully'})

@app.route('/buy/<int:key_id>', methods=['POST'])
@login_required
def buy_key(key_id):
    data = request.get_json()
    utr_number = data.get('utrNumber')
    
    if not utr_number:
        return jsonify({'error': 'UTR number is required'}), 400
        
    serial_key = SerialKey.query.get_or_404(key_id)
    if serial_key.is_used:
        return jsonify({'error': 'Key already used'}), 400
        
    purchase = Purchase(
        user_id=current_user.id,
        serial_key_id=key_id,
        utr_number=utr_number,
        status='pending'
    )
    db.session.add(purchase)
    db.session.commit()
    
    return jsonify({
        'message': 'Purchase request submitted successfully',
        'purchase_id': purchase.id
    })

@app.route('/admin/approve_purchase/<int:purchase_id>', methods=['POST'])
@login_required
def approve_purchase(purchase_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
        
    purchase = Purchase.query.get_or_404(purchase_id)
    if purchase.status != 'pending':
        return jsonify({'error': 'Purchase is not pending'}), 400
        
    purchase.status = 'approved'
    purchase.serial_key.is_used = True
    db.session.commit()
    
    return jsonify({'message': 'Purchase approved successfully'})

@app.route('/admin/reject_purchase/<int:purchase_id>', methods=['POST'])
@login_required
def reject_purchase(purchase_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
        
    data = request.get_json()
    rejection_reason = data.get('rejectionReason')
    
    if not rejection_reason:
        return jsonify({'error': 'Rejection reason is required'}), 400
        
    purchase = Purchase.query.get_or_404(purchase_id)
    if purchase.status != 'pending':
        return jsonify({'error': 'Purchase is not pending'}), 400
        
    purchase.status = 'rejected'
    purchase.rejection_reason = rejection_reason
    db.session.commit()
    
    return jsonify({'message': 'Purchase rejected successfully'})

@app.route('/admin/user_purchases/<int:user_id>')
@login_required
def get_user_purchases(user_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
        
    user = User.query.get_or_404(user_id)
    purchases = Purchase.query.filter_by(user_id=user_id).order_by(Purchase.purchase_date.desc()).all()
    
    return jsonify({
        'purchases': [{
            'purchase_date': purchase.purchase_date.strftime('%Y-%m-%d %H:%M:%S'),
            'serial_key': {
                'category': purchase.serial_key.category,
                'duration': KEY_DURATIONS[purchase.serial_key.duration]['name'],
                'price': purchase.serial_key.price
            },
            'status': purchase.status
        } for purchase in purchases]
    })

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/admin/update_qr_code', methods=['POST'])
@login_required
def update_qr_code():
    if not current_user.is_admin:
        flash('Access denied.', 'danger')
        return redirect(url_for('index'))
    
    if 'qr_code' not in request.files:
        flash('No file selected.', 'danger')
        return redirect(url_for('dashboard'))
    
    file = request.files['qr_code']
    if file.filename == '':
        flash('No file selected.', 'danger')
        return redirect(url_for('dashboard'))
    
    if file and allowed_file(file.filename):
        filename = 'qr-code.jpg'
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        flash('QR code updated successfully.', 'success')
    else:
        flash('Invalid file type.', 'danger')
    
    return redirect(url_for('dashboard'))

@app.route('/process_payment', methods=['POST'])
@login_required
def process_payment():
    try:
        # Get form data
        key_id = request.form.get('key_id')
        utr_number = request.form.get('utr_number')
        
        print(f"Processing payment - Key ID: {key_id}, UTR: {utr_number}")  # Debug log
        
        if not key_id or not utr_number:
            print("Missing key_id or utr_number")  # Debug log
            flash('Please provide both key ID and UTR number.', 'danger')
            return redirect(url_for('dashboard'))
        
        # Get the key
        key = SerialKey.query.get(key_id)
        if not key:
            print(f"Key not found: {key_id}")  # Debug log
            flash('Key not found.', 'danger')
            return redirect(url_for('dashboard'))
            
        if key.is_used:
            print(f"Key already used: {key_id}")  # Debug log
            flash('This key has already been used.', 'danger')
            return redirect(url_for('dashboard'))
        
        # Check if user already has a pending purchase for this key
        existing_purchase = Purchase.query.filter_by(
            user_id=current_user.id,
            serial_key_id=key_id,
            status='pending'
        ).first()
        
        if existing_purchase:
            print(f"User already has pending purchase for key: {key_id}")  # Debug log
            flash('You already have a pending purchase for this key.', 'danger')
            return redirect(url_for('dashboard'))
        
        # Create a new purchase
        purchase = Purchase(
            user_id=current_user.id,
            serial_key_id=key.id,
            utr_number=utr_number,
            status='pending'
        )
        
        print(f"Creating purchase - User: {current_user.id}, Key: {key.id}")  # Debug log
        
        try:
            db.session.add(purchase)
            db.session.commit()
            print("Purchase created successfully")  # Debug log
            flash('Payment details submitted successfully. Please wait for admin approval.', 'success')
        except Exception as db_error:
            print(f"Database error: {str(db_error)}")  # Debug log
            print(f"Traceback: {traceback.format_exc()}")  # Print full traceback
            db.session.rollback()
            flash('Error saving payment details. Please try again.', 'danger')
            return redirect(url_for('dashboard'))
            
    except Exception as e:
        print(f"General error in process_payment: {str(e)}")  # Debug log
        print(f"Traceback: {traceback.format_exc()}")  # Print full traceback
        db.session.rollback()
        flash('Error processing payment. Please try again.', 'danger')
    
    return redirect(url_for('dashboard'))

@app.route('/admin/change_password', methods=['POST'])
@login_required
def change_admin_password():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    if not current_password or not new_password or not confirm_password:
        return jsonify({'error': 'All fields are required'}), 400
    
    if new_password != confirm_password:
        return jsonify({'error': 'New passwords do not match'}), 400
    
    # Get admin user
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        return jsonify({'error': 'Admin user not found'}), 404
    
    # Verify current password
    if not admin.check_password(current_password):
        return jsonify({'error': 'Current password is incorrect'}), 400
    
    # Update password
    admin.set_password(new_password)
    db.session.commit()
    
    return jsonify({'message': 'Password updated successfully'}), 200

# Initialize database and create admin user
def init_db():
    try:
        with app.app_context():
            print("Initializing database...")  # Debug log
            
            # Create all tables if they don't exist
            print("Creating all tables...")  # Debug log
            db.create_all()
            print("Database tables created")  # Debug log
            
            # Create admin user if not exists
            admin = User.query.filter_by(username='admin').first()
            if not admin:
                print("Creating admin user...")  # Debug log
                admin = User(
                    username='admin',
                    password_hash=generate_password_hash('admin123'),
                    is_admin=True
                )
                db.session.add(admin)
                db.session.commit()
                print("Admin user created successfully!")  # Debug log
            else:
                print("Admin user already exists")  # Debug log
                
            # Verify database state
            print("Verifying database state...")  # Debug log
            users = User.query.all()
            print(f"Total users in database: {len(users)}")  # Debug log
            for user in users:
                print(f"User: {user.username}, ID: {user.id}, Admin: {user.is_admin}")  # Debug log
                
    except Exception as e:
        print(f"Error initializing database: {str(e)}")  # Debug log
        print(f"Traceback: {traceback.format_exc()}")  # Print full traceback
        try:
            with app.app_context():
                print("Attempting to recover database...")  # Debug log
                db.create_all()
                admin = User(
                    username='admin',
                    password_hash=generate_password_hash('admin123'),
                    is_admin=True
                )
                db.session.add(admin)
                db.session.commit()
                print("Database recovered successfully")  # Debug log
        except Exception as recovery_error:
            print(f"Error recovering database: {str(recovery_error)}")  # Debug log
            print(f"Traceback: {traceback.format_exc()}")  # Print full traceback

# Call init_db when the app starts
init_db()

# For Vercel
app = app 