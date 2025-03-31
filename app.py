from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import csv
from io import StringIO
import json
import tempfile
import traceback
import os
from dotenv import load_dotenv
from flask_pymongo import PyMongo
from bson import ObjectId
from pymongo import MongoClient

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'bgmi-key-store-secret-key-2024')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)  # Set session lifetime to 7 days

# MongoDB Configuration
MONGODB_URI = os.getenv('MONGODB_URI', 'mongodb+srv://arjunsenapati01:D5M1tf3tjfY6uzB5@bgmikey.njscwi5.mongodb.net/bgmi_keys?retryWrites=true&w=majority')
client = None
db = None

def get_db():
    global client, db
    try:
        if client is None:
            print("Connecting to MongoDB Atlas...")
            client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=5000)
            # Test the connection
            client.server_info()
            db = client.bgmi_keys
            print("Successfully connected to MongoDB Atlas!")
        return db
    except Exception as e:
        print(f"Error connecting to MongoDB: {str(e)}")
        raise

def init_db():
    try:
        db = get_db()
        print("Initializing database...")
        
        # Create indexes
        db.users.create_index([("email", 1)], unique=True)
        db.serial_keys.create_index([("key", 1)], unique=True)
        db.purchases.create_index([("user_id", 1)])
        db.purchases.create_index([("serial_key_id", 1)])
        print("Database indexes created successfully")
        
        # Create admin user if not exists
        admin = db.users.find_one({"email": "admin@example.com"})
        if not admin:
            print("Creating admin user...")
            admin_user = {
                "email": "admin@example.com",
                "password": generate_password_hash("admin123"),
                "is_admin": True,
                "created_at": datetime.utcnow()
            }
            db.users.insert_one(admin_user)
            print("Admin user created successfully")
        
        print("Database initialization completed successfully")
    except Exception as e:
        print(f"Error initializing database: {str(e)}")
        raise

# Add Vercel serverless function handler
def handler(request):
    """Handle incoming requests for Vercel serverless functions."""
    print(f"Received request: {request.method} {request.path}")  # Debug log
    
    with app.request_context(request):
        try:
            response = app.handle_request()
            return response
        except Exception as e:
            print(f"Error handling request: {str(e)}")  # Debug log
            return jsonify({
                'error': str(e),
                'status': 'error'
            }), 500

# Add a simple health check route
@app.route('/health')
def health_check():
    print("Health check route accessed")  # Debug log
    return jsonify({
        'status': 'ok',
        'timestamp': datetime.utcnow().isoformat(),
        'message': 'Health check endpoint is working'
    })

@app.route('/test_db')
def test_db():
    print("Test route accessed")  # Debug log
    try:
        print("Attempting to connect to MongoDB...")  # Debug log
        # Try to connect to MongoDB
        db = get_db()
        
        print("Creating test document...")  # Debug log
        # Try to insert a test document
        test_doc = {
            'test': True,
            'timestamp': datetime.utcnow(),
            'connection_string': MONGODB_URI  # Add connection string for debugging
        }
        result = db.test_collection.insert_one(test_doc)
        print(f"Test document inserted with ID: {result.inserted_id}")  # Debug log
        
        # Try to read it back
        test_doc = db.test_collection.find_one({'_id': result.inserted_id})
        print("Test document retrieved successfully")  # Debug log
        
        # Clean up
        db.test_collection.delete_one({'_id': result.inserted_id})
        print("Test document cleaned up")  # Debug log
        
        return jsonify({
            'success': True,
            'message': 'Successfully connected to MongoDB Atlas!',
            'database': 'bgmi_keys',
            'test_document': str(test_doc),
            'connection_status': 'connected'
        })
    except Exception as e:
        print(f"Database connection test failed: {str(e)}")  # Debug log
        print(f"Full traceback: {traceback.format_exc()}")  # Debug log
        return jsonify({
            'success': False,
            'message': f'Failed to connect to MongoDB: {str(e)}',
            'connection_status': 'failed',
            'error_details': str(e)
        }), 500

# Initialize database
init_db()

app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data['_id'])
        self.email = user_data['email']
        self.is_admin = user_data.get('is_admin', False)

@login_manager.user_loader
def load_user(user_id):
    user_data = get_db().users.find_one({'_id': ObjectId(user_id)})
    if user_data:
        return User(user_data)
    return None

@app.route('/')
def index():
    return jsonify({
        'status': 'ok',
        'message': 'BGMI Key Store API is running',
        'endpoints': {
            'health': '/health',
            'test_db': '/test_db'
        }
    })

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            email = request.form.get('email')
            password = request.form.get('password')
            
            print(f"Attempting to register user: {email}")
            
            # Check if user already exists
            db = get_db()
            existing_user = db.users.find_one({"email": email})
            if existing_user:
                print(f"User already exists: {email}")
                flash('Email already registered.', 'danger')
                return redirect(url_for('register'))
            
            # Create new user
            user = {
                "email": email,
                "password": generate_password_hash(password),
                "is_admin": False,
                "created_at": datetime.utcnow()
            }
            
            result = db.users.insert_one(user)
            print(f"User registered successfully with ID: {result.inserted_id}")
            
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            print(f"Error during registration: {str(e)}")
            flash('Error during registration. Please try again.', 'danger')
            return redirect(url_for('register'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            email = request.form.get('email')
            password = request.form.get('password')
            
            print(f"Attempting login for user: {email}")
            
            db = get_db()
            user = db.users.find_one({"email": email})
            
            if user and check_password_hash(user['password'], password):
                print(f"Login successful for user: {email}")
                user_obj = User(user)
                login_user(user_obj)
                return redirect(url_for('dashboard'))
            else:
                print(f"Login failed for user: {email}")
                flash('Invalid email or password.', 'danger')
                return redirect(url_for('login'))
                
        except Exception as e:
            print(f"Error during login: {str(e)}")
            flash('Error during login. Please try again.', 'danger')
            return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Get user's purchases
    user_purchases = list(get_db().purchases.find({'user_id': current_user.id}))
    
    # Get available keys
    available_keys = list(get_db().serial_keys.find({'is_used': False}))
    
    # Get pending purchases
    pending_purchases = list(get_db().purchases.find({
        'user_id': current_user.id,
        'status': 'pending'
    }))
    
    return render_template('dashboard.html',
                         user_purchases=user_purchases,
                         available_keys=available_keys,
                         pending_purchases=pending_purchases)

@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get all purchases
    purchases = list(get_db().purchases.find())
    
    # Get all keys
    keys = list(get_db().serial_keys.find())
    
    # Get pending purchases
    pending_purchases = list(get_db().purchases.find({'status': 'pending'}))
    
    # Get rejected purchases
    rejected_purchases = list(get_db().purchases.find({'status': 'rejected'}))
    
    return render_template('admin_dashboard.html',
                         purchases=purchases,
                         keys=keys,
                         pending_purchases=pending_purchases,
                         rejected_purchases=rejected_purchases)

@app.route('/admin/add_key', methods=['POST'])
@login_required
def add_key():
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Access denied'})
    
    try:
        key = request.form.get('key')
        if not key:
            return jsonify({'success': False, 'message': 'Key is required'})
        
        # Check if key already exists
        existing_key = get_db().serial_keys.find_one({'key': key})
        if existing_key:
            return jsonify({'success': False, 'message': 'Key already exists'})
        
        # Add new key
        new_key = {
            'key': key,
            'is_used': False,
            'created_at': datetime.utcnow()
        }
        get_db().serial_keys.insert_one(new_key)
        
        return jsonify({'success': True, 'message': 'Key added successfully'})
    except Exception as e:
        print(f"Error adding key: {str(e)}")
        return jsonify({'success': False, 'message': 'Error adding key'})

@app.route('/admin/approve_purchase/<purchase_id>')
@login_required
def approve_purchase(purchase_id):
    if not current_user.is_admin:
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))
    
    try:
        purchase = get_db().purchases.find_one({'_id': ObjectId(purchase_id)})
        if not purchase:
            flash('Purchase not found', 'error')
            return redirect(url_for('admin_dashboard'))
        
        # Update purchase status
        get_db().purchases.update_one(
            {'_id': ObjectId(purchase_id)},
            {'$set': {'status': 'approved'}}
        )
        
        # Mark key as used
        get_db().serial_keys.update_one(
            {'_id': purchase['serial_key_id']},
            {'$set': {'is_used': True}}
        )
        
        flash('Purchase approved successfully!', 'success')
    except Exception as e:
        print(f"Error approving purchase: {str(e)}")
        flash('Error approving purchase', 'error')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reject_purchase/<purchase_id>')
@login_required
def reject_purchase(purchase_id):
    if not current_user.is_admin:
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))
    
    try:
        purchase = get_db().purchases.find_one({'_id': ObjectId(purchase_id)})
        if not purchase:
            flash('Purchase not found', 'error')
            return redirect(url_for('admin_dashboard'))
        
        # Update purchase status
        get_db().purchases.update_one(
            {'_id': ObjectId(purchase_id)},
            {'$set': {'status': 'rejected'}}
        )
        
        flash('Purchase rejected successfully!', 'success')
    except Exception as e:
        print(f"Error rejecting purchase: {str(e)}")
        flash('Error rejecting purchase', 'error')
    
    return redirect(url_for('admin_dashboard'))

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
        key = get_db().serial_keys.find_one({'_id': ObjectId(key_id)})
        if not key:
            print(f"Key not found: {key_id}")  # Debug log
            flash('Key not found.', 'danger')
            return redirect(url_for('dashboard'))
            
        if key['is_used']:
            print(f"Key already used: {key_id}")  # Debug log
            flash('This key has already been used.', 'danger')
            return redirect(url_for('dashboard'))
        
        # Check if user already has a pending purchase for this key
        existing_purchase = get_db().purchases.find_one({
            'user_id': current_user.id,
            'serial_key_id': ObjectId(key_id),
            'status': 'pending'
        })
        
        if existing_purchase:
            print(f"User already has a pending purchase for key: {key_id}")  # Debug log
            flash('You already have a pending purchase for this key.', 'danger')
            return redirect(url_for('dashboard'))
        
        # Create a new purchase
        purchase = {
            'user_id': current_user.id,
            'serial_key_id': ObjectId(key_id),
            'utr_number': utr_number,
            'status': 'pending',
            'created_at': datetime.utcnow()
        }
        
        print(f"Creating purchase - User: {current_user.id}, Key: {key_id}")  # Debug log
        
        try:
            get_db().purchases.insert_one(purchase)
            print("Purchase created successfully")  # Debug log
            flash('Payment details submitted successfully. Please wait for admin approval.', 'success')
        except Exception as db_error:
            print(f"Database error: {str(db_error)}")  # Debug log
            flash('Error saving payment details. Please try again.', 'danger')
            return redirect(url_for('dashboard'))
            
    except Exception as e:
        print(f"General error in process_payment: {str(e)}")  # Debug log
        flash('Error processing payment. Please try again.', 'danger')
    
    return redirect(url_for('dashboard'))

@app.route('/admin/change_password', methods=['POST'])
@login_required
def change_password():
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Access denied'})
    
    try:
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        
        # Get admin user
        admin = get_db().users.find_one({'email': 'admin@example.com'})
        if not admin:
            return jsonify({'success': False, 'message': 'Admin user not found'})
        
        # Verify current password
        if not check_password_hash(admin['password'], current_password):
            return jsonify({'success': False, 'message': 'Current password is incorrect'})
        
        # Update password
        get_db().users.update_one(
            {'email': 'admin@example.com'},
            {'$set': {'password': generate_password_hash(new_password)}}
        )
        
        return jsonify({'success': True, 'message': 'Password updated successfully'})
    except Exception as e:
        print(f"Error changing password: {str(e)}")
        return jsonify({'success': False, 'message': 'Error changing password'})

if __name__ == '__main__':
    app.run(debug=True)
else:
    # For Vercel serverless functions
    app = app 