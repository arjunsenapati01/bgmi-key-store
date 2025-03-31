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

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')

# MongoDB Configuration
app.config['MONGO_URI'] = os.getenv('MONGODB_URI', 'mongodb+srv://your-username:your-password@your-cluster.mongodb.net/bgmi_keys?retryWrites=true&w=majority')
mongo = PyMongo(app)

# Configure upload folder
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Add session configuration
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_TYPE'] = 'filesystem'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data['_id'])
        self.username = user_data['username']
        self.password_hash = user_data['password_hash']
        self.is_admin = user_data.get('is_admin', False)

@login_manager.user_loader
def load_user(user_id):
    user_data = mongo.db.users.find_one({'_id': ObjectId(user_id)})
    if user_data:
        return User(user_data)
    return None

def init_db():
    try:
        print("Initializing database...")
        
        # Create indexes
        mongo.db.users.create_index('username', unique=True)
        mongo.db.serial_keys.create_index('key', unique=True)
        mongo.db.purchases.create_index([('user_id', 1), ('serial_key_id', 1)])
        
        # Create admin user if not exists
        admin = mongo.db.users.find_one({'username': 'admin'})
        if not admin:
            print("Creating admin user...")
            admin_user = {
                'username': 'admin',
                'password_hash': generate_password_hash('admin123'),
                'is_admin': True
            }
            mongo.db.users.insert_one(admin_user)
            print("Admin user created successfully!")
        else:
            print("Admin user already exists")
            
    except Exception as e:
        print(f"Error initializing database: {str(e)}")
        print(f"Traceback: {traceback.format_exc()}")

# Call init_db when the app starts
init_db()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            password = request.form.get('password')
            
            print(f"Attempting to register user: {username}")
            
            if not username or not password:
                print("Missing username or password")
                flash('Please provide both username and password', 'error')
                return redirect(url_for('register'))
            
            # Check if user exists
            existing_user = mongo.db.users.find_one({'username': username})
            if existing_user:
                print(f"Username already exists: {username}")
                flash('Username already exists', 'error')
                return redirect(url_for('register'))
            
            # Create new user
            print(f"Creating new user: {username}")
            new_user = {
                'username': username,
                'password_hash': generate_password_hash(password),
                'is_admin': False
            }
            
            try:
                result = mongo.db.users.insert_one(new_user)
                print(f"User {username} created successfully with ID: {result.inserted_id}")
                
                # Verify user was created
                verify_user = mongo.db.users.find_one({'_id': result.inserted_id})
                if verify_user:
                    print(f"User verified in database: {verify_user['username']}, ID: {verify_user['_id']}")
                    flash('Registration successful! Please login.', 'success')
                    return redirect(url_for('login'))
                else:
                    print("User not found after creation")
                    flash('Error creating user. Please try again.', 'error')
                    return redirect(url_for('register'))
                    
            except Exception as db_error:
                print(f"Database error during registration: {str(db_error)}")
                print(f"Traceback: {traceback.format_exc()}")
                flash('Error creating user. Please try again.', 'error')
                return redirect(url_for('register'))
                
        except Exception as e:
            print(f"General error during registration: {str(e)}")
            print(f"Traceback: {traceback.format_exc()}")
            flash('Error during registration. Please try again.', 'error')
            return redirect(url_for('register'))
            
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            password = request.form.get('password')
            
            print(f"Login attempt for user: {username}")
            
            if not username or not password:
                print("Missing username or password")
                flash('Please provide both username and password', 'error')
                return redirect(url_for('login'))
            
            # Get user from database
            user_data = mongo.db.users.find_one({'username': username})
            
            if not user_data:
                print(f"User not found: {username}")
                flash('Invalid username or password', 'error')
                return redirect(url_for('login'))
            
            print(f"User found: {user_data['username']}, ID: {user_data['_id']}")
            
            # Verify password
            if check_password_hash(user_data['password_hash'], password):
                print(f"Password verified for user: {username}")
                # Set session as permanent
                session.permanent = True
                login_user(User(user_data))
                flash('Logged in successfully!', 'success')
                return redirect(url_for('dashboard'))
            else:
                print(f"Invalid password for user: {username}")
                flash('Invalid username or password', 'error')
                return redirect(url_for('login'))
                
        except Exception as e:
            print(f"Error during login: {str(e)}")
            print(f"Traceback: {traceback.format_exc()}")
            flash('Error during login. Please try again.', 'error')
            return redirect(url_for('login'))
            
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Get user's purchases
    user_purchases = list(mongo.db.purchases.find({'user_id': current_user.id}))
    
    # Get available keys
    available_keys = list(mongo.db.serial_keys.find({'is_used': False}))
    
    # Get pending purchases
    pending_purchases = list(mongo.db.purchases.find({
        'user_id': current_user.id,
        'status': 'pending'
    }))
    
    return render_template('user_dashboard.html',
                         purchases=user_purchases,
                         available_keys=available_keys,
                         pending_purchases=pending_purchases)

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    # Get all purchases
    purchases = list(mongo.db.purchases.find())
    
    # Get all keys
    keys = list(mongo.db.serial_keys.find())
    
    # Get pending purchases
    pending_purchases = list(mongo.db.purchases.find({'status': 'pending'}))
    
    # Get rejected purchases
    rejected_purchases = list(mongo.db.purchases.find({'status': 'rejected'}))
    
    return render_template('admin_dashboard.html',
                         purchases=purchases,
                         keys=keys,
                         pending_purchases=pending_purchases,
                         rejected_purchases=rejected_purchases)

@app.route('/admin/add_key', methods=['POST'])
@admin_required
def add_key():
    try:
        key = request.form.get('key')
        price = float(request.form.get('price'))
        
        if not key or price <= 0:
            flash('Please provide valid key and price', 'error')
            return redirect(url_for('admin_dashboard'))
        
        # Check if key already exists
        existing_key = mongo.db.serial_keys.find_one({'key': key})
        if existing_key:
            flash('Key already exists', 'error')
            return redirect(url_for('admin_dashboard'))
        
        # Add new key
        new_key = {
            'key': key,
            'price': price,
            'is_used': False
        }
        mongo.db.serial_keys.insert_one(new_key)
        
        flash('Key added successfully!', 'success')
    except Exception as e:
        print(f"Error adding key: {str(e)}")
        flash('Error adding key', 'error')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/approve_purchase/<purchase_id>')
@admin_required
def approve_purchase(purchase_id):
    try:
        purchase = mongo.db.purchases.find_one({'_id': ObjectId(purchase_id)})
        if not purchase:
            flash('Purchase not found', 'error')
            return redirect(url_for('admin_dashboard'))
        
        # Update purchase status
        mongo.db.purchases.update_one(
            {'_id': ObjectId(purchase_id)},
            {'$set': {'status': 'approved'}}
        )
        
        # Mark key as used
        mongo.db.serial_keys.update_one(
            {'_id': purchase['serial_key_id']},
            {'$set': {'is_used': True}}
        )
        
        flash('Purchase approved successfully!', 'success')
    except Exception as e:
        print(f"Error approving purchase: {str(e)}")
        flash('Error approving purchase', 'error')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reject_purchase/<purchase_id>')
@admin_required
def reject_purchase(purchase_id):
    try:
        purchase = mongo.db.purchases.find_one({'_id': ObjectId(purchase_id)})
        if not purchase:
            flash('Purchase not found', 'error')
            return redirect(url_for('admin_dashboard'))
        
        # Update purchase status
        mongo.db.purchases.update_one(
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
        
        print(f"Processing payment - Key ID: {key_id}, UTR: {utr_number}")
        
        if not key_id or not utr_number:
            print("Missing key_id or utr_number")
            flash('Please provide both key ID and UTR number.', 'danger')
            return redirect(url_for('dashboard'))
        
        # Get the key
        key = mongo.db.serial_keys.find_one({'_id': ObjectId(key_id)})
        if not key:
            print(f"Key not found: {key_id}")
            flash('Key not found.', 'danger')
            return redirect(url_for('dashboard'))
            
        if key['is_used']:
            print(f"Key already used: {key_id}")
            flash('This key has already been used.', 'danger')
            return redirect(url_for('dashboard'))
        
        # Check if user already has a pending purchase for this key
        existing_purchase = mongo.db.purchases.find_one({
            'user_id': current_user.id,
            'serial_key_id': ObjectId(key_id),
            'status': 'pending'
        })
        
        if existing_purchase:
            print(f"User already has pending purchase for key: {key_id}")
            flash('You already have a pending purchase for this key.', 'danger')
            return redirect(url_for('dashboard'))
        
        # Create a new purchase
        purchase = {
            'user_id': current_user.id,
            'serial_key_id': ObjectId(key_id),
            'utr_number': utr_number,
            'status': 'pending'
        }
        
        print(f"Creating purchase - User: {current_user.id}, Key: {key_id}")
        
        try:
            mongo.db.purchases.insert_one(purchase)
            print("Purchase created successfully")
            flash('Payment details submitted successfully. Please wait for admin approval.', 'success')
        except Exception as db_error:
            print(f"Database error: {str(db_error)}")
            print(f"Traceback: {traceback.format_exc()}")
            flash('Error saving payment details. Please try again.', 'danger')
            return redirect(url_for('dashboard'))
            
    except Exception as e:
        print(f"General error in process_payment: {str(e)}")
        print(f"Traceback: {traceback.format_exc()}")
        flash('Error processing payment. Please try again.', 'danger')
    
    return redirect(url_for('dashboard'))

@app.route('/admin/change_password', methods=['POST'])
@admin_required
def change_admin_password():
    try:
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if not all([current_password, new_password, confirm_password]):
            return jsonify({'success': False, 'message': 'All fields are required'})
        
        if new_password != confirm_password:
            return jsonify({'success': False, 'message': 'New passwords do not match'})
        
        # Get admin user
        admin = mongo.db.users.find_one({'username': 'admin'})
        if not admin:
            return jsonify({'success': False, 'message': 'Admin user not found'})
        
        # Verify current password
        if not check_password_hash(admin['password_hash'], current_password):
            return jsonify({'success': False, 'message': 'Current password is incorrect'})
        
        # Update password
        mongo.db.users.update_one(
            {'username': 'admin'},
            {'$set': {'password_hash': generate_password_hash(new_password)}}
        )
        
        return jsonify({'success': True, 'message': 'Password updated successfully'})
        
    except Exception as e:
        print(f"Error changing admin password: {str(e)}")
        return jsonify({'success': False, 'message': 'Error updating password'})

if __name__ == '__main__':
    app.run(debug=True) 