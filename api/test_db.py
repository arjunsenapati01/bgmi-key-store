from http.server import BaseHTTPRequestHandler
from app import app, get_db
import json
from datetime import datetime

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        print("Database test endpoint accessed")  # Debug log
        try:
            print("Attempting to connect to MongoDB...")  # Debug log
            # Try to connect to MongoDB
            db = get_db()
            
            print("Creating test document...")  # Debug log
            # Try to insert a test document
            test_doc = {
                'test': True,
                'timestamp': datetime.utcnow(),
                'connection_string': app.config.get('MONGODB_URI', 'not set')
            }
            result = db.test_collection.insert_one(test_doc)
            print(f"Test document inserted with ID: {result.inserted_id}")  # Debug log
            
            # Try to read it back
            test_doc = db.test_collection.find_one({'_id': result.inserted_id})
            print("Test document retrieved successfully")  # Debug log
            
            # Clean up
            db.test_collection.delete_one({'_id': result.inserted_id})
            print("Test document cleaned up")  # Debug log
            
            response = {
                'success': True,
                'message': 'Successfully connected to MongoDB Atlas!',
                'database': 'bgmi_keys',
                'test_document': str(test_doc),
                'connection_status': 'connected'
            }
            status_code = 200
        except Exception as e:
            print(f"Database connection test failed: {str(e)}")  # Debug log
            response = {
                'success': False,
                'message': f'Failed to connect to MongoDB: {str(e)}',
                'connection_status': 'failed',
                'error_details': str(e)
            }
            status_code = 500
        
        self.send_response(status_code)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(response).encode()) 