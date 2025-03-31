from http.server import BaseHTTPRequestHandler
from app import app
import json

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

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        print(f"Received GET request: {self.path}")  # Debug log
        try:
            with app.request_context(self):
                response = app.handle_request()
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(response.get_data())
        except Exception as e:
            print(f"Error handling request: {str(e)}")  # Debug log
            self.send_response(500)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({
                'error': str(e),
                'status': 'error'
            }).encode()) 