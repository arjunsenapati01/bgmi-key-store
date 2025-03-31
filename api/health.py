from http.server import BaseHTTPRequestHandler
import json
from datetime import datetime

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        print("Health check endpoint accessed")  # Debug log
        response = {
            'status': 'ok',
            'timestamp': datetime.utcnow().isoformat(),
            'message': 'Health check endpoint is working'
        }
        
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(response).encode()) 