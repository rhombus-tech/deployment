#!/usr/bin/env python3
"""
Simple HTTP server for zkEVM demo playground
"""
import http.server
import socketserver
import webbrowser
import os
import sys
import json
import urllib.request
import urllib.error

PORT = 8888
DIRECTORY = "."
PROVING_SERVICE_URL = "http://localhost:3030"

class CustomHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)
    
    def end_headers(self):
        # Add CORS headers
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        super().end_headers()

    def do_GET(self):
        # Proxy requests to proving service
        if self.path.startswith('/api/proxy/'):
            # Extract the path after /api/proxy/
            proving_path = self.path[11:]  # Remove '/api/proxy'
            proving_url = f"{PROVING_SERVICE_URL}/{proving_path}"
            
            try:
                with urllib.request.urlopen(proving_url) as response:
                    data = response.read()
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.send_header('Access-Control-Allow-Origin', '*')
                    self.end_headers()
                    self.wfile.write(data)
            except urllib.error.URLError as e:
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                error_response = json.dumps({"error": str(e), "message": "Proving service unavailable"})
                self.wfile.write(error_response.encode())
        else:
            # Serve static files normally
            super().do_GET()

def main():
    # Change to the demo directory
    demo_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(demo_dir)
    
    # Create server
    with socketserver.TCPServer(("", PORT), CustomHTTPRequestHandler) as httpd:
        print(f"🚀 zkEVM Demo Server running at http://localhost:{PORT}")
        print(f"📁 Serving files from: {demo_dir}")
        print("🌐 Opening browser...")
        
        # Open browser automatically
        webbrowser.open(f'http://localhost:{PORT}')
        
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n🛑 Server stopped")
            sys.exit(0)

if __name__ == "__main__":
    main()
