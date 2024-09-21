import os
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime
import json
from urllib.parse import urlparse, parse_qs

hostName = "localhost"
serverPort = 3000
stats_file = "nibygotchi_stats.json"

client_stats = ["energy", "happiness", "fullness", "hi_score"]

# Load stats from file or initialize with defaults
def load_stats():
    if os.path.exists(stats_file):
        print("Reading stats from file")
        with open(stats_file, 'r') as file:
            return json.load(file)
    else:
        print("File does not exist")
        return {
            "energy": 100,
            "happiness": 100,
            "fullness": 100,
            "hi_score": 0,
            "last_sync": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

# Save stats to file
def save_stats(data):
    with open(stats_file, 'w') as file:
        json.dump(data, file, default=str)

# Initialize stats
stats = load_stats()

class MyServer(BaseHTTPRequestHandler):
    def __init__(self, *args, passwd=None, **kwargs):
        self.passwd = passwd  # Store the passed value (hashed password)
        super().__init__(*args, **kwargs)

    def do_GET(self):
        parsed_url = urlparse(self.path)
        query_params = parse_qs(parsed_url.query)

        if parsed_url.path == "/nibygotchi":
            if query_params.get("passwd", [None])[0] == self.passwd:
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
        
                self.wfile.write(bytes(json.dumps(stats, default=str), "utf-8"))
            else:
                self.send_response(401)
                self.send_header("Content-type", "application/json")
                self.end_headers()

                response = {
                    "status": "error",
                    "message": "not authorized"
                }

                self.wfile.write(json.dumps(response).encode("utf-8"))

    def do_POST(self):       
        parsed_url = urlparse(self.path)
        query_params = parse_qs(parsed_url.query)
        if parsed_url.path == "/nibygotchi":
            if query_params.get("passwd", [None])[0] == self.passwd:
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                post_data_str = post_data.decode('utf-8')
                
                try:
                    post_data_json = json.loads(post_data_str)
                    print(f"Received JSON data: {post_data_json}")
                    
                    if list(post_data_json.keys()) == client_stats:
                        post_data_json["last_sync"] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        stats.update(post_data_json)
                        
                        # Save the updated stats to a file
                        save_stats(stats)

                        # Send a success response
                        self.send_response(200)
                        self.send_header('Content-type', 'application/json')
                        self.end_headers()
                        
                        # Return success message
                        response = {
                            'status': 'success',
                            'message': 'Stats updated',
                            'updated_stats': stats
                        }
                        self.wfile.write(json.dumps(response, default=str).encode('utf-8'))
                    else:
                        # If the keys don't match, send an error response
                        self.send_response(400)
                        self.send_header('Content-type', 'application/json')
                        self.end_headers()
                        
                        response = {
                            'status': 'error',
                            'message': 'Invalid data shape. Keys do not match.',
                            'received_keys': list(post_data_json.keys()),
                            'expected_keys': client_stats
                        }
                        self.wfile.write(json.dumps(response).encode('utf-8'))
                
                except json.JSONDecodeError:
                    # Handle JSON parsing errors
                    self.send_response(400)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    
                    response = {
                        'status': 'error',
                        'message': 'Invalid JSON format'
                    }
                    self.wfile.write(json.dumps(response).encode('utf-8'))
            else:
                self.send_response(401)
                self.send_header("Content-type", "application/json")
                self.end_headers()

                response = {
                    "status": "error",
                    "message": "not authorized"
                }

                self.wfile.write(json.dumps(response).encode("utf-8"))

def create_handler(passwd):
    def handler(*args, **kwargs):
        MyServer(*args, passwd=passwd, **kwargs)
    return handler

if __name__ == "__main__":
    # Get the password from the environment, hash it, and start the server
    passwd = os.environ['NIBYGOTCHI_PASS']
    passwd_hash = hashlib.sha256(bytes(passwd, "utf-8")).hexdigest()

    print(f"Hashed password: {passwd_hash}")
    
    webServer = HTTPServer((hostName, serverPort), create_handler(passwd_hash))
    print(f"Server started http://{hostName}:{serverPort}")

    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
    print("Server stopped.")
