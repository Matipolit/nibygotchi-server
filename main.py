import os
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime
import json
from urllib.parse import urlparse, parse_qs

hostName = "localhost"
serverPort = 3000
stats_file = "nibygotchi_stats.json"
shop_file = "purchased_items.json"

client_stats = ["energy", "happiness", "fullness", "hi_score", "state"]
shop_items = []

class Stat:
    def __init__(self, time_to_tick_awaken, time_to_tick_asleep, time_to_tick_tv, amount_awaken, amount_asleep, amount_tv):
        self.time_to_tick_awaken = time_to_tick_awaken
        self.time_to_tick_asleep = time_to_tick_asleep
        self.time_to_tick_tv = time_to_tick_asleep
        self.amount_awaken = amount_awaken
        self.amount_asleep = amount_asleep
        self.amount_tv = amount_tv

    def adjust_amount(self, last_value, last_sync, state):
        time_delta = datetime.now() - last_sync
        seconds_passed = time_delta.seconds
        match state:
            case "awaken":
                time_delta = self.time_to_tick_awaken
                amount = self.amount_awaken
            case "asleep":
                time_delta = self.time_to_tick_asleep
                amount = self.amount_asleep
            case "watching_tv":
                time_delta = self.time_to_tick_asleep
                amount = self.amount_tv
        time_periods_passed = seconds_passed / time_delta
        return max(last_value - (amount * time_periods_passed), 0)

stat_lib = {
    "happiness": Stat(50, 100, 33, 1, 0, -3),
    "energy": Stat(50, 100, 50, 1, -2, 2),
    "fullness": Stat(50, 100, 50, 1, 1, 1)
}


# Load stats from file or initialize with defaults
def load_stats():
    if os.path.exists(stats_file):
        print("Reading stats from file")
        with open(stats_file, 'r') as file:
            return json.load(file)
    else:
        print("Stats file does not exist")
        return {
            "energy": 100,
            "happiness": 100,
            "fullness": 100,
            "hi_score": 0,
            "coins": 0,
            "state": "awaken",
            "last_sync": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

def load_shop_items():
    if os.path.exists(shop_file):
        print("Reading shop items from file")
        with open(stats_file, 'r') as file:
            return json.load(file)
    else:
        print("Shop file does not exist")
        return([])

# Save stats to file
def save_stats(data):
    with open(stats_file, 'w') as file:
        json.dump(data, file, default=str)

def save_shop_items(data):
    with open(shop_file, "w") as file:
        json.dump(data, file, default=str)

def update_stats():
    for stat in stat_lib.keys():
        stats[stat] = stat_lib[stat].adjust_amount(stats[stat], datetime.strptime(stats["last_sync"], '%Y-%m-%d %H:%M:%S'), stats["state"])


# Initialize stats
stats = load_stats()
update_stats()

shop_items = load_shop_items()

class MyServer(BaseHTTPRequestHandler):
    def __init__(self, *args, passwd=None, **kwargs):
        self.passwd = passwd  # Store the passed value (hashed password)
        super().__init__(*args, **kwargs)

    def write_not_authorized_response(self):
        self.send_response(401)
        self.send_header("Content-type", "application/json")
        self.end_headers()

        response = {
            "status": "error",
            "message": "not authorized"
        }

        self.wfile.write(json.dumps(response).encode("utf-8"))

    def do_GET(self):
        parsed_url = urlparse(self.path)
        query_params = parse_qs(parsed_url.query)

        if parsed_url.path == "/nibygotchi":
            if query_params.get("passwd", [None])[0] == self.passwd:
                new_stats = stats
                new_stats["shop_items"] = shop_items;
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(bytes(json.dumps(stats, default=str), "utf-8"))
            else:
                self.write_not_authorized_response()

    def do_POST(self):
        parsed_url = urlparse(self.path)
        query_params = parse_qs(parsed_url.query)
        if query_params.get("passwd", [None])[0] == self.passwd:
            if parsed_url.path == "/nibygotchi":
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

            elif parsed_url.path == "/nibygotchi/coins":
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                post_data_str = post_data.decode('utf-8')
                try:
                    new_coins = int(post_data_str)
                    stats["coins"] = new_coins
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()

                    # Return success message
                    response = {
                        'status': 'success',
                        'message': 'Coins updated',
                        'updated_coins': new_coins
                    }
                    self.wfile.write(json.dumps(response, default=str).encode('utf-8'))
                except Exception:
                    self.send_response(400)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()

                    response = {
                        'status': 'error',
                        'message': 'Could not parse the coins amount'
                    }
                    self.wfile.write(json.dumps(response).encode('utf-8'))

            elif parsed_url.path == "/nibygotchi/shop":
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                post_data_str = post_data.decode('utf-8')
                try:
                    if post_data_str not in shop_items:
                        shop_items.append(post_data_str)
                        self.send_response(200)
                        self.send_header('Content-type', 'application/json')
                        self.end_headers()

                        # Return success message
                        response = {
                            'status': 'success',
                            'message': 'Saved purchase',
                            'purchased items': shop_items
                        }
                        save_shop_items(shop_items)
                        self.wfile.write(json.dumps(response, default=str).encode('utf-8'))
                    else:
                        self.send_response(400)
                        self.send_header('Content-type', 'application/json')
                        self.end_headers()

                        # Return success message
                        response = {
                            'status': 'warning',
                            'message': 'Purchase already saved',
                            'purchased items': shop_items
                        }
                        self.wfile.write(json.dumps(response, default=str).encode('utf-8'))
                except Exception:
                    self.send_response(400)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()

                    response = {
                        'status': 'error',
                        'message': 'Something went wrong'
                    }
                    self.wfile.write(json.dumps(response).encode('utf-8'))
        else:
            self.write_not_authorized_response()


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
