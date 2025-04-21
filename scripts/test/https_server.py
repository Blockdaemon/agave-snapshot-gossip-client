#!/usr/bin/env python3
import http.server
import ssl
import sys
import os

# Get port from command line argument or default to 8443
port = int(sys.argv[1]) if len(sys.argv) > 1 else 8443

# Default cert/key filenames
certfile = './cert.pem'
keyfile = './key.pem'

# Basic check if files exist
if not os.path.exists(certfile) or not os.path.exists(keyfile):
    print(f"Error: Certificate ('{certfile}') or Key ('{keyfile}') not found.")
    print("Please generate them using openssl before running the server.")
    sys.exit(1)

# Create and wrap the socket using SSLContext
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
try:
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
except ssl.SSLError as e:
    print(f"Error loading certificate/key: {e}")
    print("Ensure 'cert.pem' and 'key.pem' are valid.")
    sys.exit(1)

httpd = http.server.HTTPServer(('0.0.0.0', port), http.server.SimpleHTTPRequestHandler)
try:
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
except ssl.SSLError as e:
    print(f"Error wrapping socket: {e}")
    sys.exit(1)

print(f'Serving HTTPS on port {port}')
# Serve files from the current directory
try:
    httpd.serve_forever()
except KeyboardInterrupt:
    print("\nServer stopped.")
