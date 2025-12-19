import logging
import os
import random
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import http.server
from enc.Key import Keygen, KeyStore, RSAKey
from util.container import Container
import dotenv
dotenv.load_dotenv()

log = logging.getLogger()
log.addHandler(logging.StreamHandler(sys.stdout))
log.info("\n#\n#\n# STARTING ENCRYPTION SERVER\n#\n#")



# GENERATE PRIVATE KEY,
# SEND TO BACKEND

# BACKEND USES TO GENERATE AES KEY 
# AND GIVES BACK. STORE AES KEY.
ENV = Container.fromDict(os.environ)
# ENV.printAll()
MASTER_KEY = RSAKey.from_pem_file("keys/private_key.pem")



    



class RequestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        # self.request.sendall(b'Hello, world!')
        
        if self.path == '/key':
            logging.info("Grabbing public key..")
            key = MASTER_KEY.public_key_to_pem()
            logging.info("Sending public key..")
            self.send_response(200, "OK")
            self.send_header('content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(key)
            # self.send_response(200)
        else:
            self.end_headers()
            self.send_response(404, 'Not Found')

        return


    def do_POST(self):
        if self.path == '/key':
            print("Received an AES key")
            self.send_response(200)

        else:
            self.end_headers()
            self.send_response(404, 'Not Found')
        

def run(server_class=http.server.HTTPServer, handler_class=RequestHandler):
    print(ENV.ENCRYPT_SERVER_PORT, type(ENV.ENCRYPT_SERVER_PORT))
    print(f"Starting server on port {ENV.ENCRYPT_SERVER_PORT}...")
    server_address = ('', int(ENV.ENCRYPT_SERVER_PORT))
    httpd = server_class(server_address, handler_class)
    httpd.serve_forever()


if __name__ == "__main__":
    run()