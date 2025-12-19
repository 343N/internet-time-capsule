import sys
from enc.Key import Keygen, KeyCommunicator
from os import environ
import dotenv
import logging

logFormat = "[%(asctime)s] [%(levelname)s] %(filename)s: %(message)s"
log = logging.getLogger()
logging.basicConfig(level=logging.DEBUG, format=logFormat, filename="backend.log")
log.addHandler(logging.StreamHandler(sys.stdout))
dotenv.load_dotenv()

# for x in environ:
#     print(x, environ[x])



log.info("Generating aes key...")
aes = Keygen.generate_aes_key()
log.info("Grabbing public key...")
pub = KeyCommunicator.get_public_key()
log.info("Public key retrieved")
KeyCommunicator.send_aes_key(pub, aes, "1")
