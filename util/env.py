import dotenv, os
from container import Container

dotenv.load_dotenv()
ENV = Container.fromDict(os.environ)