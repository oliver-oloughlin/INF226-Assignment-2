from flask import Flask
from routes import use_routes
from db import init_db
from decouple import config

# Set up app
app = Flask(__name__)
app.secret_key = config("SECRET")

# Initiate database and routes
init_db()
use_routes(app)
