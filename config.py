from flask import Flask, request, jsonify, render_template
from flask_pymongo import PyMongo
from gridfs import GridFS
import secrets
from flask_mail import Mail
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['MONGO_URI'] = os.environ.get('MONGO_URI')
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT'))
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', '').lower() == 'true'
app.config['MAIL_USE_SSL'] = os.environ.get('MAIL_USE_SSL', '').lower() == 'true'
mail = Mail(app)
app.secret_key = secrets.token_hex(24)
mongo = PyMongo(app)
mongo.init_app(app)
fs = GridFS(mongo.db)


db_user = mongo.db.users
db_essay = mongo.db.essays
db_sw = mongo.db.student_works
db_question = mongo.db.question_alls

def check_mongo_connection():
    try:
        mongo.cx.server_info()
        print('Connected to MongoDB')
    except Exception as e:
        print(f'MongoDB connection error: {e}')