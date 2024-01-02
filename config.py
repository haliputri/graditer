from flask import Flask, request, jsonify, render_template
from flask_pymongo import PyMongo
from gridfs import GridFS
import secrets

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['MONGO_URI'] = 'mongodb+srv://haliputri:1sampai8@cluster0.kkhummw.mongodb.net/aes'
app.secret_key = secrets.token_hex(24)
mongo = PyMongo(app)
mongo.init_app(app)
fs = GridFS(mongo.db)

db_user = mongo.db.users
db_essay = mongo.db.essays
db_sw = mongo.db.student_works

def check_mongo_connection():
    try:
        # Attempt to ping the MongoDB server
        mongo.cx.server_info()
        print('Connected to MongoDB')
        # print(mongo)
        # print(mongo.db)
        # print(mongo.db.aes)
        # print(mongo.db.aes.users)
        # print(mongo.cx)
    except Exception as e:
        print(f'MongoDB connection error: {e}')

