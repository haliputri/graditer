from flask import Flask, request, jsonify, render_template
from flask_pymongo import PyMongo
from gridfs import GridFS
import secrets
from flask_mail import Mail


app = Flask(__name__, template_folder='templates', static_folder='static')
# app.config['MONGO_URI'] = 'mongodb+srv://haliputri:1sampai8@cluster0.kkhummw.mongodb.net/aes'
app.config['MONGO_URI'] = 'mongodb+srv://haliputri:1sampai8@graditer.smz5cee.mongodb.net/graditer'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'akunlainhali@gmail.com'
app.config['MAIL_PASSWORD'] = 'xvzc dbpr pwhj fwxm'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
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
        

# import pandas as pd

# Baca data dari CSV ke dalam DataFrame
# df = pd.read_csv('SOAL_13_100.csv')
# data_stimulus = df['RESPONSE'].tolist()
# print(data_stimulus[0:3])
