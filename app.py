from flask import Flask, request, jsonify, render_template, redirect
from keras.preprocessing.text import Tokenizer
from keras.preprocessing.sequence import pad_sequences
from config import app, mongo, db_user, db_essay, check_mongo_connection
from model_aes import model, get_model, preprocess
from bson import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
from user_route import user_blueprint
from essay_route import essay_blueprint

app.register_blueprint(user_blueprint)
app.register_blueprint(essay_blueprint)

get_model()
check_mongo_connection()
    
@app.route('/')
def login():
    return render_template('login.html')