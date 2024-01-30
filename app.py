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

# @app.route("/", methods=['GET', 'POST'])
# def hello_world():
#     request_type_str = request.method
#     if request_type_str == 'GET':
#         essay_test_1 = "Saya akan mengaLamI kesulitan ekonomi jika air laut terus menaik dan memenuhi daratan"
#         processed_essay_1 = preprocess(essay_test_1)
#         print("Teks yang telah diproses:", processed_essay_1)
        
#         max_features = 3000 # how many unique words to use (since the total of unique word is only 2816)
#         maxlen = 43
        
#         tokenizer = Tokenizer(num_words=max_features)
#         token_1 = tokenizer.fit_on_texts([processed_essay_1])
#         essay_tokens_1 = tokenizer.texts_to_sequences([processed_essay_1])
#         print("\nUrutan token:", essay_tokens_1)

#         max_sequence_length = 43  # Sesuaikan dengan panjang maksimum yang digunakan saat melatih model
#         essay_tokens_padded_1 = pad_sequences(essay_tokens_1, maxlen=max_sequence_length)
#         print("\nUrutan token yang dipadatkan:", essay_tokens_padded_1)
        
#         result_as_str = str(model.predict(essay_tokens_padded_1))
#         return render_template('index.html', href=result_as_str)
    
    # elif request_type_str == 'POST':
    #     text = request.form['text']
    #     processed_text = preprocess(text)
    #     token_text = tokenizer.texts_to_sequences([processed_text])
    #     max_sequence_length = 43
    #     text_token_padded = pad_sequences(token_text, maxlen=max_sequence_length)
    #     result_as_str = str(model.predict(text_token_padded))
    #     return render_template('index.html', href=result_as_str)
    
    # else:
    #     return render_template('index.html', href="")
    
    
    # processed_essay_2 = preprocess(essay_test_2)

    # # Tokenisasi teks
    # tokenizer = Tokenizer()
    # token_1 = tokenizer.fit_on_texts([processed_essay_1])
    # token_2 = tokenizer.fit_on_texts([processed_essay_2])

    # # Ubah teks menjadi urutan token
    
    # essay_tokens_2 = tokenizer.texts_to_sequences([processed_essay_2])

    # # Padding urutan token (menjadi panjang yang sama)
    
    
    # essay_tokens_padded_2 = pad_sequences(essay_tokens_2, maxlen=max_sequence_length)

    # # print("Teks yang telah diproses:")
    # # print(processed_essay_1)
    # # print("\nUrutan token:")
    # # print(essay_tokens_1)
    # # print("\nUrutan token yang dipadatkan:")
    # # print(essay_tokens_padded_1)


    # # print("Teks yang telah diproses:")
    # # print(processed_essay_2)
    # # print("\nUrutan token:")
    # # print(essay_tokens_2)
    # # print("\nUrutan token yang dipadatkan:")
    # # print(essay_tokens_padded_2)

    
    # return render_template('index.html')
    
    
@app.route('/')
def login():
    return render_template('login.html')

@app.route('/index')
def index():
    essay_test_1 = "Saya akan mengaLamI kesulitan ekonomi jika air laut terus menaik dan memenuhi daratan"
    processed_essay_1 = preprocess(essay_test_1)
    print("Teks yang telah diproses:", processed_essay_1)
        
    max_features = 3000 # how many unique words to use (since the total of unique word is only 2816)
    maxlen = 43
        
    tokenizer = Tokenizer(num_words=max_features)
    token_1 = tokenizer.fit_on_texts([processed_essay_1])
    essay_tokens_1 = tokenizer.texts_to_sequences([processed_essay_1])
    print("\nUrutan token:", essay_tokens_1)

    max_sequence_length = 43  # Sesuaikan dengan panjang maksimum yang digunakan saat melatih model
    essay_tokens_padded_1 = pad_sequences(essay_tokens_1, maxlen=max_sequence_length)
    print("\nUrutan token yang dipadatkan:", essay_tokens_padded_1)
        
    result_as_str = str(model.predict(essay_tokens_padded_1))
    return render_template('index.html', href=result_as_str)

@app.route('/admin/')
def admin():
    return render_template('admin/admin.html')

@app.route('/admin/adminEsai')
def adminEsai():
    return render_template('admin/adminEsai.html')

@app.route('/admin/adminPengguna')
def adminPengguna():
    return render_template('admin/adminPengguna.html')

@app.route('/user/')
def user():
    return render_template('user.html')

@app.route('/user/soal', methods=['GET', 'POST'])
def kerjakan():
    try:
        user = db_user.find_one({'index': index})
        # essay_object_id = ObjectId(id_soal)
        # essay = db_essay.find_one({'_id':essay_object_id})

        if user and request.method == "POST":
            # Retrieve the value of the "answer" field
            answer = str(request.form.get("answer"))
            processed_answer = preprocess(answer)
            max_features = 3000
            maxlen = 43

            tokenizer = Tokenizer(num_words=max_features)
            token_1 = tokenizer.fit_on_texts([processed_answer])
            essay_tokens_1 = tokenizer.texts_to_sequences([processed_answer])

            max_sequence_length = 43
            essay_tokens_padded_1 = pad_sequences(essay_tokens_1, maxlen=max_sequence_length)

            result_as_str = str(model.predict(essay_tokens_padded_1))
            user_name = user['name'] if 'name' in user else user['email'].split('@')[0]
            return render_template('kerjakanSoal.html', user=user, user_name=user_name, answer=result_as_str)
        else:
            return jsonify({'error' : 'Page not found'}), 404
    except Exception as e:
        # Handle any exceptions that may occur during the process
        return jsonify({'error': str(e)}), 500
    
    # if request.method == "POST":
    #     # Print the entire form data for debugging purposes
    #     # print(request.form)

    #     # Retrieve the value of the "answer" field
    #     answer = str(request.form.get("answer"))
    #     processed_answer = preprocess(answer)
    #     max_features = 3000
    #     maxlen = 43

    #     tokenizer = Tokenizer(num_words=max_features)
    #     token_1 = tokenizer.fit_on_texts([processed_answer])
    #     essay_tokens_1 = tokenizer.texts_to_sequences([processed_answer])

    #     max_sequence_length = 43
    #     essay_tokens_padded_1 = pad_sequences(essay_tokens_1, maxlen=max_sequence_length)

    #     result_as_str = str(model.predict(essay_tokens_padded_1))
        
    #     # Print the retrieved answer for debugging purposes
    #     # print("Answer:", answer)

    #     # Render the template with the answer value
    #     return render_template('result.html', answer=result_as_str)
    # else:
    #     # Render the form template for GET requests
    #     return render_template('kerjakanSoal.html')

@app.route('/result')
def hasil():
    return render_template('result.html')


@app.route('/tambahEsai')
def tambahEsai():
    return render_template('admin/tambahEsai.html')

@app.route('/detailEsai')
def detailEsai():
    return render_template('admin/detailEsai.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)
