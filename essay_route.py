from flask import Flask, request, jsonify, Blueprint
from config import mongo, db_essay
from bson import ObjectId
from bson.binary import Binary
from keras.models import load_model, save_model
from model_aes import f1
from flask_cors import CORS
from config import fs

essay_blueprint = Blueprint('essays', __name__)
CORS(essay_blueprint)
# crud db essay
@essay_blueprint.route('/essays', methods=['GET'])
def essays():
    essays_collection = db_essay

    # Fetch all users from the collection
    essays_cursor = essays_collection.find()

    # Convert the cursor to a list of dictionaries
    essays = list(essays_cursor)

    # Convert ObjectId to string for JSON serialization
    for essay in essays:
        essay['_id'] = str(essay['_id'])
        
    essay_count = essays_collection.count_documents({})

    response_data = {'essay_count': essay_count, 'essays': essays}

    # Return a JSON response containing the inserted users
    return jsonify(response_data)

@essay_blueprint.route('/essays/<id>')
def get_essay_by_id(id):
    try:
        user_object_id = ObjectId(id)
        user = db_essay.find_one({'_id': user_object_id})

        if user:
            user['_id'] = str(user['_id'])
            return jsonify(user)
        else:
            return jsonify({'error' : 'User not found'}), 404
    except Exception as e:
        # Handle any exceptions that may occur during the process
        return jsonify({'error': str(e)}), 500

@essay_blueprint.route('/create_essay', methods=['GET', 'POST'])
def create_essays():
    data = request.json
    title = data['title']
    questions = data['questions']
    time = data['time']
    mata_pelajaran = data['mata_pelajaran']
    
    # Read the binary file
    with open('model.joblib', 'rb') as f:
        binary_model = Binary(f.read())
    
    binary_model = data['model']

    # Proses pertanyaan-pertanyaan
    for question in questions:
        question_id = question['id']
        question_text = question['text']
        # Lakukan sesuatu dengan pertanyaan
    
    # Ensure required fields are present in the request data
    if 'title' and request.method == 'POST':
        result = db_essay.insert_one({'title': title, 'mata_pelajaran': mata_pelajaran, 'questions' : questions, 'time':time, 'model':binary_model })
        resp = jsonify("User added succesfully")
        resp.status_code = 200
        return resp
    else:
        return not_found()


@essay_blueprint.route('/test', methods=['POST'])
def test_create_essays():
    # Example data
    title = "Pertanyaan-pertanyaan mengenai topik tertentu"
    questions = [
        {"question_id": 1, "text": "Pertanyaan pertama?"},
        {"question_id": 2, "text": "Pertanyaan kedua?"},
        {"question_id": 3, "text": "Pertanyaan ketiga?"}
    ]

    # Read the binary file
    model = load_model('data_A_model.h5', custom_objects={'f1': f1})

    # Save the Keras model to a file path in the native Keras format
    model.save('model.keras')

    # Save the Keras model as binary data in GridFS
    with open('model.keras', 'rb') as f:
        file_id = fs.put(f, filename='model.keras')

    # Proses pertanyaan-pertanyaan
    # (Your code for processing questions)

    # Ensure required fields are present
    if title:
        result = db_essay.insert_one({'title': title, 'questions': questions, 'model_file_id': str(file_id)})
        resp = jsonify("Essay added successfully")
        resp.status_code = 200
        return resp
    else:
        return jsonify({'error': 'Invalid request'}), 400

@essay_blueprint.route('/essays/delete/<id>', methods=['DELETE'])
def delete_essay(id):
    db_essay.delete_one({'_id': ObjectId(id)})
    resp = jsonify("Essay deleted successfully")
    resp.status_code = 200
    return resp

@essay_blueprint.route('/essays/update/<id>', methods=['PUT'])
def update_essay(id):
    try:
        _id = id
        _json = request.json

        # Ensure _json is not None and is a dictionary
        if _json and isinstance(_json, dict):
            update_fields = {}  # Initialize dictionary for fields to update

            # Check if fields to update are present in _json
            if 'title' in _json:
                update_fields['title'] = _json['title']

            if 'time' in _json:
                update_fields['time'] = _json['time']

            if 'mata_pelajaran' in _json:
                update_fields['mata_pelajaran'] = _json['mata_pelajaran']

            if 'model' in _json:
                # Save the Keras model as binary data in GridFS
                model = _json['model']
                with open('temp_model.keras', 'wb') as f:
                    f.write(model)
                with open('temp_model.keras', 'rb') as f:
                    file_id = fs.put(f, filename='temp_model.keras')
                update_fields['model_file_id'] = str(file_id)

            if 'questions' in _json:
                questions = _json['questions']
                for question in questions:
                    if 'question_id' in question and 'text' in question:
                        question_id = question['question_id']
                        text = question['text']
                        # Update the specific question using $set and $
                        db_essay.update_one(
                            {'_id': ObjectId(_id), 'questions.question_id': question_id},
                            {'$set': {'questions.$.text': text}}
                        )

            # Update the specific essay document using $set
            db_essay.update_one({'_id': ObjectId(_id)}, {'$set': update_fields})

            resp = jsonify("Essay updated successfully")
            resp.status_code = 200

            return resp
        else:
            return jsonify({'error': 'Invalid JSON data'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@essay_blueprint.errorhandler(404)
def not_found(error = None):
    message = {
        'status' : 404,
        'message' : 'Not Found' + request.url
    }
    resp = jsonify(message)
    resp.status_code = 404
    return resp 
