from keras.models import load_model
from keras import backend as K
import re

def f1(y_true, y_pred):
    def recall(y_true, y_pred):
        """Recall metric.

        Only computes a batch-wise average of recall.

        Computes the recall, a metric for multi-label classification of
        how many relevant items are selected.
        """
        true_positives = K.sum(K.round(K.clip(y_true * y_pred, 0, 1)))
        possible_positives = K.sum(K.round(K.clip(y_true, 0, 1)))
        recall = true_positives / (possible_positives + K.epsilon())
        return recall

    def precision(y_true, y_pred):
        """Precision metric.

        Only computes a batch-wise average of precision.

        Computes the precision, a metric for multi-label classification of
        how many selected items are relevant.
        """
        true_positives = K.sum(K.round(K.clip(y_true * y_pred, 0, 1)))
        predicted_positives = K.sum(K.round(K.clip(y_pred, 0, 1)))
        precision = true_positives / (predicted_positives + K.epsilon())
        return precision
    precision = precision(y_true, y_pred)
    recall = recall(y_true, y_pred)
    return 2*((precision*recall)/(precision+recall+K.epsilon()))

def get_model():
    try:
        global model
        model = load_model('data_A_model.h5', custom_objects={'f1': f1})
        print(" * Model Loaded!")
    except Exception as e:
        print(str(e))

model = load_model('data_A_model.h5', custom_objects={'f1': f1})

def preprocess(text):
    text = text.strip()  # Hapus spasi ekstra
    text = text.lower()  # Konversi ke huruf kecil
    text = re.sub('[^0-9a-zA-Z]+', ' ', text)  # Hapus karakter khusus, hanya biarkan huruf dan angka
    text = re.sub(' +', ' ', text).strip()  # Hapus spasi berlebihan
    return text

# Load the model and metric function       
with open('f1_metric.py', 'w') as f:
    f.write('from keras import backend as K\n\n')
    f.write('def f1(y_true, y_pred):\n')
    f.write('    # Your F1 metric implementation\n')
