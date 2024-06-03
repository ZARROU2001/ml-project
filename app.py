from flask import Flask, render_template, request, flash, redirect, url_for,jsonify
from werkzeug.utils import secure_filename
from joblib import load
import pefile
import hashlib
import pandas as pd
import os
import cv2
import numpy as np


# Initialize Flask application

app = Flask(__name__)

# Set a secret key for sessions and flashing messages
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'


app.config['UPLOAD_FOLDER'] = 'upload'
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Load the trained model
model = load('decision_tree_model1.pkl')
model_path = 'random_forest_model2.pkl'
rf_model = load(model_path)



# Define the allowed file extensions
ALLOWED_EXTENSIONS = {'exe'}


# Function to check if the file has allowed extension
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS



# Function to preprocess the executable file
def preprocess_exe(file_path):
    try:
        pe = pefile.PE(file_path)

        # Compute MD5 hash
        with open(file_path, 'rb') as f:
            file_data = f.read()
            md5_hash = hashlib.md5(file_data).hexdigest()

        # Extract general features
        features = {
            "Machine": pe.FILE_HEADER.Machine,
            "ImageBase": pe.OPTIONAL_HEADER.ImageBase,
            "Characteristics": pe.FILE_HEADER.Characteristics,
            "BaseOfData": pe.OPTIONAL_HEADER.BaseOfData,
            "CheckSum": pe.OPTIONAL_HEADER.CheckSum,
            "MajorLinkerVersion": pe.OPTIONAL_HEADER.MajorLinkerVersion,
            "SizeOfInitializedData": pe.OPTIONAL_HEADER.SizeOfInitializedData,
            "MajorImageVersion": pe.OPTIONAL_HEADER.MajorImageVersion,
            "ResourcesNb": len(pe.DIRECTORY_ENTRY_RESOURCE.entries) if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE') else 0,
            "MinorOperatingSystemVersion": pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,
            "ImportsNb": sum([len(entry.imports) for entry in pe.DIRECTORY_ENTRY_IMPORT]) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0,
            "SizeOfImage": pe.OPTIONAL_HEADER.SizeOfImage,
            "AddressOfEntryPoint": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            "VersionInformationSize": len(pe.VS_VERSIONINFO[0].StringTable[0].entries) if hasattr(pe, 'VS_VERSIONINFO') and hasattr(pe.VS_VERSIONINFO[0], 'StringTable') and hasattr(pe.VS_VERSIONINFO[0].StringTable[0], 'entries') else 0
        }

        return pd.DataFrame([features])

    except Exception as e:
        print("Error occurred during preprocessing:", e)
        return None
    
def preprocess_image(image_path, size=(64, 64)):
    image = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE)
    resized_image = cv2.resize(image, size)
    flattened_image = resized_image.flatten()
    return flattened_image


# Define a route to render the file upload form
@app.route('/')
def index():
    return render_template('index.html')

# Define a route to render the image upload form
@app.route('/upload_image')
def upload_image():
    return render_template('upload_image.html')

@app.route('/upload')
def upload():
    return render_template('upload.html')


# Define a route to handle file upload and make predictions
@app.route('/predict', methods=['POST'])
def predict_file():
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        
        file = request.files['file']
        
        # If the user does not select a file, browser also
        # submit an empty part without filename
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        
        # Check if the file extension is allowed
        if file and allowed_file(file.filename):
            # Securely save the file
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            
            # Preprocess the uploaded file
            df = preprocess_exe(file_path)
            
            if df is not None:
                # Make predictions using the preprocessed data
                prediction = model.predict(df)
                
                # Redirect to the result page with the prediction value
                return redirect(url_for('result', prediction=prediction))
            else:
                # Handle preprocessing failure
                flash('Error occurred during preprocessing')
                return redirect(url_for('upload_file'))
        else:
            # Handle invalid file extension
            flash('Invalid file extension. Only .exe files are allowed.')
            return redirect(url_for('upload_file'))
        

        
@app.route('/predict_image', methods=['GET', 'POST'])
def predict_image():
    if request.method == 'POST':
        if 'file' not in request.files:
            return render_template('index.html', message='Aucun fichier sélectionné')
        file = request.files['file']
        if file.filename == '':
            return render_template('index.html', message='Aucun fichier sélectionné')
        if file:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(file_path)
            print('test')
            image = preprocess_image(file_path)
            print('test1')
            # Faire une prédiction avec le modèle RandomForestClassifier
            prediction = rf_model.predict([image])
            print('test3')
            return render_template('result_image.html', message='Le type de malware détecté est : {}'.format(prediction[0]))
    return render_template('result_image.html')


# Define a route to render the result page
@app.route('/result')
def result():
    # Get the prediction value from the URL parameters
    prediction = request.args.get('prediction')
    return render_template('result.html', prediction=prediction)




if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)


