from flask import Flask, render_template, request, send_file, jsonify
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Hash import SHA256
import os
import io

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/generate-keys', methods=['POST'])
def generate_keys():
    # Generate RSA key pair
    key = RSA.generate(2048)
    private_key = key
    public_key = key.publickey()
    
    # Serialize keys
    private_pem = private_key.export_key()
    public_pem = public_key.export_key()
    
    return jsonify({
        'private_key': private_pem.decode(),
        'public_key': public_pem.decode()
    })

@app.route('/encrypt', methods=['POST'])
def encrypt_file():
    if 'file' not in request.files or 'private_key' not in request.form:
        return jsonify({'error': 'Missing file or private key'}), 400
    
    file = request.files['file']
    private_key_pem = request.form['private_key']
    
    try:
        # Load private key
        private_key = RSA.import_key(private_key_pem)
        cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
        
        # Read and encrypt file
        file_data = file.read()
        encrypted_data = cipher.encrypt(file_data)
        
        # Create response with encrypted data
        return send_file(
            io.BytesIO(encrypted_data),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=f'encrypted_{file.filename}'
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/decrypt', methods=['POST'])
def decrypt_file():
    if 'file' not in request.files or 'public_key' not in request.form:
        return jsonify({'error': 'Missing file or public key'}), 400
    
    file = request.files['file']
    public_key_pem = request.form['public_key']
    
    try:
        # Load public key
        public_key = RSA.import_key(public_key_pem)
        cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
        
        # Read and decrypt file
        encrypted_data = file.read()
        decrypted_data = cipher.decrypt(encrypted_data)
        
        # Create response with decrypted data
        return send_file(
            io.BytesIO(decrypted_data),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=f'decrypted_{file.filename}'
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404

if __name__ == '__main__':
    app.run(debug=True, port=8000)