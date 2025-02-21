from flask import Flask, render_template, request, send_file, jsonify
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Hash import SHA256
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
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    if 'public_key' not in request.form:
        return jsonify({'error': 'No public key provided'}), 400
    
    file = request.files['file']
    if not file.filename:
        return jsonify({'error': 'Empty file selected'}), 400
    
    public_key_pem = request.form['public_key']
    if not public_key_pem.strip():
        return jsonify({'error': 'Empty public key'}), 400
    
    try:
        # Load public key
        public_key = RSA.import_key(public_key_pem)
        cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
        
        # Read file in chunks to handle memory efficiently
        chunk_size = 8192  # 8KB chunks
        encrypted_data = b''
        print(dir(file))
        while True:
            chunk = file.read(chunk_size)
            if not chunk:
                break
            encrypted_data += chunk
        
        if not encrypted_data:
            return jsonify({'error': 'File is empty'}), 400

        # Decrypt the data
        try:
            decrypted_data = cipher.decrypt(encrypted_data)
        except ValueError as ve:
            return jsonify({'error': f'Decryption failed: Invalid data format'}), 400
        except Exception as de:
            return jsonify({'error': f'Decryption process failed: {str(de)}'}), 400

        # Create response with decrypted data
        memory_file = io.BytesIO(decrypted_data)
        memory_file.seek(0)
        
        return send_file(
            memory_file,
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=f'decrypted_{file.filename}'
        )
    except ValueError as ve:
        return jsonify({'error': f'Invalid key format: {str(ve)}'}), 400
    except Exception as e:
        return jsonify({'error': f'Decryption failed: {str(e)}'}), 400

@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404

if __name__ == '__main__':
    app.run(debug=True, port=8000)