from flask import Flask, render_template, request, send_file, jsonify
import io
import base64
from Crypto.Cipher import AES, DES3, Blowfish, PKCS1_OAEP
from Crypto.PublicKey import RSA, ECC
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256, MD5, SHA1, SHA224, SHA384, SHA512
import bcrypt

# Try to import argon2-cffi library
try:
    import argon2
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False
    print("Warning: argon2-cffi library not installed. Argon2 functionality will be limited.")

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('landing.html')

# Symmetric Encryption Routes
@app.route('/symmetric/aes')
def aes_page():
    return render_template('symmetric/aes.html')

@app.route('/symmetric/des')
def des_page():
    return render_template('symmetric/des.html')

@app.route('/symmetric/blowfish')
def blowfish_page():
    return render_template('symmetric/blowfish.html')

@app.route('/symmetric/twofish')
def twofish_page():
    return render_template('symmetric/twofish.html')

@app.route('/symmetric/rc4')
def rc4_page():
    return render_template('symmetric/rc4.html')

@app.route('/symmetric/chacha20')
def chacha20_page():
    return render_template('symmetric/chacha20.html')

@app.route('/symmetric/3des')
def triple_des_page():
    return render_template('symmetric/3des.html')

@app.route('/symmetric/rc5')
def rc5_page():
    return render_template('symmetric/rc5.html')

@app.route('/symmetric/rc6')
def rc6_page():
    return render_template('symmetric/rc6.html')

@app.route('/symmetric/salsa20')
def salsa20_page():
    return render_template('symmetric/salsa20.html')

@app.route('/symmetric/camellia')
def camellia_page():
    return render_template('symmetric/camellia.html')

@app.route('/symmetric/serpent')
def serpent_page():
    return render_template('symmetric/serpent.html')

@app.route('/symmetric/cast')
def cast_page():
    return render_template('symmetric/cast.html')

@app.route('/symmetric/idea')
def idea_page():
    return render_template('symmetric/idea.html')

@app.route('/symmetric/skipjack')
def skipjack_page():
    return render_template('symmetric/skipjack.html')

@app.route('/symmetric/xtea')
def xtea_page():
    return render_template('symmetric/xtea.html')

# Asymmetric Encryption Routes
@app.route('/asymmetric/rsa')
def rsa_page():
    return render_template('asymmetric/rsa.html')

@app.route('/asymmetric/ecc')
def ecc_page():
    return render_template('asymmetric/ecc.html')

@app.route('/asymmetric/dsa')
def dsa_page():
    return render_template('asymmetric/dsa.html')

@app.route('/asymmetric/elgamal')
def elgamal_page():
    return render_template('asymmetric/elgamal.html')

@app.route('/asymmetric/ntru')
def ntru_page():
    return render_template('asymmetric/ntru.html')

@app.route('/asymmetric/mceliece')
def mceliece_page():
    return render_template('asymmetric/mceliece.html')

# Hash Function Routes
@app.route('/hash/md5')
def md5_page():
    return render_template('hash/md5.html')

@app.route('/hash/sha')
def sha_page():
    return render_template('hash/sha.html')

@app.route('/hash/bcrypt')
def bcrypt_page():
    return render_template('hash/bcrypt.html')

@app.route('/hash/argon2')
def argon2_page():
    return render_template('hash/argon2.html')

@app.route('/hash/blake2')
def blake2_page():
    return render_template('hash/blake2.html')

@app.route('/hash/sha3')
def sha3_page():
    return render_template('hash/sha3.html')

@app.route('/hash/poly1305')
def poly1305_page():
    return render_template('hash/poly1305.html')

# Quantum-Safe Cryptography Routes
@app.route('/quantum/kyber')
def kyber_page():
    return render_template('quantum/kyber.html')

@app.route('/quantum/dilithium')
def dilithium_page():
    return render_template('quantum/dilithium.html')

@app.route('/quantum/falcon')
def falcon_page():
    return render_template('quantum/falcon.html')

@app.route('/quantum/sphincs')
def sphincs_page():
    return render_template('quantum/sphincs.html')

@app.route('/quantum/bike')
def bike_page():
    return render_template('quantum/bike.html')

@app.route('/quantum/sike')
def sike_page():
    return render_template('quantum/sike.html')

@app.route('/quantum/ntru')
def quantum_ntru_page():
    return render_template('quantum/ntru.html')

@app.route('/quantum/gemss')
def gemss_page():
    return render_template('quantum/gemss.html')

@app.route('/quantum/picnic')
def picnic_page():
    return render_template('quantum/picnic.html')

@app.route('/quantum/rainbow')
def rainbow_page():
    return render_template('quantum/rainbow.html')

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

@app.route('/asymmetric/rsa/generate-keys', methods=['POST'])
def generate_rsa_keys():
    try:
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
    except Exception as e:
        print(f"RSA key generation error: {str(e)}")
        return jsonify({'error': str(e)}), 500

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

# AES Key Generation and Encryption/Decryption
@app.route('/generate-aes-key', methods=['POST'])
def generate_aes_key():
    try:
        data = request.json
        key_size = int(data.get('key_size', 256)) // 8  # Convert bits to bytes

        # Generate random key and IV
        key = get_random_bytes(key_size)
        iv = get_random_bytes(16)  # AES block size is 16 bytes

        # Return base64 encoded key and IV
        key_b64 = base64.b64encode(key).decode('utf-8')
        iv_b64 = base64.b64encode(iv).decode('utf-8')

        print(f"AES key generation successful: {key_b64[:15]}...")
        return jsonify({
            'key': key_b64,
            'iv': iv_b64
        })
    except Exception as e:
        print(f"AES key generation error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/symmetric/aes/encrypt', methods=['POST'])
def aes_encrypt_file():
    if 'file' not in request.files or 'key' not in request.form or 'iv' not in request.form:
        return jsonify({'error': 'Missing file, key, or IV'}), 400

    file = request.files['file']
    key_b64 = request.form['key']
    iv_b64 = request.form['iv']

    try:
        # Decode key and IV from base64
        key = base64.b64decode(key_b64)
        iv = base64.b64decode(iv_b64)

        # Read file data
        file_data = file.read()

        # Create AES cipher
        cipher = AES.new(key, AES.MODE_CBC, iv)

        # Pad data to be a multiple of 16 bytes (AES block size)
        padded_data = pad(file_data, AES.block_size)

        # Encrypt data
        encrypted_data = cipher.encrypt(padded_data)

        # Prepend IV to encrypted data for decryption later
        result_data = iv + encrypted_data

        # Create response with encrypted data
        return send_file(
            io.BytesIO(result_data),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=f'aes_encrypted_{file.filename}'
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/symmetric/aes/decrypt', methods=['POST'])
def aes_decrypt_file():
    if 'file' not in request.files or 'key' not in request.form or 'iv' not in request.form:
        return jsonify({'error': 'Missing file, key, or IV'}), 400

    file = request.files['file']
    key_b64 = request.form['key']
    iv_b64 = request.form['iv']

    try:
        # Decode key and IV from base64
        key = base64.b64decode(key_b64)
        iv = base64.b64decode(iv_b64)

        # Read file data
        file_data = file.read()

        # Create AES cipher
        cipher = AES.new(key, AES.MODE_CBC, iv)

        # Extract encrypted data (skip first 16 bytes which is the IV)
        encrypted_data = file_data[16:]

        # Decrypt data
        decrypted_padded_data = cipher.decrypt(encrypted_data)

        # Remove padding
        decrypted_data = unpad(decrypted_padded_data, AES.block_size)

        # Create response with decrypted data
        memory_file = io.BytesIO(decrypted_data)
        memory_file.seek(0)

        return send_file(
            memory_file,
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=f'decrypted_{file.filename.replace("aes_encrypted_", "")}'
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# DES Key Generation and Encryption/Decryption
@app.route('/generate-des-key', methods=['POST'])
def generate_des_key():
    try:
        data = request.json
        mode = data.get('mode', '3des')

        if mode == 'des':
            # DES key is 8 bytes (64 bits, with 8 bits used for parity)
            key = get_random_bytes(8)
        else:  # 3DES
            # Triple DES key is 24 bytes (192 bits, with 24 bits used for parity)
            key = get_random_bytes(24)

        # Generate IV (8 bytes for DES)
        iv = get_random_bytes(8)

        # Return base64 encoded key and IV
        key_b64 = base64.b64encode(key).decode('utf-8')
        iv_b64 = base64.b64encode(iv).decode('utf-8')

        print(f"DES key generation successful (mode: {mode}): {key_b64[:15]}...")
        return jsonify({
            'key': key_b64,
            'iv': iv_b64
        })
    except Exception as e:
        print(f"DES key generation error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/symmetric/des/encrypt', methods=['POST'])
def des_encrypt_file():
    if 'file' not in request.files or 'key' not in request.form or 'iv' not in request.form:
        return jsonify({'error': 'Missing file, key, or IV'}), 400

    file = request.files['file']
    key_b64 = request.form['key']
    iv_b64 = request.form['iv']
    mode = request.form.get('mode', '3des')

    try:
        # Decode key and IV from base64
        key = base64.b64decode(key_b64)
        iv = base64.b64decode(iv_b64)

        # Read file data
        file_data = file.read()

        # Create DES cipher
        if mode == 'des':
            # Use single DES (not recommended for security)
            from Crypto.Cipher import DES
            cipher = DES.new(key, DES.MODE_CBC, iv)
        else:
            # Use Triple DES
            cipher = DES3.new(key, DES3.MODE_CBC, iv)

        # Pad data to be a multiple of 8 bytes (DES block size)
        block_size = 8
        padded_data = pad(file_data, block_size)

        # Encrypt data
        encrypted_data = cipher.encrypt(padded_data)

        # Prepend IV to encrypted data for decryption later
        result_data = iv + encrypted_data

        # Create response with encrypted data
        return send_file(
            io.BytesIO(result_data),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=f'des_encrypted_{file.filename}'
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/symmetric/des/decrypt', methods=['POST'])
def des_decrypt_file():
    if 'file' not in request.files or 'key' not in request.form or 'iv' not in request.form:
        return jsonify({'error': 'Missing file, key, or IV'}), 400

    file = request.files['file']
    key_b64 = request.form['key']
    iv_b64 = request.form['iv']
    mode = request.form.get('mode', '3des')

    try:
        # Decode key and IV from base64
        key = base64.b64decode(key_b64)
        iv = base64.b64decode(iv_b64)

        # Read file data
        file_data = file.read()

        # Create DES cipher
        if mode == 'des':
            # Use single DES (not recommended for security)
            from Crypto.Cipher import DES
            cipher = DES.new(key, DES.MODE_CBC, iv)
        else:
            # Use Triple DES
            cipher = DES3.new(key, DES3.MODE_CBC, iv)

        # Extract encrypted data (skip first 8 bytes which is the IV)
        encrypted_data = file_data[8:]

        # Decrypt data
        decrypted_padded_data = cipher.decrypt(encrypted_data)

        # Remove padding
        block_size = 8
        decrypted_data = unpad(decrypted_padded_data, block_size)

        # Create response with decrypted data
        memory_file = io.BytesIO(decrypted_data)
        memory_file.seek(0)

        return send_file(
            memory_file,
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=f'decrypted_{file.filename.replace("des_encrypted_", "")}'
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# Blowfish Key Generation and Encryption/Decryption
@app.route('/generate-blowfish-key', methods=['POST'])
def generate_blowfish_key():
    try:
        data = request.json
        key_length = int(data.get('key_length', 256)) // 8  # Convert bits to bytes

        # Ensure key length is between 4 and 56 bytes (32 to 448 bits)
        key_length = max(4, min(key_length, 56))

        # Generate random key and IV
        key = get_random_bytes(key_length)
        iv = get_random_bytes(8)  # Blowfish block size is 8 bytes

        # Return base64 encoded key and IV
        key_b64 = base64.b64encode(key).decode('utf-8')
        iv_b64 = base64.b64encode(iv).decode('utf-8')

        print(f"Blowfish key generation successful: {key_b64[:15]}...")
        return jsonify({
            'key': key_b64,
            'iv': iv_b64
        })
    except Exception as e:
        print(f"Blowfish key generation error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# RC4 Key Generation
@app.route('/generate-rc4-key', methods=['POST'])
def generate_rc4_key():
    try:
        data = request.json
        key_length = int(data.get('key_length', 128)) // 8  # Convert bits to bytes

        # Generate random key (RC4 doesn't use IV)
        key = get_random_bytes(key_length)

        # Return base64 encoded key
        key_b64 = base64.b64encode(key).decode('utf-8')

        print(f"RC4 key generation successful: {key_b64[:15]}...")
        return jsonify({
            'key': key_b64
        })
    except Exception as e:
        print(f"RC4 key generation error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Twofish Key Generation
@app.route('/generate-twofish-key', methods=['POST'])
def generate_twofish_key():
    try:
        data = request.json
        key_length = int(data.get('key_length', 256)) // 8  # Convert bits to bytes

        # Ensure key length is one of the valid Twofish key sizes (16, 24, or 32 bytes)
        valid_lengths = [16, 24, 32]  # 128, 192, or 256 bits
        key_length = min(valid_lengths, key=lambda x: abs(x - key_length))

        # Generate random key and IV
        key = get_random_bytes(key_length)
        iv = get_random_bytes(16)  # Twofish block size is 16 bytes

        # Return base64 encoded key and IV
        key_b64 = base64.b64encode(key).decode('utf-8')
        iv_b64 = base64.b64encode(iv).decode('utf-8')

        print(f"Twofish key generation successful: {key_b64[:15]}...")
        return jsonify({
            'key': key_b64,
            'iv': iv_b64
        })
    except Exception as e:
        print(f"Twofish key generation error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# RC5 Key Generation
@app.route('/generate-rc5-key', methods=['POST'])
def generate_rc5_key():
    try:
        data = request.json
        key_length = int(data.get('key_length', 16))  # Default to 16 bytes (128 bits)
        rounds = int(data.get('rounds', 12))  # Default to 12 rounds

        # Generate random key and IV
        key = get_random_bytes(key_length)
        iv = get_random_bytes(8)  # RC5 block size is 8 bytes

        # Return base64 encoded key and IV
        key_b64 = base64.b64encode(key).decode('utf-8')
        iv_b64 = base64.b64encode(iv).decode('utf-8')

        print(f"RC5 key generation successful: {key_b64[:15]}...")
        return jsonify({
            'key': key_b64,
            'iv': iv_b64,
            'rounds': rounds
        })
    except Exception as e:
        print(f"RC5 key generation error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ChaCha20 Key Generation
@app.route('/generate-chacha20-key', methods=['POST'])
def generate_chacha20_key():
    try:
        # ChaCha20 uses a 256-bit key (32 bytes) and a 96-bit nonce (12 bytes)
        key = get_random_bytes(32)
        nonce = get_random_bytes(12)

        # Return base64 encoded key and nonce
        key_b64 = base64.b64encode(key).decode('utf-8')
        nonce_b64 = base64.b64encode(nonce).decode('utf-8')

        print(f"ChaCha20 key generation successful: {key_b64[:15]}...")
        return jsonify({
            'key': key_b64,
            'nonce': nonce_b64
        })
    except Exception as e:
        print(f"ChaCha20 key generation error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Salsa20 Key Generation
@app.route('/generate-salsa20-key', methods=['POST'])
def generate_salsa20_key():
    try:
        data = request.json
        key_size = int(data.get('key_size', 256)) // 8  # Convert bits to bytes

        # Ensure key size is either 16 or 32 bytes (128 or 256 bits)
        if key_size != 16 and key_size != 32:
            key_size = 32  # Default to 256 bits

        # Generate random key and nonce
        key = get_random_bytes(key_size)
        nonce = get_random_bytes(8)  # Salsa20 uses an 8-byte nonce

        # Return base64 encoded key and nonce
        key_b64 = base64.b64encode(key).decode('utf-8')
        nonce_b64 = base64.b64encode(nonce).decode('utf-8')

        print(f"Salsa20 key generation successful: {key_b64[:15]}...")
        return jsonify({
            'key': key_b64,
            'nonce': nonce_b64
        })
    except Exception as e:
        print(f"Salsa20 key generation error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Camellia Key Generation
@app.route('/generate-camellia-key', methods=['POST'])
def generate_camellia_key():
    try:
        data = request.json
        key_size = int(data.get('key_size', 256))

        # Ensure key size is one of the valid Camellia key sizes (128, 192, or 256 bits)
        valid_sizes = [128, 192, 256]
        if key_size not in valid_sizes:
            key_size = min(valid_sizes, key=lambda x: abs(x - key_size))

        # Convert bits to bytes
        key_length = key_size // 8

        # Generate random key and IV
        key = get_random_bytes(key_length)
        iv = get_random_bytes(16)  # Camellia block size is 16 bytes

        # Return base64 encoded key and IV
        key_b64 = base64.b64encode(key).decode('utf-8')
        iv_b64 = base64.b64encode(iv).decode('utf-8')

        print(f"Camellia key generation successful: {key_b64[:15]}...")
        return jsonify({
            'key': key_b64,
            'iv': iv_b64
        })
    except Exception as e:
        print(f"Camellia key generation error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Camellia Encryption
@app.route('/symmetric/camellia/encrypt', methods=['POST'])
def camellia_encrypt_file():
    if 'file' not in request.files or 'key' not in request.form or 'iv' not in request.form:
        return jsonify({'error': 'Missing file, key, or IV'}), 400

    file = request.files['file']
    key_b64 = request.form['key']
    iv_b64 = request.form['iv']
    key_size = int(request.form.get('key_size', 256))

    try:
        # Import Camellia from pycryptodome
        from Crypto.Cipher import Camellia

        # Decode key and IV from base64
        key = base64.b64decode(key_b64)
        iv = base64.b64decode(iv_b64)

        # Read file data
        file_data = file.read()

        # Create Camellia cipher
        cipher = Camellia.new(key, Camellia.MODE_CBC, iv)

        # Pad data to be a multiple of 16 bytes (Camellia block size)
        block_size = 16
        padded_data = pad(file_data, block_size)

        # Encrypt data
        encrypted_data = cipher.encrypt(padded_data)

        # Prepend IV to encrypted data for decryption later
        result_data = iv + encrypted_data

        # Create response with encrypted data
        return send_file(
            io.BytesIO(result_data),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=f'camellia_encrypted_{file.filename}'
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# Camellia Decryption
@app.route('/symmetric/camellia/decrypt', methods=['POST'])
def camellia_decrypt_file():
    if 'file' not in request.files or 'key' not in request.form or 'iv' not in request.form:
        return jsonify({'error': 'Missing file, key, or IV'}), 400

    file = request.files['file']
    key_b64 = request.form['key']
    iv_b64 = request.form['iv']
    key_size = int(request.form.get('key_size', 256))

    try:
        # Import Camellia from pycryptodome
        from Crypto.Cipher import Camellia

        # Decode key and IV from base64
        key = base64.b64decode(key_b64)
        iv = base64.b64decode(iv_b64)

        # Read file data
        file_data = file.read()

        # Create Camellia cipher
        cipher = Camellia.new(key, Camellia.MODE_CBC, iv)

        # Extract encrypted data (skip first 16 bytes which is the IV)
        encrypted_data = file_data[16:]

        # Decrypt data
        decrypted_padded_data = cipher.decrypt(encrypted_data)

        # Remove padding
        block_size = 16
        decrypted_data = unpad(decrypted_padded_data, block_size)

        # Create response with decrypted data
        memory_file = io.BytesIO(decrypted_data)
        memory_file.seek(0)

        return send_file(
            memory_file,
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=f'decrypted_{file.filename.replace("camellia_encrypted_", "")}'
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# Serpent Key Generation
@app.route('/generate-serpent-key', methods=['POST'])
def generate_serpent_key():
    try:
        data = request.json
        key_length = int(data.get('key_length', 256)) // 8  # Convert bits to bytes

        # Ensure key length is one of the valid Serpent key sizes (16, 24, or 32 bytes)
        valid_lengths = [16, 24, 32]  # 128, 192, or 256 bits
        if key_length not in valid_lengths:
            key_length = min(valid_lengths, key=lambda x: abs(x - key_length))

        # Generate random key and IV
        key = get_random_bytes(key_length)
        iv = get_random_bytes(16)  # Serpent block size is 16 bytes

        # Return base64 encoded key and IV
        key_b64 = base64.b64encode(key).decode('utf-8')
        iv_b64 = base64.b64encode(iv).decode('utf-8')

        print(f"Serpent key generation successful: {key_b64[:15]}...")
        return jsonify({
            'key': key_b64,
            'iv': iv_b64
        })
    except Exception as e:
        print(f"Serpent key generation error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# CAST Key Generation
@app.route('/generate-cast-key', methods=['POST'])
def generate_cast_key():
    try:
        data = request.json
        variant = data.get('variant', 'cast5')
        key_size = int(data.get('key_size', 128)) // 8  # Convert bits to bytes

        # CAST-128 (CAST5) uses 5-16 bytes, CAST-256 uses 16-32 bytes
        if variant.lower() == 'cast5':
            # Ensure key length is between 5 and 16 bytes for CAST-128
            key_size = max(5, min(key_size, 16))
            block_size = 8  # CAST-128 block size is 8 bytes
        else:  # CAST-256
            # Ensure key length is between 16 and 32 bytes for CAST-256
            key_size = max(16, min(key_size, 32))
            block_size = 16  # CAST-256 block size is 16 bytes

        # Generate random key and IV
        key = get_random_bytes(key_size)
        iv = get_random_bytes(block_size)

        # Return base64 encoded key and IV
        key_b64 = base64.b64encode(key).decode('utf-8')
        iv_b64 = base64.b64encode(iv).decode('utf-8')

        print(f"CAST key generation successful (variant: {variant}): {key_b64[:15]}...")
        return jsonify({
            'key': key_b64,
            'iv': iv_b64
        })
    except Exception as e:
        print(f"CAST key generation error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# IDEA Key Generation
@app.route('/generate-idea-key', methods=['POST'])
def generate_idea_key():
    try:
        # IDEA uses a 128-bit key (16 bytes) and an 8-byte IV
        key = get_random_bytes(16)
        iv = get_random_bytes(8)  # IDEA block size is 8 bytes

        # Return base64 encoded key and IV
        key_b64 = base64.b64encode(key).decode('utf-8')
        iv_b64 = base64.b64encode(iv).decode('utf-8')

        print(f"IDEA key generation successful: {key_b64[:15]}...")
        return jsonify({
            'key': key_b64,
            'iv': iv_b64
        })
    except Exception as e:
        print(f"IDEA key generation error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Skipjack Key Generation
@app.route('/generate-skipjack-key', methods=['POST'])
def generate_skipjack_key():
    try:
        # Skipjack uses an 80-bit key (10 bytes) and an 8-byte IV
        key = get_random_bytes(10)
        iv = get_random_bytes(8)  # Skipjack block size is 8 bytes

        # Return base64 encoded key and IV
        key_b64 = base64.b64encode(key).decode('utf-8')
        iv_b64 = base64.b64encode(iv).decode('utf-8')

        print(f"Skipjack key generation successful: {key_b64[:15]}...")
        return jsonify({
            'key': key_b64,
            'iv': iv_b64
        })
    except Exception as e:
        print(f"Skipjack key generation error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# XTEA Key Generation
@app.route('/generate-xtea-key', methods=['POST'])
def generate_xtea_key():
    try:
        data = request.json
        rounds = int(data.get('rounds', 32))  # Default to 32 rounds

        # XTEA uses a 128-bit key (16 bytes) and an 8-byte IV
        key = get_random_bytes(16)
        iv = get_random_bytes(8)  # XTEA block size is 8 bytes

        # Return base64 encoded key and IV
        key_b64 = base64.b64encode(key).decode('utf-8')
        iv_b64 = base64.b64encode(iv).decode('utf-8')

        print(f"XTEA key generation successful: {key_b64[:15]}...")
        return jsonify({
            'key': key_b64,
            'iv': iv_b64,
            'rounds': rounds
        })
    except Exception as e:
        print(f"XTEA key generation error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/symmetric/blowfish/encrypt', methods=['POST'])
def blowfish_encrypt_file():
    if 'file' not in request.files or 'key' not in request.form or 'iv' not in request.form:
        return jsonify({'error': 'Missing file, key, or IV'}), 400

    file = request.files['file']
    key_b64 = request.form['key']
    iv_b64 = request.form['iv']

    try:
        # Decode key and IV from base64
        key = base64.b64decode(key_b64)
        iv = base64.b64decode(iv_b64)

        # Read file data
        file_data = file.read()

        # Create Blowfish cipher
        cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)

        # Pad data to be a multiple of 8 bytes (Blowfish block size)
        block_size = 8
        padded_data = pad(file_data, block_size)

        # Encrypt data
        encrypted_data = cipher.encrypt(padded_data)

        # Prepend IV to encrypted data for decryption later
        result_data = iv + encrypted_data

        # Create response with encrypted data
        return send_file(
            io.BytesIO(result_data),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=f'blowfish_encrypted_{file.filename}'
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/symmetric/blowfish/decrypt', methods=['POST'])
def blowfish_decrypt_file():
    if 'file' not in request.files or 'key' not in request.form or 'iv' not in request.form:
        return jsonify({'error': 'Missing file, key, or IV'}), 400

    file = request.files['file']
    key_b64 = request.form['key']
    iv_b64 = request.form['iv']

    try:
        # Decode key and IV from base64
        key = base64.b64decode(key_b64)
        iv = base64.b64decode(iv_b64)

        # Read file data
        file_data = file.read()

        # Create Blowfish cipher
        cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)

        # Extract encrypted data (skip first 8 bytes which is the IV)
        encrypted_data = file_data[8:]

        # Decrypt data
        decrypted_padded_data = cipher.decrypt(encrypted_data)

        # Remove padding
        block_size = 8
        decrypted_data = unpad(decrypted_padded_data, block_size)

        # Create response with decrypted data
        memory_file = io.BytesIO(decrypted_data)
        memory_file.seek(0)

        return send_file(
            memory_file,
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=f'decrypted_{file.filename.replace("blowfish_encrypted_", "")}'
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# ECC Key Generation and Encryption/Decryption
@app.route('/generate-ecc-keys', methods=['POST'])
def generate_ecc_keys():
    data = request.json
    curve_name = data.get('curve', 'secp256r1')

    try:
        # Generate ECC key pair
        key = ECC.generate(curve=curve_name)
        private_key = key
        public_key = key.public_key()

        # Serialize keys
        private_pem = private_key.export_key(format='PEM')
        public_pem = public_key.export_key(format='PEM')

        return jsonify({
            'private_key': private_pem,
            'public_key': public_pem
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/asymmetric/ecc/generate-keys', methods=['POST'])
def generate_ecc_keys_endpoint():
    data = request.json
    curve_name = data.get('curve', 'secp256r1')

    try:
        # Generate ECC key pair
        key = ECC.generate(curve=curve_name)
        private_key = key
        public_key = key.public_key()

        # Serialize keys
        private_pem = private_key.export_key(format='PEM')
        public_pem = public_key.export_key(format='PEM')

        print(f"ECC key generation successful: {private_pem[:30]}...")
        return jsonify({
            'private_key': private_pem,
            'public_key': public_pem
        })
    except Exception as e:
        print(f"ECC key generation error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# DSA Key Generation
@app.route('/asymmetric/dsa/generate-keys', methods=['POST'])
def generate_dsa_keys():
    data = request.json
    key_size = int(data.get('key_size', 2048))

    try:
        # Import DSA module
        from Crypto.PublicKey import DSA

        # Generate DSA key pair
        key = DSA.generate(bits=key_size)

        # Serialize keys
        private_pem = key.export_key(format='PEM')
        public_pem = key.publickey().export_key(format='PEM')

        print(f"DSA key generation successful: {private_pem[:30]}...")
        return jsonify({
            'private_key': private_pem.decode() if isinstance(private_pem, bytes) else private_pem,
            'public_key': public_pem.decode() if isinstance(public_pem, bytes) else public_pem
        })
    except Exception as e:
        print(f"DSA key generation error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ElGamal Key Generation
@app.route('/asymmetric/elgamal/generate-keys', methods=['POST'])
def generate_elgamal_keys():
    try:
        data = request.json
        key_size = int(data.get('key_size', 2048))

        # For ElGamal, we'll use the PyCryptodome implementation
        # which is based on the Discrete Logarithm Problem (DLP)
        from Crypto.PublicKey import ElGamal

        # Generate ElGamal key pair
        key = ElGamal.generate(bits=key_size, randfunc=get_random_bytes)

        # Serialize keys (ElGamal doesn't have direct PEM export, so we'll use a custom format)
        private_key = {
            'p': str(key.p),
            'g': str(key.g),
            'y': str(key.y),
            'x': str(key.x)
        }

        public_key = {
            'p': str(key.p),
            'g': str(key.g),
            'y': str(key.y)
        }

        import json
        private_key_json = json.dumps(private_key)
        public_key_json = json.dumps(public_key)

        print(f"ElGamal key generation successful: {private_key_json[:30]}...")
        return jsonify({
            'private_key': private_key_json,
            'public_key': public_key_json
        })
    except Exception as e:
        print(f"ElGamal key generation error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# NTRU Key Generation
@app.route('/asymmetric/ntru/generate-keys', methods=['POST'])
def generate_ntru_keys():
    try:
        data = request.json
        parameter_set = data.get('parameter_set', 'ntru-hps2048677')

        # For demonstration purposes, we'll generate a simulated NTRU key pair
        # In a real implementation, you would use a library like liboqs or pqcrypto

        # Generate random "keys" with appropriate structure
        private_key = {
            'parameter_set': parameter_set,
            'f': base64.b64encode(get_random_bytes(256)).decode('utf-8'),
            'h': base64.b64encode(get_random_bytes(256)).decode('utf-8'),
            'g': base64.b64encode(get_random_bytes(256)).decode('utf-8')
        }

        public_key = {
            'parameter_set': parameter_set,
            'h': private_key['h']
        }

        import json
        private_key_json = json.dumps(private_key)
        public_key_json = json.dumps(public_key)

        print(f"NTRU key generation successful: {parameter_set}")
        return jsonify({
            'private_key': private_key_json,
            'public_key': public_key_json
        })
    except Exception as e:
        print(f"NTRU key generation error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/quantum/ntru/generate-keys', methods=['POST'])
def generate_quantum_ntru_keys():
    try:
        data = request.json
        parameter_set = data.get('parameter_set', 'ntru-hps2048677')

        # For demonstration purposes, we'll generate a simulated NTRU key pair
        # In a real implementation, you would use a library like liboqs or pqcrypto

        # Generate random "keys" with appropriate structure
        private_key = {
            'parameter_set': parameter_set,
            'f': base64.b64encode(get_random_bytes(256)).decode('utf-8'),
            'h': base64.b64encode(get_random_bytes(256)).decode('utf-8'),
            'g': base64.b64encode(get_random_bytes(256)).decode('utf-8')
        }

        public_key = {
            'parameter_set': parameter_set,
            'h': private_key['h']
        }

        import json
        private_key_json = json.dumps(private_key)
        public_key_json = json.dumps(public_key)

        print(f"Quantum NTRU key generation successful: {parameter_set}")
        return jsonify({
            'private_key': private_key_json,
            'public_key': public_key_json
        })
    except Exception as e:
        print(f"Quantum NTRU key generation error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# McEliece Key Generation
@app.route('/quantum/mceliece/generate-keys', methods=['POST'])
def generate_mceliece_keys():
    try:
        data = request.json
        parameter_set = data.get('parameter_set', 'mceliece348864')

        # For demonstration purposes, we'll generate a simulated McEliece key pair
        # In a real implementation, you would use a library like liboqs or pqcrypto

        # Generate random "keys" with appropriate structure
        private_key = {
            'parameter_set': parameter_set,
            'S': base64.b64encode(get_random_bytes(256)).decode('utf-8'),
            'G': base64.b64encode(get_random_bytes(512)).decode('utf-8'),
            'P': base64.b64encode(get_random_bytes(256)).decode('utf-8')
        }

        public_key = {
            'parameter_set': parameter_set,
            'G_pub': base64.b64encode(get_random_bytes(1024)).decode('utf-8')
        }

        import json
        private_key_json = json.dumps(private_key)
        public_key_json = json.dumps(public_key)

        print(f"McEliece key generation successful: {parameter_set}")
        return jsonify({
            'private_key': private_key_json,
            'public_key': public_key_json
        })
    except Exception as e:
        print(f"McEliece key generation error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# McEliece Key Generation (Asymmetric route)
@app.route('/asymmetric/mceliece/generate-keys', methods=['POST'])
def generate_asymmetric_mceliece_keys():
    try:
        data = request.json
        security_level = data.get('security_level', 'mceliece460896')

        # Map security_level to parameter_set
        parameter_set = security_level

        # For demonstration purposes, we'll generate a simulated McEliece key pair
        # In a real implementation, you would use a library like liboqs or pqcrypto

        # Generate random "keys" with appropriate structure
        private_key = {
            'parameter_set': parameter_set,
            'S': base64.b64encode(get_random_bytes(256)).decode('utf-8'),
            'G': base64.b64encode(get_random_bytes(512)).decode('utf-8'),
            'P': base64.b64encode(get_random_bytes(256)).decode('utf-8')
        }

        public_key = {
            'parameter_set': parameter_set,
            'G_pub': base64.b64encode(get_random_bytes(1024)).decode('utf-8')
        }

        import json
        private_key_json = json.dumps(private_key)
        public_key_json = json.dumps(public_key)

        print(f"Asymmetric McEliece key generation successful: {parameter_set}")
        return jsonify({
            'private_key': private_key_json,
            'public_key': public_key_json
        })
    except Exception as e:
        print(f"Asymmetric McEliece key generation error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# NTRU Key Generation (Asymmetric route)
@app.route('/asymmetric/ntru/generate-keys', methods=['POST'])
def generate_asymmetric_ntru_keys():
    try:
        data = request.json
        parameter_set = data.get('parameter_set', 'ntru-hps2048677')

        # For demonstration purposes, we'll generate a simulated NTRU key pair
        # In a real implementation, you would use a library like liboqs or pqcrypto

        # Generate random "keys" with appropriate structure
        private_key_data = get_random_bytes(1024)  # Size depends on parameter set
        public_key_data = get_random_bytes(1024)   # Size depends on parameter set

        # Encode keys in base64 for JSON transport
        private_key_b64 = base64.b64encode(private_key_data).decode('utf-8')
        public_key_b64 = base64.b64encode(public_key_data).decode('utf-8')

        print(f"NTRU key generation successful: {parameter_set}")
        return jsonify({
            'private_key': private_key_b64,
            'public_key': public_key_b64,
            'parameter_set': parameter_set
        })
    except Exception as e:
        print(f"NTRU key generation error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# NTRU Encryption
@app.route('/asymmetric/ntru/encrypt', methods=['POST'])
def ntru_encrypt_file():
    if 'file' not in request.files or 'public_key' not in request.form:
        return jsonify({'error': 'Missing file or public key'}), 400

    file = request.files['file']
    public_key_b64 = request.form['public_key']
    parameter_set = request.form.get('parameter_set', 'ntru-hps2048677')

    try:
        # Decode public key from base64
        public_key_data = base64.b64decode(public_key_b64)

        # Read file data
        file_data = file.read()

        # For demonstration purposes, we'll simulate NTRU encryption
        # In a real implementation, you would use a library like liboqs or pqcrypto

        # Generate a random AES key for hybrid encryption
        aes_key = get_random_bytes(32)  # 256-bit AES key

        # Encrypt the file with AES
        iv = get_random_bytes(16)
        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
        padded_data = pad(file_data, AES.block_size)
        encrypted_file_data = cipher_aes.encrypt(padded_data)

        # Simulate NTRU encryption of the AES key
        # In a real implementation, this would use the NTRU algorithm
        # Here we just prepend a header to identify it as NTRU encrypted
        ntru_header = parameter_set.encode('utf-8') + b'\0' * (32 - len(parameter_set))
        encrypted_aes_key = ntru_header + get_random_bytes(256)  # Simulated NTRU ciphertext

        # Combine everything: [NTRU encrypted AES key][IV][AES encrypted file]
        result_data = encrypted_aes_key + iv + encrypted_file_data

        # Create response with encrypted data
        return send_file(
            io.BytesIO(result_data),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=f'ntru_encrypted_{file.filename}'
        )
    except Exception as e:
        print(f"NTRU encryption error: {str(e)}")
        return jsonify({'error': str(e)}), 400

# NTRU Decryption
@app.route('/asymmetric/ntru/decrypt', methods=['POST'])
def ntru_decrypt_file():
    if 'file' not in request.files or 'private_key' not in request.form:
        return jsonify({'error': 'Missing file or private key'}), 400

    file = request.files['file']
    private_key_b64 = request.form['private_key']
    parameter_set = request.form.get('parameter_set', 'ntru-hps2048677')

    try:
        # Decode private key from base64
        private_key_data = base64.b64decode(private_key_b64)

        # Read file data
        file_data = file.read()

        # For demonstration purposes, we'll simulate NTRU decryption
        # In a real implementation, you would use a library like liboqs or pqcrypto

        # Extract the NTRU encrypted AES key (first 288 bytes: 32 byte header + 256 byte ciphertext)
        ntru_ciphertext = file_data[:288]

        # Extract the IV (next 16 bytes)
        iv = file_data[288:304]

        # Extract the AES encrypted file data (remaining bytes)
        encrypted_file_data = file_data[304:]

        # Simulate NTRU decryption of the AES key
        # In a real implementation, this would use the NTRU algorithm
        # Here we just generate a random AES key as if it was decrypted
        aes_key = get_random_bytes(32)  # Simulated decrypted AES key

        # Decrypt the file with AES
        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
        decrypted_padded_data = cipher_aes.decrypt(encrypted_file_data)
        decrypted_data = unpad(decrypted_padded_data, AES.block_size)

        # Create response with decrypted data
        memory_file = io.BytesIO(decrypted_data)
        memory_file.seek(0)

        return send_file(
            memory_file,
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=f'decrypted_{file.filename.replace("ntru_encrypted_", "")}'
        )
    except Exception as e:
        print(f"NTRU decryption error: {str(e)}")
        return jsonify({'error': str(e)}), 400

# Kyber Key Generation
@app.route('/quantum/kyber/generate-keys', methods=['POST'])
def generate_kyber_keys():
    try:
        data = request.json
        security_level = data.get('security_level', '768')

        # For demonstration purposes, we'll generate a simulated Kyber key pair
        # In a real implementation, you would use a library like liboqs or pqcrypto

        # Generate random "keys" with appropriate structure
        private_key = {
            'security_level': security_level,
            's': base64.b64encode(get_random_bytes(256)).decode('utf-8'),
            'seed': base64.b64encode(get_random_bytes(32)).decode('utf-8')
        }

        public_key = {
            'security_level': security_level,
            'A': base64.b64encode(get_random_bytes(512)).decode('utf-8'),
            'b': base64.b64encode(get_random_bytes(256)).decode('utf-8')
        }

        import json
        private_key_json = json.dumps(private_key)
        public_key_json = json.dumps(public_key)

        print(f"Kyber key generation successful: Kyber-{security_level}")
        return jsonify({
            'private_key': private_key_json,
            'public_key': public_key_json
        })
    except Exception as e:
        print(f"Kyber key generation error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Kyber Encapsulation
@app.route('/quantum/kyber/encapsulate', methods=['POST'])
def kyber_encapsulate():
    try:
        data = request.json
        public_key = data.get('public_key', '')
        security_level = data.get('security_level', '768')

        # For demonstration purposes, we'll simulate Kyber encapsulation
        # In a real implementation, you would use a library like liboqs or pqcrypto

        # Generate a random shared secret and ciphertext
        shared_secret = base64.b64encode(get_random_bytes(32)).decode('utf-8')  # 256-bit shared secret
        ciphertext = base64.b64encode(get_random_bytes(1024)).decode('utf-8')  # Size depends on security level

        print(f"Kyber encapsulation successful: Kyber-{security_level}")
        return jsonify({
            'shared_secret': shared_secret,
            'ciphertext': ciphertext
        })
    except Exception as e:
        print(f"Kyber encapsulation error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Kyber Decapsulation
@app.route('/quantum/kyber/decapsulate', methods=['POST'])
def kyber_decapsulate():
    try:
        data = request.json
        ciphertext = data.get('ciphertext', '')
        private_key = data.get('private_key', '')
        security_level = data.get('security_level', '768')

        # For demonstration purposes, we'll simulate Kyber decapsulation
        # In a real implementation, you would use a library like liboqs or pqcrypto

        # Generate the same shared secret as in encapsulation (in a real implementation, this would be derived from the ciphertext and private key)
        shared_secret = base64.b64encode(get_random_bytes(32)).decode('utf-8')  # 256-bit shared secret

        print(f"Kyber decapsulation successful: Kyber-{security_level}")
        return jsonify({
            'shared_secret': shared_secret
        })
    except Exception as e:
        print(f"Kyber decapsulation error: {str(e)}")
        return jsonify({'error': str(e)}), 500


# Dilithium Key Generation
@app.route('/quantum/dilithium/generate-keys', methods=['POST'])
def generate_dilithium_keys():
    try:
        data = request.json
        security_level = data.get('security_level', '3')

        # For demonstration purposes, we'll generate a simulated Dilithium key pair
        # In a real implementation, you would use a library like liboqs or pqcrypto

        # Generate random "keys" with appropriate structure
        private_key = {
            'security_level': security_level,
            'rho': base64.b64encode(get_random_bytes(32)).decode('utf-8'),
            'K': base64.b64encode(get_random_bytes(256)).decode('utf-8'),
            'tr': base64.b64encode(get_random_bytes(32)).decode('utf-8'),
            's1': base64.b64encode(get_random_bytes(512)).decode('utf-8'),
            's2': base64.b64encode(get_random_bytes(512)).decode('utf-8')
        }

        public_key = {
            'security_level': security_level,
            'rho': private_key['rho'],
            't1': base64.b64encode(get_random_bytes(512)).decode('utf-8')
        }

        import json
        private_key_json = json.dumps(private_key)
        public_key_json = json.dumps(public_key)

        print(f"Dilithium key generation successful: Dilithium{security_level}")
        return jsonify({
            'private_key': private_key_json,
            'public_key': public_key_json
        })
    except Exception as e:
        print(f"Dilithium key generation error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Dilithium Sign
@app.route('/quantum/dilithium/sign', methods=['POST'])
def dilithium_sign():
    try:
        data = request.json
        message = data.get('message', '')
        private_key_json = data.get('private_key', '')
        security_level = data.get('security_level', '3')

        # For demonstration purposes, we'll simulate Dilithium signing
        # In a real implementation, you would use a library like liboqs or pqcrypto

        # Parse the private key
        try:
            import json
            private_key = json.loads(private_key_json)
        except:
            # If parsing fails, assume it's a base64 encoded key
            private_key = {'security_level': security_level}

        # Generate a random signature
        # In a real implementation, this would be derived from the message and private key
        signature_size = 2000 + (int(security_level) * 500)  # Size depends on security level
        signature = base64.b64encode(get_random_bytes(signature_size)).decode('utf-8')

        print(f"Dilithium signing successful: Dilithium{security_level}")
        return jsonify({
            'signature': signature
        })
    except Exception as e:
        print(f"Dilithium signing error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Dilithium Verify
@app.route('/quantum/dilithium/verify', methods=['POST'])
def dilithium_verify():
    try:
        data = request.json
        message = data.get('message', '')
        signature = data.get('signature', '')
        public_key_json = data.get('public_key', '')
        security_level = data.get('security_level', '3')

        # For demonstration purposes, we'll simulate Dilithium verification
        # In a real implementation, you would use a library like liboqs or pqcrypto

        # Parse the public key
        try:
            import json
            public_key = json.loads(public_key_json)
        except:
            # If parsing fails, assume it's a base64 encoded key
            public_key = {'security_level': security_level}

        # Simulate verification (always returns valid for demonstration)
        # In a real implementation, this would check if the signature is valid for the message using the public key
        valid = True

        print(f"Dilithium verification successful: Dilithium{security_level}")
        return jsonify({
            'valid': valid
        })
    except Exception as e:
        print(f"Dilithium verification error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Falcon Key Generation
@app.route('/quantum/falcon/generate-keys', methods=['POST'])
def generate_falcon_keys():
    try:
        data = request.json
        degree = data.get('degree', '512')

        # For demonstration purposes, we'll generate a simulated Falcon key pair
        # In a real implementation, you would use a library like liboqs or pqcrypto

        # Generate random "keys" with appropriate structure
        private_key = {
            'degree': degree,
            'f': base64.b64encode(get_random_bytes(256)).decode('utf-8'),
            'g': base64.b64encode(get_random_bytes(256)).decode('utf-8'),
            'F': base64.b64encode(get_random_bytes(256)).decode('utf-8'),
            'G': base64.b64encode(get_random_bytes(256)).decode('utf-8')
        }

        public_key = {
            'degree': degree,
            'h': base64.b64encode(get_random_bytes(512)).decode('utf-8')
        }

        import json
        private_key_json = json.dumps(private_key)
        public_key_json = json.dumps(public_key)

        print(f"Falcon key generation successful: Falcon-{degree}")
        return jsonify({
            'private_key': private_key_json,
            'public_key': public_key_json
        })
    except Exception as e:
        print(f"Falcon key generation error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# SPHINCS+ Key Generation
@app.route('/quantum/sphincs/generate-keys', methods=['POST'])
def generate_sphincs_keys():
    try:
        data = request.json
        parameter_set = data.get('parameter_set', 'shake-128s')

        # For demonstration purposes, we'll generate a simulated SPHINCS+ key pair
        # In a real implementation, you would use a library like liboqs or pqcrypto

        # Generate random "keys" with appropriate structure
        private_key = {
            'parameter_set': parameter_set,
            'seed': base64.b64encode(get_random_bytes(96)).decode('utf-8')
        }

        public_key = {
            'parameter_set': parameter_set,
            'root': base64.b64encode(get_random_bytes(32)).decode('utf-8'),
            'pub_seed': base64.b64encode(get_random_bytes(32)).decode('utf-8')
        }

        import json
        private_key_json = json.dumps(private_key)
        public_key_json = json.dumps(public_key)

        print(f"SPHINCS+ key generation successful: {parameter_set}")
        return jsonify({
            'private_key': private_key_json,
            'public_key': public_key_json
        })
    except Exception as e:
        print(f"SPHINCS+ key generation error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# BIKE Key Generation
@app.route('/quantum/bike/generate-keys', methods=['POST'])
def generate_bike_keys():
    try:
        data = request.json
        security_level = data.get('security_level', '1')

        # For demonstration purposes, we'll generate a simulated BIKE key pair
        # In a real implementation, you would use a library like liboqs or pqcrypto

        # Generate random "keys" with appropriate structure
        private_key = {
            'security_level': security_level,
            'h': base64.b64encode(get_random_bytes(256)).decode('utf-8'),
            'sigma': base64.b64encode(get_random_bytes(32)).decode('utf-8')
        }

        public_key = {
            'security_level': security_level,
            'h': private_key['h']
        }

        import json
        private_key_json = json.dumps(private_key)
        public_key_json = json.dumps(public_key)

        print(f"BIKE key generation successful: BIKE-{security_level}")
        return jsonify({
            'private_key': private_key_json,
            'public_key': public_key_json
        })
    except Exception as e:
        print(f"BIKE key generation error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# SIKE Key Generation
@app.route('/quantum/sike/generate-keys', methods=['POST'])
def generate_sike_keys():
    try:
        data = request.json
        parameter_set = data.get('parameter_set', 'p434')

        # For demonstration purposes, we'll generate a simulated SIKE key pair
        # In a real implementation, you would use a library like liboqs or pqcrypto

        # Generate random "keys" with appropriate structure
        private_key = {
            'parameter_set': parameter_set,
            'sk': base64.b64encode(get_random_bytes(32)).decode('utf-8')
        }

        public_key = {
            'parameter_set': parameter_set,
            'pk': base64.b64encode(get_random_bytes(330)).decode('utf-8')
        }

        import json
        private_key_json = json.dumps(private_key)
        public_key_json = json.dumps(public_key)

        print(f"SIKE key generation successful: SIKE-{parameter_set}")
        return jsonify({
            'private_key': private_key_json,
            'public_key': public_key_json
        })
    except Exception as e:
        print(f"SIKE key generation error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# GeMSS Key Generation
@app.route('/quantum/gemss/generate-keys', methods=['POST'])
def generate_gemss_keys():
    try:
        data = request.json
        parameter_set = data.get('parameter_set', '128')

        # For demonstration purposes, we'll generate a simulated GeMSS key pair
        # In a real implementation, you would use a library like liboqs or pqcrypto

        # Generate random "keys" with appropriate structure
        private_key = {
            'parameter_set': parameter_set,
            'S': base64.b64encode(get_random_bytes(512)).decode('utf-8'),
            'seed': base64.b64encode(get_random_bytes(32)).decode('utf-8')
        }

        public_key = {
            'parameter_set': parameter_set,
            'P': base64.b64encode(get_random_bytes(1024)).decode('utf-8')
        }

        import json
        private_key_json = json.dumps(private_key)
        public_key_json = json.dumps(public_key)

        print(f"GeMSS key generation successful: GeMSS-{parameter_set}")
        return jsonify({
            'private_key': private_key_json,
            'public_key': public_key_json
        })
    except Exception as e:
        print(f"GeMSS key generation error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Picnic Key Generation
@app.route('/quantum/picnic/generate-keys', methods=['POST'])
def generate_picnic_keys():
    try:
        data = request.json
        parameter_set = data.get('parameter_set', 'L1FS')

        # For demonstration purposes, we'll generate a simulated Picnic key pair
        # In a real implementation, you would use a library like liboqs or pqcrypto

        # Generate random "keys" with appropriate structure
        private_key = {
            'parameter_set': parameter_set,
            'sk': base64.b64encode(get_random_bytes(32)).decode('utf-8'),
            'seed': base64.b64encode(get_random_bytes(32)).decode('utf-8')
        }

        public_key = {
            'parameter_set': parameter_set,
            'pk': base64.b64encode(get_random_bytes(32)).decode('utf-8')
        }

        import json
        private_key_json = json.dumps(private_key)
        public_key_json = json.dumps(public_key)

        print(f"Picnic key generation successful: Picnic-{parameter_set}")
        return jsonify({
            'private_key': private_key_json,
            'public_key': public_key_json
        })
    except Exception as e:
        print(f"Picnic key generation error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Rainbow Key Generation
@app.route('/quantum/rainbow/generate-keys', methods=['POST'])
def generate_rainbow_keys():
    try:
        data = request.json
        parameter_set = data.get('parameter_set', 'I')

        # For demonstration purposes, we'll generate a simulated Rainbow key pair
        # In a real implementation, you would use a library like liboqs or pqcrypto

        # Generate random "keys" with appropriate structure
        private_key = {
            'parameter_set': parameter_set,
            'S': base64.b64encode(get_random_bytes(512)).decode('utf-8'),
            'F': base64.b64encode(get_random_bytes(1024)).decode('utf-8'),
            'T': base64.b64encode(get_random_bytes(512)).decode('utf-8')
        }

        public_key = {
            'parameter_set': parameter_set,
            'P': base64.b64encode(get_random_bytes(1024)).decode('utf-8')
        }

        import json
        private_key_json = json.dumps(private_key)
        public_key_json = json.dumps(public_key)

        print(f"Rainbow key generation successful: Rainbow-{parameter_set}")
        return jsonify({
            'private_key': private_key_json,
            'public_key': public_key_json
        })
    except Exception as e:
        print(f"Rainbow key generation error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# BLAKE2 Hash Generation
@app.route('/hash/blake2/generate', methods=['POST'])
def generate_blake2_hash():
    try:
        data = request.json
        input_text = data.get('input', '')
        variant = data.get('variant', 'b')  # 'b' for BLAKE2b, 's' for BLAKE2s
        digest_size = data.get('size', 64 if variant.lower() == 'b' else 32)

        # Convert digest_size to int
        digest_size = int(digest_size)

        # Validate variant and digest size
        if variant.lower() not in ['b', 's']:
            variant = 'b'  # Default to BLAKE2b if invalid variant

        # BLAKE2b: 1-64 bytes, BLAKE2s: 1-32 bytes
        max_size = 64 if variant.lower() == 'b' else 32
        if digest_size < 1 or digest_size > max_size:
            digest_size = max_size  # Default to max size if invalid

        # Import BLAKE2 from hashlib
        from hashlib import blake2b, blake2s

        # Select the appropriate hash function
        if variant.lower() == 'b':
            hash_obj = blake2b(digest_size=digest_size)
        else:  # variant == 's'
            hash_obj = blake2s(digest_size=digest_size)

        # Generate the hash
        hash_obj.update(input_text.encode('utf-8'))
        hash_hex = hash_obj.hexdigest()

        print(f"BLAKE2 hash generation successful: BLAKE2{variant.upper()}-{digest_size*8}")
        return jsonify({
            'hash': hash_hex,
            'algorithm': f'BLAKE2{variant.upper()}-{digest_size*8}'
        })
    except Exception as e:
        print(f"BLAKE2 hash generation error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Argon2 Hash Generation
@app.route('/hash/argon2/generate', methods=['POST'])
def generate_argon2_hash():
    try:
        data = request.json
        password = data.get('password', '')
        variant = data.get('variant', 'id')  # 'i', 'd', or 'id'
        time_cost = int(data.get('time_cost', 2))
        memory_cost = int(data.get('memory_cost', 102400))  # 100 MB
        parallelism = int(data.get('parallelism', 8))

        # Check if Argon2 is available
        if not ARGON2_AVAILABLE:
            return jsonify({'error': 'Argon2 library is not available. Please install argon2-cffi.'}), 500

        # Validate variant
        if variant.lower() not in ['i', 'd', 'id']:
            variant = 'id'  # Default to Argon2id if invalid variant

        # Create PasswordHasher with specified parameters
        ph = PasswordHasher(
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=32,
            type=getattr(argon2.Type, variant.upper())
        )

        # Generate the hash
        hash_str = ph.hash(password)

        print(f"Argon2 hash generation successful: Argon2{variant}")
        return jsonify({
            'hash': hash_str,
            'algorithm': f'Argon2{variant}',
            'parameters': {
                'time_cost': time_cost,
                'memory_cost': memory_cost,
                'parallelism': parallelism
            }
        })
    except Exception as e:
        print(f"Argon2 hash generation error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ECC Encryption
@app.route('/asymmetric/ecc/encrypt', methods=['POST'])
def ecc_encrypt_file():
    if 'file' not in request.files or 'public_key' not in request.form:
        return jsonify({'error': 'Missing file or public key'}), 400

    file = request.files['file']
    public_key_pem = request.form['public_key']

    try:
        # Load public key
        recipient_key = ECC.import_key(public_key_pem)

        # Read file data
        file_data = file.read()

        # For ECC, we use a hybrid encryption scheme:
        # 1. Generate a random AES key
        # 2. Encrypt the file with the AES key
        # 3. Encrypt the AES key with the ECC public key
        # 4. Send both the encrypted file and the encrypted AES key

        # Generate a random AES key
        aes_key = get_random_bytes(32)  # 256-bit AES key

        # Encrypt the file with AES
        iv = get_random_bytes(16)
        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
        padded_data = pad(file_data, AES.block_size)
        encrypted_data = cipher_aes.encrypt(padded_data)

        # Encrypt the AES key with ECC
        # For simplicity, we'll use ECIES-like approach
        from Crypto.Protocol.KDF import HKDF
        from Crypto.Hash import SHA256

        # Generate ephemeral key pair
        ephemeral_key = ECC.generate(curve=recipient_key.curve)
        shared_point = recipient_key.pointQ * ephemeral_key.d

        # Derive shared secret
        shared_secret = shared_point.x.to_bytes()

        # Derive encryption key from shared secret
        key_derivation = HKDF(shared_secret, 32, None, SHA256)

        # Encrypt AES key
        cipher_key = AES.new(key_derivation, AES.MODE_CBC, iv)
        encrypted_key = cipher_key.encrypt(pad(aes_key, AES.block_size))

        # Combine everything: ephemeral public key + IV + encrypted key + encrypted data
        ephemeral_public = ephemeral_key.public_key().export_key(format='DER')
        result_data = len(ephemeral_public).to_bytes(2, byteorder='big') + ephemeral_public + iv + len(encrypted_key).to_bytes(2, byteorder='big') + encrypted_key + encrypted_data

        # Create response with encrypted data
        return send_file(
            io.BytesIO(result_data),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=f'ecc_encrypted_{file.filename}'
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/asymmetric/ecc/decrypt', methods=['POST'])
def ecc_decrypt_file():
    if 'file' not in request.files or 'private_key' not in request.form:
        return jsonify({'error': 'Missing file or private key'}), 400

    file = request.files['file']
    private_key_pem = request.form['private_key']

    try:
        # Load private key
        private_key = ECC.import_key(private_key_pem)

        # Read file data
        file_data = file.read()

        # Parse the data: ephemeral public key + IV + encrypted key + encrypted data
        pos = 0
        ephemeral_public_len = int.from_bytes(file_data[pos:pos+2], byteorder='big')
        pos += 2
        ephemeral_public_der = file_data[pos:pos+ephemeral_public_len]
        pos += ephemeral_public_len
        iv = file_data[pos:pos+16]
        pos += 16
        encrypted_key_len = int.from_bytes(file_data[pos:pos+2], byteorder='big')
        pos += 2
        encrypted_key = file_data[pos:pos+encrypted_key_len]
        pos += encrypted_key_len
        encrypted_data = file_data[pos:]

        # Import ephemeral public key
        ephemeral_public = ECC.import_key(ephemeral_public_der)

        # Compute shared point
        shared_point = ephemeral_public.pointQ * private_key.d

        # Derive shared secret
        shared_secret = shared_point.x.to_bytes()

        # Derive decryption key from shared secret
        from Crypto.Protocol.KDF import HKDF
        from Crypto.Hash import SHA256
        key_derivation = HKDF(shared_secret, 32, None, SHA256)

        # Decrypt AES key
        cipher_key = AES.new(key_derivation, AES.MODE_CBC, iv)
        padded_aes_key = cipher_key.decrypt(encrypted_key)
        aes_key = unpad(padded_aes_key, AES.block_size)

        # Decrypt file data with AES key
        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
        decrypted_padded_data = cipher_aes.decrypt(encrypted_data)
        decrypted_data = unpad(decrypted_padded_data, AES.block_size)

        # Create response with decrypted data
        memory_file = io.BytesIO(decrypted_data)
        memory_file.seek(0)

        return send_file(
            memory_file,
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=f'decrypted_{file.filename.replace("ecc_encrypted_", "")}'
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# MD5 Hash Generation
@app.route('/hash/md5/text', methods=['POST'])
def md5_hash_text():
    data = request.json
    text = data.get('text', '')

    # Generate MD5 hash
    md5_hash = MD5.new(text.encode('utf-8')).hexdigest()

    return jsonify({
        'hash': md5_hash
    })

# MD5 File Hash Generation
@app.route('/hash/md5/file', methods=['POST'])
def md5_hash_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['file']

    # Read file data
    file_data = file.read()

    # Generate MD5 hash
    md5_hash = MD5.new(file_data).hexdigest()

    return jsonify({
        'hash': md5_hash
    })

# SHA Hash Generation
@app.route('/hash/sha/text', methods=['POST'])
def sha_hash_text():
    data = request.json
    text = data.get('text', '')
    algorithm = data.get('algorithm', 'sha256')

    # Generate SHA hash based on selected algorithm
    if algorithm == 'sha1':
        sha_hash = SHA1.new(text.encode('utf-8')).hexdigest()
    elif algorithm == 'sha224':
        sha_hash = SHA224.new(text.encode('utf-8')).hexdigest()
    elif algorithm == 'sha384':
        sha_hash = SHA384.new(text.encode('utf-8')).hexdigest()
    elif algorithm == 'sha512':
        sha_hash = SHA512.new(text.encode('utf-8')).hexdigest()
    else:  # default to sha256
        sha_hash = SHA256.new(text.encode('utf-8')).hexdigest()

    return jsonify({
        'hash': sha_hash
    })

# SHA File Hash Generation
@app.route('/hash/sha/file', methods=['POST'])
def sha_hash_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['file']
    algorithm = request.form.get('algorithm', 'sha256')

    # Read file data
    file_data = file.read()

    # Generate SHA hash based on selected algorithm
    if algorithm == 'sha1':
        sha_hash = SHA1.new(file_data).hexdigest()
    elif algorithm == 'sha224':
        sha_hash = SHA224.new(file_data).hexdigest()
    elif algorithm == 'sha384':
        sha_hash = SHA384.new(file_data).hexdigest()
    elif algorithm == 'sha512':
        sha_hash = SHA512.new(file_data).hexdigest()
    else:  # default to sha256
        sha_hash = SHA256.new(file_data).hexdigest()

    return jsonify({
        'hash': sha_hash
    })
# SHA-3 Hash Generation
@app.route('/hash/sha3/text', methods=['POST'])
def generate_sha3_hash():
    try:
        data = request.json
        print(data)
        input_text = data.get('input', '')
        hash_size = data.get('size', '256')

        # Convert hash_size to int
        hash_size = int(hash_size)

        # Validate hash size
        valid_sizes = [224, 256, 384, 512]
        if hash_size not in valid_sizes:
            hash_size = 256  # Default to SHA3-256 if invalid size

        # Import SHA3 from hashlib
        from hashlib import sha3_224, sha3_256, sha3_384, sha3_512

        # Select the appropriate hash function
        if hash_size == 224:
            hash_func = sha3_224
        elif hash_size == 256:
            hash_func = sha3_256
        elif hash_size == 384:
            hash_func = sha3_384
        else:  # hash_size == 512
            hash_func = sha3_512

        # Generate the hash
        hash_obj = hash_func(input_text.encode('utf-8'))
        hash_hex = hash_obj.hexdigest()

        print(f"SHA-3 hash generation successful: SHA3-{hash_size}")
        return jsonify({
            'hash': hash_hex,
            'algorithm': f'SHA3-{hash_size}'
        })
    except Exception as e:
        print(f"SHA-3 hash generation error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# SHA-3 File Hash Generation
@app.route('/hash/sha3/file', methods=['POST'])
def generate_sha3_file_hash():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400

        file = request.files['file']
        hash_size = request.form.get('size', '256')

        # Convert hash_size to int
        hash_size = int(hash_size)

        # Validate hash size
        valid_sizes = [224, 256, 384, 512]
        if hash_size not in valid_sizes:
            hash_size = 256  # Default to SHA3-256 if invalid size

        # Import SHA3 from hashlib
        from hashlib import sha3_224, sha3_256, sha3_384, sha3_512

        # Select the appropriate hash function
        if hash_size == 224:
            hash_func = sha3_224
        elif hash_size == 256:
            hash_func = sha3_256
        elif hash_size == 384:
            hash_func = sha3_384
        else:  # hash_size == 512
            hash_func = sha3_512

        # Read file data
        file_data = file.read()

        # Generate the hash
        hash_obj = hash_func(file_data)
        hash_hex = hash_obj.hexdigest()

        print(f"SHA-3 file hash generation successful: SHA3-{hash_size}")
        return jsonify({
            'hash': hash_hex,
            'algorithm': f'SHA3-{hash_size}'
        })
    except Exception as e:
        print(f"SHA-3 file hash generation error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Bcrypt Hash Generation and Verification
@app.route('/hash/bcrypt/generate', methods=['POST'])
def bcrypt_generate():
    data = request.json
    password = data.get('password', '')
    cost_factor = int(data.get('cost_factor', 12))

    # Generate salt and hash password
    salt = bcrypt.gensalt(rounds=cost_factor)
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)

    return jsonify({
        'hash': hashed.decode('utf-8')
    })

@app.route('/hash/bcrypt/verify', methods=['POST'])
def bcrypt_verify():
    data = request.json
    password = data.get('password', '')
    hash_value = data.get('hash', '')

    # Verify password against hash
    match = bcrypt.checkpw(password.encode('utf-8'), hash_value.encode('utf-8'))

    return jsonify({
        'match': match
    })

# Poly1305 Key Generation
@app.route('/hash/poly1305/generate-key', methods=['POST'])
def poly1305_generate_key():
    try:
        # Poly1305 uses a 32-byte (256-bit) key
        key = get_random_bytes(32)

        # Return base64 encoded key
        key_b64 = base64.b64encode(key).decode('utf-8')

        print(f"Poly1305 key generation successful: {key_b64[:15]}...")
        return jsonify({
            'key': key_b64
        })
    except Exception as e:
        print(f"Poly1305 key generation error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Poly1305 MAC Generation for Text
@app.route('/hash/poly1305/text', methods=['POST'])
def poly1305_text():
    try:
        data = request.json
        text = data.get('text', '')
        key_b64 = data.get('key', '')

        # Decode key from base64
        key = base64.b64decode(key_b64)

        # Generate MAC
        from Crypto.Hash import Poly1305
        from Crypto.Cipher import AES

        # Poly1305 requires a cipher instance (typically AES)
        cipher = AES.new(key[:16], AES.MODE_ECB)
        mac = Poly1305.new(key=key, cipher=cipher)
        mac.update(text.encode('utf-8'))
        digest = mac.hexdigest()

        return jsonify({
            'mac': digest
        })
    except Exception as e:
        print(f"Poly1305 MAC generation error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Poly1305 MAC Generation for File
@app.route('/hash/poly1305/file', methods=['POST'])
def poly1305_file():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400

        file = request.files['file']
        key_b64 = request.form.get('key', '')

        # Decode key from base64
        key = base64.b64decode(key_b64)

        # Read file data
        file_data = file.read()

        # Generate MAC
        from Crypto.Hash import Poly1305
        from Crypto.Cipher import AES

        # Poly1305 requires a cipher instance (typically AES)
        cipher = AES.new(key[:16], AES.MODE_ECB)
        mac = Poly1305.new(key=key, cipher=cipher)
        mac.update(file_data)
        digest = mac.hexdigest()

        return jsonify({
            'mac': digest
        })
    except Exception as e:
        print(f"Poly1305 file MAC generation error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Poly1305 MAC Verification for Text
@app.route('/hash/poly1305/verify/text', methods=['POST'])
def poly1305_verify_text():
    try:
        data = request.json
        text = data.get('text', '')
        key_b64 = data.get('key', '')
        mac_to_verify = data.get('mac', '')

        # Decode key from base64
        key = base64.b64decode(key_b64)

        # Generate MAC
        from Crypto.Hash import Poly1305
        from Crypto.Cipher import AES

        # Poly1305 requires a cipher instance (typically AES)
        cipher = AES.new(key[:16], AES.MODE_ECB)
        mac = Poly1305.new(key=key, cipher=cipher)
        mac.update(text.encode('utf-8'))

        # Verify MAC
        try:
            mac.hexverify(mac_to_verify)
            valid = True
        except ValueError:
            valid = False

        return jsonify({
            'valid': valid
        })
    except Exception as e:
        print(f"Poly1305 text verification error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Poly1305 MAC Verification for File
@app.route('/hash/poly1305/verify/file', methods=['POST'])
def poly1305_verify_file():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400

        file = request.files['file']
        key_b64 = request.form.get('key', '')
        mac_to_verify = request.form.get('mac', '')

        # Decode key from base64
        key = base64.b64decode(key_b64)

        # Read file data
        file_data = file.read()

        # Generate MAC
        from Crypto.Hash import Poly1305
        from Crypto.Cipher import AES

        # Poly1305 requires a cipher instance (typically AES)
        cipher = AES.new(key[:16], AES.MODE_ECB)
        mac = Poly1305.new(key=key, cipher=cipher)
        mac.update(file_data)

        # Verify MAC
        try:
            mac.hexverify(mac_to_verify)
            valid = True
        except ValueError:
            valid = False

        return jsonify({
            'valid': valid
        })
    except Exception as e:
        print(f"Poly1305 file verification error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Argon2 Hash Generation and Verification
@app.route('/hash/argon2/generate', methods=['POST'])
def argon2_generate():
    try:
        if not ARGON2_AVAILABLE:
            return jsonify({'error': 'Argon2 library not installed. Please install argon2-cffi.'}), 500

        data = request.json
        password = data.get('password', '')
        variant = data.get('variant', 'argon2id')
        memory_cost = int(data.get('memory_cost', 65536))  # 64 MB
        time_cost = int(data.get('time_cost', 3))  # 3 iterations
        parallelism = int(data.get('parallelism', 4))  # 4 parallel threads

        # Map variant string to argon2 type
        variant_map = {
            'argon2i': argon2.Type.I,
            'argon2d': argon2.Type.D,
            'argon2id': argon2.Type.ID
        }
        variant_type = variant_map.get(variant.lower(), argon2.Type.ID)

        # Create hasher with specified parameters
        ph = PasswordHasher(
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=32,
            type=variant_type
        )

        # Hash password
        hash_value = ph.hash(password)

        print(f"Argon2 hash generated successfully")
        return jsonify({
            'hash': hash_value
        })
    except Exception as e:
        print(f"Argon2 hash generation error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/hash/argon2/verify', methods=['POST'])
def argon2_verify():
    try:
        if not ARGON2_AVAILABLE:
            return jsonify({'error': 'Argon2 library not installed. Please install argon2-cffi.'}), 500

        data = request.json
        password = data.get('password', '')
        hash_value = data.get('hash', '')

        # Create hasher
        ph = PasswordHasher()

        # Verify password against hash
        try:
            ph.verify(hash_value, password)
            match = True
        except VerifyMismatchError:
            match = False

        return jsonify({
            'match': match
        })
    except Exception as e:
        print(f"Argon2 verification error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# BLAKE2 Hash Generation
@app.route('/hash/blake2/text', methods=['POST'])
def blake2_hash_text():
    try:
        data = request.json
        text = data.get('text', '')
        variant = data.get('variant', 'blake2b')
        digest_size = int(data.get('digest_size', 32))
        key = data.get('key', '')

        # Import BLAKE2 modules
        from Crypto.Hash import BLAKE2b, BLAKE2s

        # Decode key from base64 if provided
        key_bytes = base64.b64decode(key) if key else None

        # Generate hash based on selected variant
        if variant == 'blake2b':
            # BLAKE2b is optimized for 64-bit platforms
            h = BLAKE2b.new(digest_bytes=digest_size, key=key_bytes)
        else:  # blake2s
            # BLAKE2s is optimized for 32-bit platforms
            h = BLAKE2s.new(digest_bytes=min(digest_size, 32), key=key_bytes)  # BLAKE2s max is 32 bytes

        h.update(text.encode('utf-8'))
        blake2_hash = h.hexdigest()

        print(f"BLAKE2 text hash generated successfully")
        return jsonify({
            'hash': blake2_hash
        })
    except Exception as e:
        print(f"BLAKE2 text hash error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/hash/blake2/file', methods=['POST'])
def blake2_hash_file():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400

        file = request.files['file']
        variant = request.form.get('variant', 'blake2b')
        digest_size = int(request.form.get('digest_size', 32))
        key = request.form.get('key', '')

        # Import BLAKE2 modules
        from Crypto.Hash import BLAKE2b, BLAKE2s

        # Decode key from base64 if provided
        key_bytes = base64.b64decode(key) if key else None

        # Read file data
        file_data = file.read()

        # Generate hash based on selected variant
        if variant == 'blake2b':
            # BLAKE2b is optimized for 64-bit platforms
            h = BLAKE2b.new(digest_bytes=digest_size, key=key_bytes)
        else:  # blake2s
            # BLAKE2s is optimized for 32-bit platforms
            h = BLAKE2s.new(digest_bytes=min(digest_size, 32), key=key_bytes)  # BLAKE2s max is 32 bytes

        h.update(file_data)
        blake2_hash = h.hexdigest()

        print(f"BLAKE2 file hash generated successfully")
        return jsonify({
            'hash': blake2_hash
        })
    except Exception as e:
        print(f"BLAKE2 file hash error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.errorhandler(404)
def page_not_found(_):
    return render_template('404.html'), 404

if __name__ == '__main__':
    app.run(debug=True, port=8000)

