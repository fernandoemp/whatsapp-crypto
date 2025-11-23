from flask import Flask, request, jsonify
from flask_cors import CORS
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import base64
import json
import os

app = Flask(__name__)
CORS(app)

# Cargar desde variables de entorno
PRIVATE_KEY_PEM = os.environ.get('WHATSAPP_PRIVATE_KEY', '').replace('\\n', '\n')
PASSPHRASE = os.environ.get('WHATSAPP_PASSPHRASE', '').encode()

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'service': 'whatsapp-crypto'})

@app.route('/decrypt', methods=['POST'])
def decrypt_whatsapp():
    """
    Desencripta payload de WhatsApp Flows
    Body:
    {
        "encrypted_aes_key": "base64...",
        "encrypted_flow_data": "base64...",
        "initial_vector": "base64..."
    }
    """
    try:
        data = request.json

        # Validar datos
        if not all(k in data for k in ['encrypted_aes_key', 'encrypted_flow_data', 'initial_vector']):
            return jsonify({'error': 'Missing required fields'}), 400

        # Decodificar Base64
        encrypted_aes_key = base64.b64decode(data['encrypted_aes_key'])
        encrypted_flow_data = base64.b64decode(data['encrypted_flow_data'])
        iv = base64.b64decode(data['initial_vector'])
        print(f"📥 Decrypting - AES Key: {len(encrypted_aes_key)} bytes, Data: {len(encrypted_flow_data)} bytes")

        # Cargar llave privada
        private_key = serialization.load_pem_private_key(
            PRIVATE_KEY_PEM.encode() if isinstance(PRIVATE_KEY_PEM, str) else PRIVATE_KEY_PEM,
            password=PASSPHRASE,
            backend=default_backend()
        )

        # Desencriptar AES key con RSA
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(f"✅ AES Key decrypted: {len(aes_key)} bytes")

        # Separar ciphertext y auth tag
        auth_tag = encrypted_flow_data[-16:]
        ciphertext = encrypted_flow_data[:-16]

        # Desencriptar con AES-GCM
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.GCM(iv, auth_tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()

        # Parse JSON
        decrypted_data = json.loads(decrypted.decode('utf-8'))
        print(f"✅ Decrypted successfully. Action: {decrypted_data.get('action')}")

        return jsonify({
            'success': True,
            'decrypted_data': decrypted_data,
            'aes_key': base64.b64encode(aes_key).decode(),
            'iv': base64.b64encode(iv).decode()
        })
    except Exception as e:
        print(f"❌ Decryption error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/encrypt', methods=['POST'])
def encrypt_whatsapp():
    """
    Encripta respuesta para WhatsApp Flows
    Body:
    {
        "response_data": {...},
        "aes_key": "base64...",
        "iv": "base64..."
    }
    """
    try:
        data = request.json
        if not all(k in data for k in ['response_data', 'aes_key', 'iv']):
            return jsonify({'error': 'Missing required fields'}), 400

        response_data = data['response_data']
        aes_key = base64.b64decode(data['aes_key'])
        iv = base64.b64decode(data['iv'])

        # Invertir IV para respuesta
        flipped_iv = bytes(reversed(iv))
        print(f"🔐 Encrypting response. IV flipped: {flipped_iv.hex()[:16]}")

        # Encriptar con AES-GCM
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.GCM(flipped_iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        json_str = json.dumps(response_data)
        ciphertext = encryptor.update(json_str.encode()) + encryptor.finalize()

        # Concatenar ciphertext + auth_tag
        encrypted = ciphertext + encryptor.tag
        encrypted_b64 = base64.b64encode(encrypted).decode()
        print(f"✅ Encrypted successfully. Length: {len(encrypted_b64)}")

        return jsonify({
            'success': True,
            'encrypted_response': encrypted_b64
        })
    except Exception as e:
        print(f"❌ Encryption error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)