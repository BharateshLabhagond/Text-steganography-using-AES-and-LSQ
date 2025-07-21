# app.py
from flask import Flask, render_template, request
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import base64

app = Flask(__name__)

LSQ_1 = '\u200d'  # Zero-width joiner = 1
LSQ_0 = '\u200c'  # Zero-width non-joiner = 0

def encrypt(password, plain_text):
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plain_text.encode('utf-8'))
    return base64.b64encode(salt + cipher.nonce + tag + ciphertext).decode('utf-8')

def decrypt(password, cipher_text):
    try:
        decoded = base64.b64decode(cipher_text)
        salt = decoded[:16]
        nonce = decoded[16:32]
        tag = decoded[32:48]
        ciphertext = decoded[48:]
        key = PBKDF2(password, salt, dkLen=32)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted = cipher.decrypt_and_verify(ciphertext, tag)
        return decrypted.decode('utf-8')
    except (ValueError, KeyError):
        return "Decryption failed. Incorrect password or corrupted data."

def embed_lsq_text(cover_text, encrypted_message):
    binary_data = ''.join(format(ord(char), '08b') for char in encrypted_message)
    stego_text = ""
    index = 0
    for bit in binary_data:
        if index < len(cover_text):
            stego_text += cover_text[index]
            index += 1
        stego_text += LSQ_1 if bit == '1' else LSQ_0
    stego_text += cover_text[index:]
    return stego_text

def extract_lsq_text(stego_text):
    binary_data = ""
    for char in stego_text:
        if char == LSQ_1:
            binary_data += '1'
        elif char == LSQ_0:
            binary_data += '0'
    if len(binary_data) % 8 != 0:
        binary_data = binary_data[:-(len(binary_data) % 8)]
    try:
        return ''.join(chr(int(binary_data[i:i+8], 2)) for i in range(0, len(binary_data), 8))
    except ValueError:
        return ""

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/embed', methods=['POST'])
def embed():
    cover_text = request.form['cover_text']
    secret_message = request.form['secret_message']
    password_embed = request.form['password_embed']

    encrypted_message = encrypt(password_embed, secret_message)
    stego_text = embed_lsq_text(cover_text, encrypted_message)

    return render_template('index.html',
                           success_message="Message successfully embedded using LSQ encoding!",
                           stego_text_result=stego_text,
                           scroll_to='stego_result',
                           extracted_message=None,
                           request_form={
                               'secret_message': secret_message,
                               'cover_text': cover_text,
                               'password_embed': password_embed
                           })

@app.route('/extract', methods=['POST'])
def extract():
    stego_text = request.form['stego_text']
    password_extract = request.form['password_extract']
    extracted_encrypted = extract_lsq_text(stego_text)

    if not extracted_encrypted:
        return render_template('index.html',
                               extracted_message="No LSQ-encoded message found.",
                               stego_text_result=None,
                               scroll_to='extract_result',
                               request_form={
                                   'stego_text': stego_text,
                                   'password_extract': password_extract
                               })

    decrypted_message = decrypt(password_extract, extracted_encrypted)
    return render_template('index.html',
                           extracted_message=decrypted_message,
                           stego_text_result=None,
                           success_message=None,
                           scroll_to='extract_result',
                           request_form={
                               'stego_text': stego_text,
                               'password_extract': password_extract
                           })

if __name__ == '__main__':
    app.run(debug=True)