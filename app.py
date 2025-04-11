from flask import Flask, request, jsonify, send_file
from io import BytesIO
from PIL import Image
import numpy as np
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import random
import zipfile
import json
import os

app = Flask(__name__)

# Configuration
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
ZIP_EXTENSIONS = {'zip'}
DEFAULT_BLOCK_SIZE = (100, 100)  # width, height in pixels

def allowed_file(filename, valid_exts):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in valid_exts

def derive_aes_key(key: str):
    if not key:
        raise ValueError("Please Input the key")
    if len(key) > 32:
        raise ValueError("The limit of key has been exceeded")
    return hashlib.sha256(key.encode()).digest()

def encrypt_data(key, data: bytes) -> bytes:
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    padded_data = pad(data, AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    return iv + ciphertext

def decrypt_data(key, data: bytes) -> bytes:
    iv = data[:16]
    ciphertext = data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted

def split_image_randomized_overlapping(image, block_size=DEFAULT_BLOCK_SIZE,
                                       overlap_ratio=0.2, random_offset_ratio=0.1):
    width, height = image.size
    block_width, block_height = block_size
    stride_x = int(block_width * (1 - overlap_ratio))
    stride_y = int(block_height * (1 - overlap_ratio))
    if stride_x <= 0 or stride_y <= 0:
        stride_x, stride_y = 1, 1

    blocks = []
    coords = []
    for x in range(0, width - block_width + 1, stride_x):
        for y in range(0, height - block_height + 1, stride_y):
            max_offset_x = int(block_width * random_offset_ratio)
            max_offset_y = int(block_height * random_offset_ratio)
            offset_x = random.randint(-max_offset_x, max_offset_x)
            offset_y = random.randint(-max_offset_y, max_offset_y)
            new_x = min(max(x + offset_x, 0), width - block_width)
            new_y = min(max(y + offset_y, 0), height - block_height)
            block = image.crop((new_x, new_y, new_x + block_width, new_y + block_height))
            blocks.append(block)
            coords.append((new_x, new_y))
    return blocks, coords, (width, height)

@app.route('/')
def index():
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <script src="https://cdn.tailwindcss.com"></script>
    <title>SecureSnap</title>
    <style>
        html {
            scroll-behavior: smooth;
        }
        body {
            scroll-behavior: smooth;
        }
        .hover-effect:hover {
            transform: scale(1.05);
            transition: transform 0.3s ease-in-out;
        }
      .typed-out {
    overflow: hidden;
    border-right: 0.15em solid blue;
    white-space: nowrap;
    animation: typing 1s steps(10, end) forwards, blinking 0.8s infinite;
    font-size: 1.8rem;
    width: 0;
    display: inline-block;
    position: relative;
    z-index: 10; /* Ensure it's above other elements */
}


        @keyframes typing {
            from { width: 0 }
            to { width: 22% }
        }

        @keyframes blinking {
            from { border-color: transparent }
            to { border-color: blue; }
        }
    </style>
    
</head>
<body class="bg-[#1E1B42] text-[#00FFAA] font-sans">
    <nav class="flex justify-between items-center p-5 bg-[#2C2A4A] shadow-md fixed w-full top-0">
        <h1 class="text-xl font-bold text-white">Secure<span class="text-xl font-bold text-[#00FFAA]">Snap</span></h1>
        <ul class="flex space-x-5 text-white">
            <li><a href="#home" class="hover:text-[#00FFAA]">Home</a></li>
            <li><a href="#about" class="hover:text-[#00FFAA]">About</a></li>
            <li><a href="#demo" class="hover:text-[#00FFAA]">Demo</a></li>
            <li><a href="#sender" class="hover:text-[#00FFAA]">Sender</a></li>
            <li><a href="#receiver" class="hover:text-[#00FFAA]">Receiver</a></li>
        </ul>
   </nav>
<header id="home" class="text-center h-screen flex flex-col justify-center items-center">
    <h2 class="text-7xl font-bold bg-gradient-to-r from-[#00FFAA] via-gray-400 to-blue-600 bg-clip-text text-transparent glow-text">
        SecureSnap
    </h2>
    <p class="text-lg mt-2 text-gray-300">Protect your images with military-grade encryption</p>

    <!-- Typing Animation Container -->
    <div class="typed-container w-[920px] h-[50px] flex justify-center items-center overflow-hidden">
        <div class="typed-out text-2xl font-semibold text-[#00FFAA]">
            Pixel Slice Stitch
        </div>
    </div>

    <!-- Centering the button -->
    <div class="flex justify-center mt-4">
        <button onclick="window.location.href='mailto:projectmajor337@gmail.com'" 
                class="w-40 px-6 py-3 text-white bg-gradient-to-r from-[#00FFAA] to-blue-600 rounded-lg shadow-md hover:from-[#00DD99] hover:to-blue-500 transition-all duration-300">
            Let's Talk
        </button>
    </div>
</header>



    <section id="about" class="min-h-screen flex flex-col justify-center items-center p-10">
        <h3 class="text-3xl font-semibold text-center mb-5">About Us</h3>
        <p class="mt-4 mb-4 text-center text-gray-300 w-full max-w-3xl">
            In a world where digital security is more important than ever, we set out to tackle one of its biggest challenges: protecting images from prying eyes. Traditional encryption methods often struggle with complex multimedia data, leading to vulnerabilities and inefficiencies. That’s where our innovation comes in.  
            At SecureSnap, we’ve developed a cutting-edge dual-layered security approach that splits images into encrypted segments, making unauthorized reconstruction nearly impossible. With advanced stitching algorithms, we ensure seamless reassembly while maintaining both security and efficiency.  
            What drives us? A passion for cybersecurity, a love for problem-solving, and the belief that digital privacy should never be compromised. Join us as we revolutionize secure multimedia communication—one encrypted pixel at a time!
        </p>
    <!--
     <div class="flex justify-center items-center gap-10 p-10">
    <img src="/static/split.png" alt="Image 1" class="w-1/4 rounded-lg shadow-md object-cover">
    <img src="/static/encrypt.png" alt="Image 2" class="w-1/4 rounded-lg shadow-md">
    <img src="/static/creditCard.png" alt="Image 3" class="w-1/4 rounded-lg shadow-md">
        </div>  
    -->
        <div>
        <h4 class="text-xl font-semibold text-center mb-5 mt-5">Our Mission<h4>
        <div class="grid lg:grid-cols-2 gap-10 mt-10 w-4.5/6">
            <div class="p-6 bg-[#2C2A4A] shadow-md rounded-lg hover-effect w-full">
                <h4 class="text-xl font-bold text-center mb-2">Sender</h4>
                <p class="text-center text-gray-300 text-justify">
                    Encrypting images isn’t just about security—it’s about staying ahead of threats. Our system empowers you to protect your images using cutting-edge encryption techniques. By splitting the image into segments and encrypting each part individually, we ensure that even if an attacker gains access to a fragment, it remains unreadable.
                </p>
                <h4 class="mt-3 font-semibold">✔ How it works:</h4>
                <ul class="list-disc list-inside text-gray-300 space-y-1 mt-1">
                    <li>Upload your image to our system.</li>
                    <li>It gets divided into real-time randomized segments based on different input image sizes.</li>
                    <li>Each segment is encrypted using advanced algorithms.</li>
                    <li>The encrypted segments are stored locally, ready for controlled access.</li>
                </ul>
            </div>
            <div class="p-6 bg-[#2C2A4A] shadow-md rounded-lg hover-effect w-full">
                <h4 class="text-xl font-bold text-center mb-2">Receiver</h4>
                <p class="text-center text-gray-300 text-justify">
                    Decryption is just as crucial as encryption—what’s the point of security if the right person can’t access the data? Our system seamlessly reconstructs encrypted images, ensuring that only those with the correct decryption key can restore the original content.
                </p>
                <h4 class="mt-3 font-semibold">✔ How it works:</h4>
                <ul class="list-disc list-inside text-gray-300 space-y-1 mt-1">
                    <li>Provide the encrypted segments to the system.</li>
                    <li>The system decrypts each part securely.</li>
                    <li>The segments are stitched back together.</li>
                    <li>You retrieve your fully restored, protected image.</li>
                </ul>
            </div>
        </div>
        </div>
    </section>
    <section id="demo" class="h-screen flex flex-col justify-center items-center p-10">
        <h3 class="text-3xl font-semibold text-center mb-3">Demo</h3>
        <video controls class="w-3/4 mt-5 rounded-lg shadow-lg">
            <source src="/static/demo2.mp4" type="video/mp4" />
            Your browser does not support the video tag.
        </video> 
       <!-- <iframe width="859" height="600" src="https://www.loom.com/embed/eb2d1a7f1b7641e9ae4bce5c44768660?sid=c8becfa5-7135-4b02-ac28-7ace51cfb948" frameborder="0" webkitallowfullscreen mozallowfullscreen allowfullscreen></iframe> -->
    </section>
<section id="sender" class="h-screen flex flex-col justify-center items-center p-10">
    <h3 class="text-3xl font-semibold text-center mb-4">Sender</h3>
    <div class="grid grid-cols-2 gap-10 mt-5 w-3/4">
        <div class="p-5 bg-[#2C2A4A] shadow-md rounded-lg hover-effect">
            <h2 class="text-xl font-bold text-center text-white">Split an Image</h2>
            <form method="POST" action="/split" enctype="multipart/form-data">
                <label class="text-white">Upload Image:</label>
                <input type="file" name="split-file" accept="image/*" required class="block w-full p-2 border rounded-md bg-[#1E1B42] text-[#00FFAA]">
                <button type="submit" class="mt-3 bg-[#00FFAA] text-[#1E1B42] p-2 rounded-lg w-full hover:bg-[#00DD99]">Split & Zip</button>
            </form>
        </div>
        <div class="p-5 bg-[#2C2A4A] shadow-md rounded-lg hover-effect">
            <h2 class="text-xl font-bold text-center text-white">Encrypt🔐</h2>
            <form method="POST" action="/encrypt_zip" enctype="multipart/form-data">
                <label class="text-white mt-4 mb-4">Upload .zip (from split):</label>
                <input type="file" name="encrypt-zip-file" accept=".zip" required class="block w-full p-2 border rounded-md bg-[#1E1B42] text-[#00FFAA]">
                <label class="mt-4 mb-4 text-white">Security Key:</label>
                <input type="password" name="key" placeholder="Enter your security key" required class="block w-full p-2 border rounded-md bg-[#1E1B42] text-[#00FFAA]">
                <button type="submit" class="mt-4 bg-[#00FFAA] text-[#1E1B42] p-2 rounded-lg w-full hover:bg-[#00DD99]">Encrypt ZIP 🔐</button>
            </form>
        </div>
    </div>
</section>

<section id="receiver" class="h-screen flex flex-col justify-center items-center p-10">
    <h3 class="text-3xl font-semibold text-center mb-4">Receiver</h3>
    <div class="p-5 bg-[#2C2A4A] shadow-md rounded-lg hover-effect w-3/4">
        <h2 class="text-xl font-bold text-center text-white">Decrypt & Stitch 🔓</h2>
        <form method="POST" action="/stitch_decrypt" enctype="multipart/form-data">
            <label class="text-white">Upload Encrypted ZIP:</label>
            <input type="file" name="stitch-zip-file" accept=".zip" required class="block w-full p-2 border rounded-md bg-[#1E1B42] text-[#00FFAA]">
            <label class="mt-3 text-white">Security Key:</label>
            <input type="password" name="key" placeholder="Enter your security key" required class="block w-full p-2 border rounded-md bg-[#1E1B42] text-[#00FFAA]">
            <button type="submit" class="mt-3 bg-[#00FFAA] text-[#1E1B42] p-2 rounded-lg w-full hover:bg-[#00DD99]">Stitch & Decrypt 🔓</button>
        </form>
    </div>
</section>

    <footer class="text-center p-5 bg-[#2C2A4A] shadow-md mt-10">
        <p class="text-[#00FFAA]">All rights reserved © SecureSnap</p>
    </footer>  
</body>
</html>"""

# ---------------------------
# 1. Split Endpoint
# ---------------------------
@app.route('/split', methods=['POST'])
def split_image():
    if 'split-file' not in request.files:
        return jsonify({'message': 'No file provided'}), 400
    file = request.files['split-file']
    if file.filename == '' or not allowed_file(file.filename, ALLOWED_EXTENSIONS):
        return jsonify({'message': 'Invalid file format or no file selected'}), 400

    try:
        image = Image.open(file)
    except Exception:
        return jsonify({'message': 'Unable to open image'}), 400

    blocks, coords, original_size = split_image_randomized_overlapping(
        image, block_size=DEFAULT_BLOCK_SIZE, overlap_ratio=0.2, random_offset_ratio=0.1
    )
    if not blocks:
        return jsonify({'message': 'Image too small to split'}), 400

    metadata = {
        "original_size": original_size,
        "block_size": list(DEFAULT_BLOCK_SIZE),
        "blocks": [{"block_index": i, "x": x, "y": y} for i, (x, y) in enumerate(coords)]
    }

    zip_buffer = BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        for i, block in enumerate(blocks):
            block_buffer = BytesIO()
            block.save(block_buffer, format="PNG")
            block_buffer.seek(0)
            zf.writestr(f"block_{i}.png", block_buffer.getvalue())
        zf.writestr("metadata.json", json.dumps(metadata))
    zip_buffer.seek(0)
    return send_file(zip_buffer, mimetype='application/zip', as_attachment=True, download_name="split_blocks.zip")

# ---------------------------
# 2. Encrypt ZIP Endpoint
# ---------------------------
@app.route('/encrypt_zip', methods=['POST'])
def encrypt_zip():
    if 'encrypt-zip-file' not in request.files or 'key' not in request.form:
        return jsonify({'message': 'ZIP file and key are required'}), 400

    file = request.files['encrypt-zip-file']
    raw_key = request.form['key']
    try:
        key = derive_aes_key(raw_key)
    except ValueError as e:
        return jsonify({'message': str(e)}), 400

    if file.filename == '' or not allowed_file(file.filename, ZIP_EXTENSIONS):
        return jsonify({'message': 'Invalid file format or no file selected'}), 400

    try:
        input_zip = zipfile.ZipFile(BytesIO(file.read()))
    except Exception:
        return jsonify({'message': 'Unable to open ZIP file'}), 400

    encrypted_zip_buffer = BytesIO()
    with zipfile.ZipFile(encrypted_zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zout:
        for info in input_zip.infolist():
            file_data = input_zip.read(info.filename)
            encrypted_file = encrypt_data(key, file_data)
            new_filename = info.filename.rsplit('.', 1)[0] + ".bin"
            zout.writestr(new_filename, encrypted_file)
    encrypted_zip_buffer.seek(0)
    return send_file(encrypted_zip_buffer, mimetype='application/zip', as_attachment=True, download_name="encrypted_blocks.zip")

# ---------------------------
# 3. Stitch & Decrypt Endpoint
# ---------------------------
@app.route('/stitch_decrypt', methods=['POST'])
def stitch_decrypt():
    if 'stitch-zip-file' not in request.files or 'key' not in request.form:
        return jsonify({'message': 'Encrypted ZIP and key are required'}), 400

    file = request.files['stitch-zip-file']
    raw_key = request.form['key']
    try:
        key = derive_aes_key(raw_key)
    except ValueError as e:
        return jsonify({'message': str(e)}), 400

    if file.filename == '' or not allowed_file(file.filename, ZIP_EXTENSIONS):
        return jsonify({'message': 'Invalid file format or no file selected'}), 400

    try:
        encrypted_zip = zipfile.ZipFile(BytesIO(file.read()))
    except Exception:
        return jsonify({'message': 'Unable to open encrypted ZIP file'}), 400

    metadata = None
    blocks_dict = {}
    for info in encrypted_zip.infolist():
        fname = info.filename
        encrypted_data = encrypted_zip.read(fname)
        try:
            decrypted_data = decrypt_data(key, encrypted_data)
        except Exception:
            return jsonify({'message': f'Error decrypting {fname}'}), 400

        if "metadata" in fname.lower():
            try:
                metadata = json.loads(decrypted_data.decode())
            except Exception:
                return jsonify({'message': 'Error reading metadata'}), 400
        else:
            try:
                block_img = Image.open(BytesIO(decrypted_data))
                idx = int(fname.split('_')[-1].split('.')[0])
                blocks_dict[idx] = block_img
            except Exception:
                continue

    if metadata is None:
        return jsonify({'message': 'Missing metadata for stitching'}), 400

    orig_width, orig_height = metadata.get("original_size", (0, 0))
    if orig_width == 0 or orig_height == 0:
        return jsonify({'message': 'Invalid original image size in metadata'}), 400

    stitched_image = Image.new("RGB", (orig_width, orig_height))
    for block_info in metadata["blocks"]:
        idx = block_info["block_index"]
        x = block_info["x"]
        y = block_info["y"]
        block_img = blocks_dict.get(idx)
        if block_img:
            stitched_image.paste(block_img, (x, y))
    out_buffer = BytesIO()
    stitched_image.save(out_buffer, format="PNG")
    out_buffer.seek(0)
    return send_file(out_buffer, mimetype='image/png', as_attachment=True, download_name="stitched_image.png")

# ---------------------------
# 4. Forgot Key Endpoint (Simulated)
# ---------------------------
@app.route('/forgot_key', methods=['POST'])
def forgot_key():
    email = request.form.get("email")
    if not email:
        return jsonify({'message': 'Please provide your email address'}), 400
    return jsonify({'message': f'An authentication email has been sent to {email}.'}), 200

if __name__ == '__main__':
    app.run(debug=True)
