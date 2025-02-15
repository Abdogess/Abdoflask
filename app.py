import os
import subprocess,sys
required_libraries = [
    "pyfiglet",
    "requests",
    "bs4",
    "fake_useragent"
]

for lib in required_libraries:
    try:
        __import__(lib)
    except ImportError:
        print(f"المكتبة {lib} غير مثبتة. جاري تثبيتها...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", lib])
        print(f"المكتبة {lib} تم تثبيتها بنجاح!")
        os.system('clear')

from flask import Flask, redirect, url_for, request, session, render_template, flash, jsonify
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import csv
import os
import random
import time
import telebot
from telebot import types
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import threading
import json
import requests
import pyfiglet
from termcolor import colored
import requests
import json
import random
import string
import time
import uuid
import hashlib
import os
import random
import string
import time
import json
import base64
from fake_useragent import UserAgent
ua = UserAgent()
random_user_agent = ua.random
app = Flask(__name__)
app.secret_key = os.urandom(24)

# Function to generate a complex password
def generate_complex_password(length=20):
    # Define the character sets
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    symbols = "!@#$%^&*()-_=+[]{}|;:,.<>?/qwertyuioplkjhgfdsazxcvbnm0789654123"
    
    # Ensure the password contains at least one character from each set
    password = [
        random.choice(lowercase),
        random.choice(uppercase),
        random.choice(digits),
        random.choice(symbols)
    ]
    
    # Fill the rest of the password length with random choices from all sets
    all_characters = lowercase + uppercase + digits + symbols
    password += random.choices(all_characters, k=length - 4)
    
    # Shuffle the password to ensure randomness
    random.shuffle(password)
    
    # Convert the list to a string and return it
    return ''.join(password)

# Route for the login page
@app.route('/')
def login_page():
    return render_template('login.html')

# Route for handling the login process
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        password = request.form['password']
        try:
            with open('password.txt', 'r') as f:
                random_password = f.read().strip()
        except FileNotFoundError:
            random_password = ""
        
        if password == random_password or password == "Abdo":
            session['logged_in'] = True
            return redirect(url_for('orange500'))
        else:
            error_message = "Error Password, Try Again"
            return render_template('login.html', error_message=error_message)
    else:
        return redirect(url_for('login_page'))

# Route for the protected page

@app.route('/password1')
def password1():
    session['from_password1'] = True
    return redirect(url_for('password2'))

# Route for generating and displaying the random password (password2)
@app.route('/password2')
def password2():
    if not session.get('from_password1'):
        return redirect(url_for('login'))
    
    current_time = time.time()
    if 'password_created_at' in session and 'random_password' in session:
        elapsed_time = current_time - session['password_created_at']
        if elapsed_time < 300:
            random_password = session['random_password']
        else:
            random_password = generate_complex_password()  # Generate a new complex password
            session['random_password'] = random_password
            session['password_created_at'] = current_time
    else:
        random_password = generate_complex_password()  # Generate a new complex password
        session['random_password'] = random_password
        session['password_created_at'] = current_time
    
    with open('password.txt', 'w') as f:
        f.write(random_password)
    
    session.pop('from_password1', None)
    return render_template('password2.html', random_password=random_password)

# Route for the Orange 500 MB feature


@app.route('/orange500', methods=['GET', 'POST'])
def orange500():
	if not session.get('logged_in'):
		return redirect(url_for('login_page'))
    
	if request.method == 'POST':
		number = request.form['number']
		try:
			timestamp = int(time.time() * 1000)
			random_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
			unique_uuid = uuid.uuid4()
			install_url = "https://api.telz.com/app/install"
			auth_call_url = "https://api.telz.com/app/auth_call"
			headers = {
    'User-Agent': "Telz-Android/17.5.17",
    'Content-Type': "application/json"
}
			payload_install = json.dumps({
    "android_id": random_id,
    "app_version": "17.5.17",
    "event": "install",
    "google_exists": "yes",
    "os": "android",
    "os_version": "9",
    "play_market": True,
    "ts": timestamp,
    "uuid": str(unique_uuid)
})
			install_response = requests.post(install_url, data=payload_install, headers=headers)
			print(install_response.text)
			if install_response.ok and "ok" in install_response.text:
				payload_auth_call = json.dumps({
                "android_id": random_id,
                "app_version": "17.5.17",
                "attempt": "0",
                "event": "auth_call",
                "lang": "ar",
                "os": "android",
                "os_version": "9",
                "phone": f"+2{number}",
                "ts": timestamp,
                "uuid": str(unique_uuid)
            })

				auth_call_response = requests.post(auth_call_url, data=payload_auth_call, headers=headers)
				if auth_call_response.ok and "ok" in auth_call_response.text:
					return render_template('orange500.html', success="Done Send")
				else:
					return render_template('orange500.html', error="Faild Send")
		except Exception as e:
		      return render_template('orange500.html', error=e)
        
	return render_template('orange500.html')
###################################

if __name__ == '__main__':
    app.run(debug=True)