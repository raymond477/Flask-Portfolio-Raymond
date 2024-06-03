# Full Stack Web Internship Program: Next Steps
# Created by Peter Raymond Hon
# Flask python development program register and login with working OTP

from flask import Flask, render_template, redirect, request, url_for, flash, session, make_response # disini saya akan import hal-hal yang akan digunakan dalam flask ini
import pymysql.cursors                                                                              # ini berguna untuk membuat kursor penghubung ke mysql
from flask_mail import Mail, Message                                                                # ini berguna untuk autentikasi menggunakan email karena untuk OTP
import random                                                                                       # ini untuk melakukan randomisasi dalam OTP jadi tidak mudah ditebak
import string        
from flask_bcrypt import Bcrypt, check_password_hash
from datetime import datetime , timedelta
 
app = Flask(__name__) # Deklarasi program awal flask (wajib ada)
bcrypt = Bcrypt(app)

app.secret_key = "SECRET12346789"

# Konfigurasi untuk pengiriman email OTP
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = ''   
app.config['MAIL_PASSWORD'] = '' 
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

mail = Mail (app)

# Fungsi untuk koneksi ke database SQL menggunakan (phpmyadmin)
db_config = {

    'host': 'localhost', #menggunakan localhost phpmyadmin karena masih lokal
    'user': 'root',
    'password': '',
    'db': 'internship',
    'cursorclass': pymysql.cursors.DictCursor #menggunakan kursor pymysql diatas

}

# Fungsinya untuk membuat koneksi ke mysql dari database diatas
def create_connection():
    return pymysql.connect(**db_config)

# Generate OTP menggunakan random jadi tidak bisa diketaui siapapun termasuk admin website
def generate_otp():
    otp = ''.join(random.choices(string.ascii_letters + string.digits, k=6))
    return otp

# Kirim email dengan OTP (email harus sesuai)
def send_otp_email(email, otp):
    msg = Message('Kode OTP untuk Registrasi', sender='', recipients=[email])
    msg.body = f'Kode OTP Anda untuk registrasi di MaiaDigital.com adalah: {otp}'
    mail.send(msg)

# Routing untuk halaman pertama website dijalanka pada port http://127.0.0.1:5000/
@app.route('/')
def index():
    return render_template ('index.html')


@app.route('/register', methods = ['GET','POST'])
def register():
    if request.method == 'POST':                # Harus menggunakan method post dikarenakan jika menggunakan GET maka data user yang diinput rahasia akan terlihat di URL
        username = request.form['username']
        password = request.form['password']
        email    = request.form['email']

        connection = create_connection()        # memanggil koneksi database
        cursor = connection.cursor()

        otp = generate_otp()                    # untuk generate OTP register user
        send_otp_email(email,otp)

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')  # Enkripsi password

        session['otp'] = otp
        session['username'] = username
        session['password'] = hashed_password
        session['email'] = email

        flash ("Kode OTP telah dikirim kedalam email tertuju")

        return redirect (url_for('verify'))
    
    return render_template ('register.html')

@app.route('/verify', methods = ['GET','POST'])
def verify():
    if request.method == 'POST':
        user_otp = request.form['otp']
        if 'otp' in session and user_otp == session['otp']:
            connection = create_connection()
            cursor = connection.cursor()

            cursor.execute ("INSERT INTO users (username,password,email) VALUES (%s,%s,%s)", 
                            (session['username'], session['password'], session['email']))
            connection.commit() # Untuk mengeksekusi query diatas

            cursor.close()
            connection.close() # Menutup koneksi database karena sudah di insert diatas dan perlu penutupan dari create_connection()

            flash('Registrasi berhasil', 'success')
            session.pop('otp', None)
            session.pop('username', None)
            session.pop('password', None)
            session.pop('email', None)

            return redirect(url_for('login'))
        else:
            flash('Kode OTP salah, silakan coba lagi', 'error')

    return render_template('verify.html')


@app.route('/login', methods = ['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form ['username']
        password = request.form ['password']

        connection = create_connection()
        cursor = connection.cursor()

        cursor.execute ("SELECT * FROM users WHERE username = %s ", (username,)) # Mencari semua user yang telah terdaftar didalam database
        
        user = cursor.fetchone()

        cursor.close()
        connection.close()

        if user and check_password_hash(user['password'], password):
            session['id'] = user['id']
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            flash('Username atau password salah', 'danger')


    return render_template ('login.html')

@app.route('/setcookie_dashboard', methods = ['POST'])
def setcookie_dashboard():
    if request.method == 'POST':
        username = request.form ['username']
        password = request.form ['password']

        resp = make_response(render_template('dashboard.html'))

        resp.set_cookie('username',username)
        resp.set_cookie('password',password)

        return resp


@app.route('/dashboard', methods = ['GET','POST'])
def dashboard():
    if request.method == "POST":
        username = request.cookies.get ('username')
        password = request.cookies.get ('password')
    
        return render_template ('dashboard.html' , username=username , password=password)


# Untuk route logout user yang telah login
@app.route('/logout')
def logout():
    id       = session.get ('id')
    username = session.get ('username')

    if id is not None :
        session.pop('id', None)
    
    if username is not None:
        session.pop('username', None)

    return redirect (url_for('index'))



# Penutup dari kode flask
if __name__ == '__main__':
    app.run(debug=True)


