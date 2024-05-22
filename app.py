from flask import Flask, request, render_template, flash, redirect, url_for,session, logging, send_file, jsonify, Response, render_template_string
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators, DateTimeField, BooleanField, IntegerField, DecimalField, HiddenField, SelectField, RadioField
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from flask_mail import Mail, Message
from functools import wraps
from sqlalchemy import and_
from werkzeug.utils import secure_filename
from coolname import generate_slug
from datetime import timedelta, datetime
from objective import ObjectiveTest
from subjective import SubjectiveTest
from sqlalchemy import func
from flask import request, jsonify
from deepface import DeepFace
from datetime import datetime
import pandas as pd
import stripe
import operator
import functools
import math, random 
import csv
import cv2
import numpy as np
import json
import base64
from wtforms_components import TimeField
from flask import request
from flask_sqlalchemy import SQLAlchemy
from wtforms_components import DateField
from wtforms.validators import DataRequired
from wtforms.validators import ValidationError, NumberRange
from flask_session import Session
from flask_cors import CORS, cross_origin
import camera
import os

app = Flask(__name__)


DATABASE_DIRECTORY = os.path.join(
    os.getcwd(),
    'DB'
)

os.makedirs(DATABASE_DIRECTORY, exist_ok=True)

DATABASE_FILE = os.path.join(
    DATABASE_DIRECTORY,
    'data.db'
)

# Configure the Flask application
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///'+DATABASE_FILE
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465 

app.config['MAIL_USERNAME'] = 'hafizhashimkardar@gmail.com'
app.config['MAIL_PASSWORD'] = 'imbr yhko jjei aapp'
app.config['MAIL_USE_TLS'] = False  
app.config['MAIL_USE_SSL'] = True  

app.config['SESSION_TYPE'] = 'filesystem'

app.config["TEMPLATES_AUTO_RELOAD"] = True

stripe_keys = {
    "secret_key": "dummy",
    "publishable_key": "dummy",
}

stripe.api_key = stripe_keys["secret_key"]

mail = Mail(app)

sess = Session()
sess.init_app(app)

cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'

app.secret_key= '123456'
db = SQLAlchemy(app)

        
with app.app_context():
    db.create_all()

sender = 'hafizhashimkardar@gmail.com'

YOUR_DOMAIN = 'http://localhost:5000'


class WindowEstimationLog(db.Model):
    wid = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=False)
    test_id = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    window_event = db.Column(db.Integer, nullable=False)
    uid = db.Column(db.Integer, nullable=False)

class LongQA(db.Model):
    longqa_qid = db.Column(db.Integer, primary_key=True, autoincrement=True)
    test_id = db.Column(db.Text, nullable=False)
    qid = db.Column(db.Text, nullable=False)
    q = db.Column(db.Text, nullable=False)
    marks = db.Column(db.Integer)
    uid = db.Column(db.Integer)

class LongTest(db.Model):
    longtest_qid = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.Text, nullable=False)
    test_id = db.Column(db.Text, nullable=False)
    qid = db.Column(db.Integer, nullable=False)
    ans = db.Column(db.Text, nullable=False)
    marks = db.Column(db.Integer, nullable=False)
    uid = db.Column(db.Integer, nullable=False)


# Define the PracticalQA model
class PracticalQA(db.Model):
    pracqa_qid = db.Column(db.Integer, primary_key=True, autoincrement=True)
    test_id = db.Column(db.Text, nullable=False)
    qid = db.Column(db.Text, nullable=False)
    q = db.Column(db.Text, nullable=False)
    compiler = db.Column(db.Integer, nullable=False)
    marks = db.Column(db.Integer, nullable=False)
    uid = db.Column(db.Integer, nullable=False)

# Define the PracticalTest model
class PracticalTest(db.Model):
    pid = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.Text, nullable=False)
    test_id = db.Column(db.Text, nullable=False)
    qid = db.Column(db.Text, nullable=False)
    code = db.Column(db.Text)
    input = db.Column(db.Text)
    executed = db.Column(db.Text, default=None)
    marks = db.Column(db.Integer, nullable=False)
    uid = db.Column(db.Integer, nullable=False)


# Define the ProctoringLog model
class ProctoringLog(db.Model):
    pid = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.Text, nullable=False)
    name = db.Column(db.Text, nullable=False)
    test_id = db.Column(db.Text, nullable=False)
    voice_db = db.Column(db.Integer, default=0)
    img_log = db.Column(db.Text, nullable=False)
    user_movements_updown = db.Column(db.Integer, nullable=False)
    user_movements_lr = db.Column(db.Integer, nullable=False)
    user_movements_eyes = db.Column(db.Integer, nullable=False)
    phone_detection = db.Column(db.Integer, nullable=False)
    person_status = db.Column(db.Integer, nullable=False)
    log_time = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp(), nullable=False)
    uid = db.Column(db.Integer, nullable=False)

# Define the Questions model
class Questions(db.Model):
    questions_uid = db.Column(db.Integer, primary_key=True, autoincrement=True)
    test_id = db.Column(db.Text, nullable=False)
    qid = db.Column(db.Text, nullable=False)
    q = db.Column(db.Text, nullable=False)
    a = db.Column(db.Text, nullable=False)
    b = db.Column(db.Text, nullable=False)
    c = db.Column(db.Text, nullable=False)
    d = db.Column(db.Text, nullable=False)
    ans = db.Column(db.Text, nullable=False)
    marks = db.Column(db.Integer, nullable=False)
    uid = db.Column(db.Integer, nullable=False)

# Define the Students model
class Students(db.Model):
    sid = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.Text, nullable=False)
    test_id = db.Column(db.Text, nullable=False)
    qid = db.Column(db.Text, default=None)
    ans = db.Column(db.Text)
    uid = db.Column(db.Integer, nullable=False)

# Define the StudentTestInfo model
class StudentTestInfo(db.Model):
    stiid = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.Text, nullable=False)
    test_id = db.Column(db.Text, nullable=False)
    time_left = db.Column(db.Text, nullable=False)
    completed = db.Column(db.Integer, default=0)
    uid = db.Column(db.Integer, nullable=False)

# Define the Teachers model
class Teachers(db.Model):
    tid = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.Text, nullable=False)
    test_id = db.Column(db.Text, nullable=False)
    test_type = db.Column(db.Text, nullable=False)
    start = db.Column(db.TIMESTAMP, nullable=False, server_default=db.func.current_timestamp())
    end = db.Column(db.TIMESTAMP, nullable=False, default='0000-00-00 00:00:00')
    duration = db.Column(db.Integer, nullable=False)
    show_ans = db.Column(db.Integer, nullable=False)
    password = db.Column(db.Text, nullable=False)
    subject = db.Column(db.Text, nullable=False)
    topic = db.Column(db.Text, nullable=False)
    neg_marks = db.Column(db.Integer, nullable=False)
    calc = db.Column(db.Integer, nullable=False)
    proctoring_type = db.Column(db.Integer, nullable=False, default=0)
    uid = db.Column(db.Integer, nullable=False)

# Define the Users model
class users(db.Model):
    uid = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.Text, nullable=False)
    email = db.Column(db.Text, nullable=False)
    password = db.Column(db.Text, nullable=False)
    register_time = db.Column(db.TIMESTAMP, nullable=False, server_default=db.func.current_timestamp())
    user_type = db.Column(db.Text, nullable=False)
    user_image = db.Column(db.Text, nullable=False)
    user_login = db.Column(db.Integer, nullable=False)
    examcredits = db.Column(db.Integer, nullable=False, default=7)

@app.before_request
def make_session_permanent():
	session.permanent = True

def user_role_professor(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if  session['logged_in']==True:

            if session['user_role'] == "teacher" or session['user_role'] == "Teacher":
                return f(*args, **kwargs)
            else:
                flash('You dont have privilege to access this page!', 'danger')
                return render_template("404.html") 
        else:
            flash('Unauthorized, Please login!', 'danger')
            return redirect(url_for('login'))
    return wrap

def user_role_student(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            if session['user_role'] == "student":
                return f(*args, **kwargs)
            else:
                flash('You dont have privilege to access this page!', 'danger')
                return render_template("404.html") 
        else:
            flash('Unauthorized, Please login!', 'danger')
            return redirect(url_for('login'))
    return wrap

@app.route("/config")
@user_role_professor
def get_publishable_key():
    stripe_config = {"publicKey": stripe_keys["publishable_key"]}
    return jsonify(stripe_config)


@app.route('/video_feed', methods=['GET','POST'])
@user_role_student
def video_feed():
    if request.method == "POST":
        imgData = request.form['data[imgData]']
        testid = request.form['data[testid]']
        voice_db = request.form['data[voice_db]']
        proctorData = camera.get_frame(imgData)
        jpg_as_text = proctorData['jpg_as_text']
        mob_status = proctorData['mob_status']
        person_status = proctorData['person_status']
        user_move1 = proctorData['user_move1']
        user_move2 = proctorData['user_move2']
        eye_movements = proctorData['eye_movements']

        proctoring_log = ProctoringLog(email=session['email'],
                                       name=session['name'],
                                       test_id=testid,
                                       voice_db=voice_db,
                                       img_log=jpg_as_text,
                                       user_movements_updown=user_move1,
                                       user_movements_lr=user_move2,
                                       user_movements_eyes=eye_movements,
                                       phone_detection=mob_status,
                                       person_status=person_status,
                                       uid=session['uid'])

        db.session.add(proctoring_log)
        db.session.commit()

        return "recorded image of video"
    else:
        return "error in video"


@app.route('/window_event', methods=['POST'])
@user_role_student
def window_event():
    if request.method == "POST":
        try:
            testid = request.form['testid']
            
            window_log = WindowEstimationLog(email=session['email'], test_id=testid, name=session['name'], window_event=1, uid=session['uid'])
            db.session.add(window_log)
            db.session.commit()
            
            return "recorded window"
        except Exception as e:
            error_message = f"Error occurred while recording window: {str(e)}"
            return error_message

@app.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():
    try:
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[
                {
                    'price_data': {
                        'currency': 'inr',
                        'unit_amount': 499*100,
                        'product_data': {
                            'name': 'Basic Exam Plan of 10 units',
                            'images': ['https://i.imgur.com/LsvO3kL_d.webp?maxwidth=760&fidelity=grand'],
                        },
                    },
                    'quantity': 1,
                },
            ],
            mode='payment',
            success_url=YOUR_DOMAIN + '/success',
            cancel_url=YOUR_DOMAIN + '/cancelled',
        )
        return jsonify({'id': checkout_session.id})
    except Exception as e:
        return jsonify(error=str(e)), 403

@app.route("/livemonitoringtid")
@user_role_professor
def livemonitoringtid():
    cresults = Teachers.query.filter_by(email=session['email'], uid=session['uid'], proctoring_type=1).all()
    
    if cresults:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        testids = [teacher.test_id for teacher in cresults if teacher.start <= now <= teacher.end]
        return render_template("livemonitoringtid.html", cresults=testids)
    else:
        return render_template("livemonitoringtid.html", cresults=None)


@app.route('/live_monitoring', methods=['GET','POST'])
@user_role_professor
def live_monitoring():
	if request.method == 'POST':
		testid = request.form['choosetid']
		return render_template('live_monitoring.html',testid = testid)
	else:
		return render_template('live_monitoring.html',testid = None)	


@app.route("/success")
@user_role_professor
def success():
    user = users.query.filter_by(email=session['email'], uid=session['uid']).first()
    if user:
        user.examcredits += 10
        db.session.commit()
        return render_template("success.html")
    else:
        flash("User not found!")
        return redirect(url_for('professor_index'))


@app.route("/cancelled")
@user_role_professor
def cancelled():
    return render_template("cancelled.html")

@app.route("/payment")
@user_role_professor
def payment():
    user = users.query.filter_by(email=session['email'], uid=session['uid']).first()
    if user:
        callresults = user.examcredits
        return render_template("payment.html", key=stripe_keys['publishable_key'], callresults=callresults)
    else:
        flash("User not found!")
        return redirect(url_for('professor_index'))

@app.route('/')
def index():
	return render_template('index.html')

@app.errorhandler(404) 
def not_found(e):
	return render_template("404.html") 

@app.errorhandler(500)
def internal_error(error):
	return render_template("500.html") 

@app.route('/calc')
def calc():
	return render_template('calc.html')

@app.route('/report_professor')
@user_role_professor
def report_professor():
	return render_template('report_professor.html')

@app.route('/student_index')
@user_role_student
def student_index():
	return render_template('student_index.html')

@app.route('/professor_index')
@user_role_professor
def professor_index():
	return render_template('professor_index.html')

@app.route('/faq')
def faq():
	return render_template('faq.html')

@app.route('/report_student')
@user_role_student
def report_student():
	return render_template('report_student.html')

@app.route('/report_professor_email', methods=['GET','POST'])
@user_role_professor
def report_professor_email():
	if request.method == 'POST':
		careEmail = 'hafizhashimkardar@gmail.com'
		cname = session['name']
		cemail = session['email']
		ptype = request.form['prob_type']
		cquery = request.form['rquery']
		msg1 = Message('PROBLEM REPORTED', sender = sender, recipients = [careEmail])
		msg1.body = " ".join(["NAME:", cname, "PROBLEM TYPE:", ptype ,"EMAIL:", cemail, "", "QUERY:", cquery]) 
		mail.send(msg1)
		flash('Your Problem has been recorded.', 'success')
	return render_template('report_professor.html')

@app.route('/report_student_email', methods=['GET','POST'])
@user_role_student
def report_student_email():
	if request.method == 'POST':
		careEmail = 'hafizhashimkardar@gmail.com'
		cname = session['name']
		cemail = session['email']
		ptype = request.form['prob_type']
		cquery = request.form['rquery']
		msg1 = Message('PROBLEM REPORTED', sender = sender, recipients = [careEmail])
		msg1.body = " ".join(["NAME:", cname, "PROBLEM TYPE:", ptype ,"EMAIL:", cemail, "", "QUERY:", cquery]) 
		mail.send(msg1)
		flash('Your Problem has been recorded.', 'success')
	return render_template('report_student.html')

@app.route('/contact', methods=['GET','POST'])
def contact():
	if request.method == 'POST':
		careEmail = 'hafizhashimkardar@gmail.com'
		cname = request.form['cname']
		cemail = request.form['cemail']
		cquery = request.form['cquery']
		msg1 = Message('Hello', sender = sender, recipients = [cemail])
		msg2 = Message('Hello', sender = sender, recipients = [careEmail])
		msg1.body = "YOUR QUERY WILL BE PROCESSED! WITHIN 24 HOURS"
		msg2 = Message('Hello', sender = sender, recipients = [careEmail])
		msg2.body = " ".join(["NAME:", cname, "EMAIL:", cemail, "QUERY:", cquery]) 
		mail.send(msg1)
		mail.send(msg2)
		flash('Your Query has been recorded.', 'success')
	return render_template('contact.html')

@app.route('/lostpassword', methods=['GET','POST'])
def lostpassword():
    if request.method == 'POST':
        lpemail = request.form['lpemail']
        results = users.query.filter(users.email == lpemail).all()
        rows = len(results)
        if rows > 0:
            sesOTPfp = generateOTP()
            session['tempOTPfp'] = sesOTPfp
            session['seslpemail'] = lpemail
            msg1 = Message('MyProctor.ai - OTP Verification for Lost Password', sender=sender, recipients=[lpemail])
            msg1.body = "Your OTP Verfication code for reset password is " + sesOTPfp + "."
            mail.send(msg1)
            return redirect(url_for('verifyOTPfp'))
        else:
            return render_template('lostpassword.html', error="Account not found.")
    return render_template('lostpassword.html')


@app.route('/verifyOTPfp', methods=['GET','POST'])
def verifyOTPfp():
	if request.method == 'POST':
		fpOTP = request.form['fpotp']
		fpsOTP = session['tempOTPfp']
		if(fpOTP == fpsOTP):
			return redirect(url_for('lpnewpwd')) 
	return render_template('verifyOTPfp.html')

@app.route('/lpnewpwd', methods=['GET', 'POST'])
def lpnewpwd():
    if request.method == 'POST':
        npwd = request.form['npwd']
        cpwd = request.form['cpwd']
        slpemail = session['seslpemail']
        if npwd == cpwd:
            user = users.query.filter_by(email=slpemail).first()
            if user:
                user.password = npwd
                db.session.commit()
                session.clear()
                return render_template('login.html', success="Your password was successfully changed.")
            else:
                return render_template('login.html', error="User not found.")
        else:
            return render_template('login.html', error="Passwords don't match.")
    return render_template('login.html')

@app.route('/generate_test')
@user_role_professor
def generate_test():
	return render_template('generatetest.html')

@app.route('/changepassword_professor')
@user_role_professor
def changepassword_professor():
	return render_template('changepassword_professor.html')

@app.route('/changepassword_student')
@user_role_student
def changepassword_student():
	return render_template('changepassword_student.html')

def generateOTP() : 
    digits = "0123456789"
    OTP = "" 
    for i in range(5) : 
        OTP += digits[math.floor(random.random() * 10)] 
    return OTP 

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        user_type = request.form['user_type']
        imgdata = request.form['image_hidden']
        session['Name'] = name
        session['Email'] = email
        session['Password'] = password
        session['UT'] = user_type
        session['Image'] = imgdata

        new_user = users(name=name, email=email, password=password, user_type=user_type, user_image=imgdata, user_login=0)

        db.session.add(new_user)
        db.session.commit()
        sesOTP = generateOTP()
        session['tempOTP'] = sesOTP
        msg1 = Message('MyProctor.ai - OTP Verification', sender=sender, recipients=[email])
        msg1.body = "New Account opening - Your OTP Verfication code is " + sesOTP + "."
        mail.send(msg1)
        return redirect(url_for('verifyEmail')) 
    return render_template('register.html')

@app.route('/verifyEmail', methods=['GET', 'POST'])
def verifyEmail():
    if request.method == 'POST':
        theOTP = request.form['eotp']
        mOTP = session['tempOTP']
        dbName = session['Name']
        dbEmail = session['Email']
        dbPassword = session['Password']
        dbUser_type = session['UT']
        dbImgdata = session['Image']
      
        if theOTP == mOTP:
            # Create a new User instance
            new_user = users(name=dbName, email=dbEmail, password=dbPassword, user_type=dbUser_type, user_image=dbImgdata, user_login=0)
            
            db.session.add(new_user)
            
            # Commit the transaction
            db.session.commit()
            
            flash("Thanks for registering! You are successfully verified!")
            return redirect(url_for('login'))
        else:
            return render_template('register.html', error="OTP is incorrect.")
    return render_template('verifyEmail.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password_candidate = request.form['password']
        user_type = request.form['user_type']
        imgdata1 = request.form['image_hidden']
        user = users.query.filter_by(email=email, user_type=user_type).first()
        if user:
            imgdata2 = user.user_image
            password = user.password
            name = user.name
            uid = user.uid
            nparr1 = np.frombuffer(base64.b64decode(imgdata1), np.uint8)
            nparr2 = np.frombuffer(base64.b64decode(imgdata2), np.uint8)
            image1 = cv2.imdecode(nparr1, cv2.COLOR_BGR2GRAY)
            image2 = cv2.imdecode(nparr2, cv2.COLOR_BGR2GRAY)
            img_result = DeepFace.verify(image1, image2, enforce_detection=False)
            if img_result["verified"] == True and password == password_candidate:
                user.user_login = 1
                db.session.commit()  
                session['logged_in'] = True
                session['email'] = email
                session['name'] = name
                session['user_role'] = user_type
                session['uid'] = uid
              
                print(session)

                if user_type == "student":
                    return redirect(url_for('student_index'))
                else:
                     return redirect(url_for('professor_index'))
            else:
                error = 'Either Image not Verified or you have entered Invalid password or Already logged in'
                return render_template('login.html', error=error)
        else:
            error = 'Already logged in or Email was not found!'
            return render_template('login.html', error=error)
        
    return render_template('login.html')



# @app.route('/changepassword', methods=["GET", "POST"])
# def changePassword():
# 	if request.method == "POST":
# 		oldPassword = request.form['oldpassword']
# 		newPassword = request.form['newpassword']
# 		cur = mysql.connection.cursor()
# 		results = cur.execute('SELECT * from users where email = %s and uid = %s', (session['email'], session['uid']))
# 		if results > 0:
# 			data = cur.fetchone()
# 			password = data['password']
# 			usertype = data['user_type']
# 			if(password == oldPassword):
# 				cur.execute("UPDATE users SET password = %s WHERE email = %s", (newPassword, session['email']))
# 				mysql.connection.commit()
# 				msg="Changed successfully"
# 				flash('Changed successfully.', 'success')
# 				cur.close()
# 				if usertype == "student":
# 					return render_template("student_index.html", success=msg)
# 				else:
# 					return render_template("professor_index.html", success=msg)
# 			else:
# 				error = "Wrong password"
# 				if usertype == "student":
# 					return render_template("student_index.html", error=error)
# 				else:
# 					return render_template("professor_index.html", error=error)
# 		else:
# 			return redirect(url_for('/'))

@app.route('/logout', methods=["GET", "POST"])
def logout():
    user = users.query.filter_by(email=session.get('email'), uid=session.get('uid')).first()
    if user:
        user.user_login = 0
        db.session.commit()
        session.clear()
        return redirect(url_for('index'))
    else:
        return "error"
    
def examcreditscheck():
    user = users.query.filter_by(email=session['email'], uid=session['uid']).first()
    if user and user.examcredits >= 1:
        return True
    return False

class QAUploadForm(FlaskForm):
    subject = StringField('Subject')
    topic = StringField('Topic')
    doc = FileField('CSV Upload', validators=[FileRequired()])
    start_date = DateField('Start Date', validators=[DataRequired()], format='%Y-%m-%d')
    start_time = TimeField('Start Time', default=datetime.utcnow()+timedelta(hours=5.5))
    end_date = DateField('End Date', validators=[DataRequired()], format='%Y-%m-%d')
    end_time = TimeField('End Time', default=datetime.utcnow()+timedelta(hours=5.5))
    duration = IntegerField('Duration(in min)')
    password = PasswordField('Exam Password', [validators.Length(min=3, max=6)])
    proctor_type = RadioField('Proctoring Type', choices=[('0','Automatic Monitoring'),('1','Live Monitoring')])

    def validate_end_date(form, field):
        if field.data < form.start_date.data:
            raise ValidationError("End date must not be earlier than start date.")
    
    def validate_end_time(form, field):
        start_date_time = datetime.strptime(str(form.start_date.data) + " " + str(form.start_time.data),"%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%d %H:%M")
        end_date_time = datetime.strptime(str(form.end_date.data) + " " + str(field.data),"%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%d %H:%M")
        if start_date_time >= end_date_time:
            raise ValidationError("End date time must not be earlier/equal than start date time")
    
    def validate_start_date(form, field):
        if datetime.strptime(str(form.start_date.data) + " " + str(form.start_time.data),"%Y-%m-%d %H:%M:%S") < datetime.now():
            raise ValidationError("Start date and time must not be earlier than current")
@app.route('/create_test_lqa', methods=['GET', 'POST'])
@user_role_professor
def create_test_lqa():
    form = QAUploadForm()
    if request.method == 'POST' and form.validate_on_submit():
        test_id = generate_slug(2)
        filename = secure_filename(form.doc.data.filename)
        filestream = form.doc.data
        filestream.seek(0)
        ef = pd.read_csv(filestream,names=['qid', 'q', 'marks'])
       
        if examcreditscheck():
            for _, row in ef.iterrows():
                new_question = LongQA(test_id=test_id, qid=row['qid'], q=row['q'], marks=row['marks'], uid=session['uid'])
                db.session.add(new_question)
            db.session.commit()
            
            start_date = form.start_date.data
            end_date = form.end_date.data
            start_time = form.start_time.data
            end_time = form.end_time.data
            start_date_str = start_date.strftime("%Y-%m-%d")
            end_date_str = end_date.strftime("%Y-%m-%d")

            start_time_str = start_time.strftime("%H:%M:%S")
            end_time_str = end_time.strftime("%H:%M:%S")

            start_date_time = datetime.strptime(start_date_str + " " + start_time_str, "%Y-%m-%d %H:%M:%S")
            end_date_time = datetime.strptime(end_date_str + " " + end_time_str, "%Y-%m-%d %H:%M:%S")
            duration = int(form.duration.data) * 60
            password = form.password.data
            subject = form.subject.data
            topic = form.topic.data
            proctor_type = form.proctor_type.data
            
            new_teacher = Teachers(
                email=session['email'],
                test_id=test_id,
                test_type="subjective",
                start=start_date_time,
                end=end_date_time,
                duration=duration,
                show_ans=0,
                password=password,
                subject=subject,
                topic=topic,
                neg_marks=0,
                calc=0,
                proctoring_type=proctor_type,
                uid=session['uid']
            )
            db.session.add(new_teacher)
            db.session.commit()
            
            user = users.query.filter_by(email=session['email'], uid=session['uid']).first()
            if user:
                user.examcredits -= 1  
                db.session.commit()
            
            
            flash(f'Exam ID: {test_id}', 'success')
            return redirect(url_for('professor_index'))
        else:
            flash("No exam credits points are found! Please pay it!")
            return redirect(url_for('professor_index'))
    return render_template('create_test_lqa.html', form=form)

class UploadForm(FlaskForm):
    subject = StringField('Subject')
    topic = StringField('Topic')
    doc = FileField('CSV Upload', validators=[FileRequired()])
    start_date = DateField('Start Date', validators=[DataRequired()], format='%Y-%m-%d')
    start_time = TimeField('Start Time', default=datetime.utcnow()+timedelta(hours=5.5))
    end_date = DateField('End Date', validators=[DataRequired()], format='%Y-%m-%d')
    end_time = TimeField('End Time', default=datetime.utcnow()+timedelta(hours=5.5))
    calc = BooleanField('Enable Calculator')
    neg_mark = DecimalField('Enable negative marking in % ', validators=[NumberRange(min=0, max=100)])
    duration = IntegerField('Duration(in min)')
    password = PasswordField('Exam Password', [validators.Length(min=3, max=6)])
    proctor_type = RadioField('Proctoring Type', choices=[('0','Automatic Monitoring'),('1','Live Monitoring')])

    def validate_end_date(form, field):
        if field.data < form.start_date.data:
            raise ValidationError("End date must not be earlier than start date.")
    
    def validate_end_time(form, field):
        start_date_time = datetime.strptime(str(form.start_date.data) + " " + str(form.start_time.data),"%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%d %H:%M")
        end_date_time = datetime.strptime(str(form.end_date.data) + " " + str(field.data),"%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%d %H:%M")
        if start_date_time >= end_date_time:
            raise ValidationError("End date time must not be earlier/equal than start date time")
    
    def validate_start_date(form, field):
        if datetime.strptime(str(form.start_date.data) + " " + str(form.start_time.data),"%Y-%m-%d %H:%M:%S") < datetime.now():
            raise ValidationError("Start date and time must not be earlier than current")
class TestForm(Form):
    test_id = StringField('Exam ID')
    password = PasswordField('Exam Password')
    img_hidden_form = HiddenField(label=(''))

@app.route('/create-test', methods = ['GET', 'POST'])
@user_role_professor
def create_test():
    form = UploadForm()
    if request.method == 'POST' and form.validate_on_submit():
        test_id = generate_slug(2)
        filename = secure_filename(form.doc.data.filename)
        filestream = form.doc.data
        filestream.seek(0)
        ef = pd.read_csv(filestream,names=['qid', 'q', 'a', 'b', 'c', 'd', 'ans', 'marks'])
        ef['qid'] = ef['qid'].astype(int)
        ef['marks'] = ef['marks'].astype(int)
        print(ef.dtypes)
        user = users.query.filter_by(email=session['email']).first()
        ecc = user.examcredits
        if ecc:
            for row in range(len(ef)):
                question = Questions(
                    test_id=test_id,
                    qid=int(ef['qid'][row]),
                    q=ef['q'][row],
                    a=ef['a'][row],
                    b=ef['b'][row],
                    c=ef['c'][row],
                    d=ef['d'][row],
                    ans=ef['ans'][row],
                    marks=int(ef['marks'][row]),
                    uid=session['uid']
                )
                db.session.add(question)

            db.session.commit()
            start_date = form.start_date.data
            end_date = form.end_date.data
            start_time = form.start_time.data
            end_time = form.end_time.data

            start_date_str = start_date.strftime("%Y-%m-%d")
            end_date_str = end_date.strftime("%Y-%m-%d")

            start_time_str = start_time.strftime("%H:%M:%S")
            end_time_str = end_time.strftime("%H:%M:%S")

            start_date_time = datetime.strptime(start_date_str + " " + start_time_str, "%Y-%m-%d %H:%M:%S")
            end_date_time = datetime.strptime(end_date_str + " " + end_time_str, "%Y-%m-%d %H:%M:%S")


            neg_mark = int(form.neg_mark.data)
            calc = int(form.calc.data)
            duration = int(form.duration.data)*60
            password = form.password.data
            subject = form.subject.data
            topic = form.topic.data
            proctor_type = form.proctor_type.data
            new_teacher = Teachers(
                email=session['email'],
                test_id=test_id,
                test_type="objective",
                start=start_date_time,
                end=end_date_time,
                duration=duration,
                show_ans=1,
                password=password,
                subject=subject,
                topic=topic,
                neg_marks=neg_mark,
                calc=calc,
                proctoring_type=proctor_type,
                uid=session['uid']
            )
            db.session.add(new_teacher)
            db.session.commit()
            user = users.query.filter_by(email=session['email'], uid=session['uid']).first()
            if user.examcredits >= 1:
                user.examcredits -= 1
                db.session.commit()
            flash(f'Exam ID: {test_id}', 'success')
            return redirect(url_for('professor_index'))
        else:
            flash("No exam credits points are found! Please pay it!")
            return redirect(url_for('professor_index'))
    return render_template('create_test.html' , form = form)

class PracUploadForm(FlaskForm):
    subject = StringField('Subject')
    topic = StringField('Topic')
    questionprac = StringField('Question')
    marksprac = IntegerField('Marks')
    start_date = DateField('Start Date', validators=[DataRequired()], format='%Y-%m-%d')
    start_time = TimeField('Start Time', default=datetime.utcnow()+timedelta(hours=5.5))
    end_time = TimeField('End Time', default=datetime.utcnow()+timedelta(hours=5.5))
    end_date = DateField('End Date', validators=[DataRequired()], format='%Y-%m-%d')
    duration = IntegerField('Duration(in min)')
    compiler = SelectField(u'Compiler/Interpreter', choices=[
        ('11', 'C'), ('27', 'C#'), ('1', 'C++'), ('114', 'Go'), ('10', 'Java'), ('47', 'Kotlin'),
        ('56', 'Node.js'), ('43', 'Objective-C'), ('29', 'PHP'), ('54', 'Perl-6'), ('116', 'Python 3x'),
        ('117', 'R'), ('17', 'Ruby'), ('93', 'Rust'), ('52', 'SQLite-queries'), ('40', 'SQLite-schema'),
        ('39', 'Scala'), ('85', 'Swift'), ('57', 'TypeScript')
    ])
    password = PasswordField('Exam Password', [validators.Length(min=3, max=10)])
    proctor_type = RadioField('Proctoring Type', choices=[
        ('0', 'Automatic Monitoring'), ('1', 'Live Monitoring')
    ])
    
    
    def validate_end_date(form, field):
        if field.data < form.start_date.data:
            raise ValidationError("End date must not be earlier than start date.")
    def validate_end_time(form, field):
        start_date_time = datetime.strptime(str(form.start_date.data) + " " + str(form.start_time.data),"%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%d %H:%M")
        end_date_time = datetime.strptime(str(form.end_date.data) + " " + str(field.data),"%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%d %H:%M")
        if start_date_time >= end_date_time:
            raise ValidationError("End date time must not be earlier/equal than start date time")
	
    def validate_start_date(form, field):
        if datetime.strptime(str(form.start_date.data) + " " + str(form.start_time.data),"%Y-%m-%d %H:%M:%S") < datetime.now():
            raise ValidationError("Start date and time must not be earlier than current")

@app.route('/create_test_pqa', methods=['GET', 'POST'])
@user_role_professor
def create_test_pqa():
    form = PracUploadForm()
    if request.method == 'POST' and form.validate_on_submit():
        ecc = examcreditscheck()
        if ecc:
            test_id = generate_slug(2)
            compiler = form.compiler.data
            questionprac = form.questionprac.data
            marksprac = int(form.marksprac.data)
            practical_question = PracticalQA(
                test_id=test_id,
                qid=1,
                q=questionprac,
                compiler=compiler,
                marks=marksprac,
                uid=session.get('uid')
            )
            db.session.add(practical_question)
            db.session.commit()

            start_date = form.start_date.data
            end_date = form.end_date.data
            start_time = form.start_time.data
            end_time = form.end_time.data
            
            start_date_str = start_date.strftime("%Y-%m-%d")
            end_date_str = end_date.strftime("%Y-%m-%d")

            start_time_str = start_time.strftime("%H:%M:%S")
            end_time_str = end_time.strftime("%H:%M:%S")

            start_date_time = datetime.strptime(start_date_str + " " + start_time_str, "%Y-%m-%d %H:%M:%S")
            end_date_time = datetime.strptime(end_date_str + " " + end_time_str, "%Y-%m-%d %H:%M:%S")
            duration = int(form.duration.data) * 60
            password = form.password.data
            subject = form.subject.data
            topic = form.topic.data
            proctor_type = form.proctor_type.data

            teacher = Teachers(
                email=session['email'],
                test_id=test_id,
                test_type="practical",
                start=start_date_time,
                end=end_date_time,
                duration=duration,
                show_ans=0,
                password=password,
                subject=subject,
                topic=topic,
                neg_marks=0,
                calc=0,
                proctoring_type=proctor_type,
                uid=session['uid']
            )
            db.session.add(teacher)
            db.session.commit()

            user = users.query.filter_by(email=session['email'], uid=session['uid']).first()
            if user:
                user.examcredits -= 0  # Decrement the examcredits by 1
                db.session.commit()

            flash(f'Exam ID: {test_id}', 'success')
            return redirect(url_for('professor_index'))
        else:
            flash("No exam credits points are found! Please pay it!")
            return redirect(url_for('professor_index'))

    return render_template('create_prac_qa.html', form=form)


@app.route('/deltidlist', methods=['GET'])
@user_role_professor
def deltidlist():
    results = Teachers.query.filter_by(email=session.get('email'), uid=session.get('uid')).count()
    if results > 0:
        cresults = Teachers.query.filter_by(email=session.get('email'), uid=session.get('uid')).all()
        now = datetime.now()
        testids = []
        for teacher in cresults:
            if datetime.strptime(str(teacher.start), "%Y-%m-%d %H:%M:%S") > now:
                testids.append(teacher.test_id)
        
        return render_template("deltidlist.html", cresults=testids)
    else:
        return render_template("deltidlist.html", cresults=None)


@app.route('/deldispques', methods=['GET','POST'])
@user_role_professor
def deldispques():
    if request.method == 'POST':
        tidoption = request.form['choosetid']
        test_type = examtypecheck(tidoption)
        if test_type == "objective":
            callresults = Questions.query.filter_by(test_id=tidoption, uid=session['uid']).all()
            return render_template("deldispques.html", callresults=callresults, tid=tidoption)
        elif test_type == "subjective":
            callresults = LongQA.query.filter_by(test_id=tidoption, uid=session['uid']).all()
            return render_template("deldispquesLQA.html", callresults=callresults, tid=tidoption)
        elif test_type == "practical":
            callresults = PracticalQA.query.filter_by(test_id=tidoption, uid=session['uid']).all()
            return render_template("deldispquesPQA.html", callresults=callresults, tid=tidoption)
        else:
            flash("Some Error Occurred!")
            return redirect(url_for('/deltidlist'))

@app.route('/delete_questions/<testid>', methods=['GET', 'POST'])
@user_role_professor
def delete_questions(testid):
    test_type = examtypecheck(testid)
    if test_type == "objective":
        msg = '' 
        if request.method == 'POST':
            testqdel = request.json['qids']
            if testqdel:
                if ',' in testqdel:
                    testqdel = testqdel.split(',')                
                    for getid in testqdel:
                        question_to_delete = Questions.query.filter_by(test_id=testid, qid=getid,uid=session['uid']).first()

                        if question_to_delete:
                            db.session.delete(question_to_delete)
                        db.session.commit()
                            
                    resp = jsonify('<span style=\'color:green;\'>Questions deleted successfully</span>')
                    resp.status_code = 200
                    return resp
                else:
                    question_to_delete = Questions.query.filter_by(test_id=testid, qid=testqdel, uid=session['uid']).first()
                    if question_to_delete:
                        db.session.delete(question_to_delete)
                    db.session.commit()
                    resp = jsonify('<span style=\'color:green;\'>Questions deleted successfully</span>')
                    resp.status_code = 200
                    return resp
    elif test_type == "subjective":
        msg = '' 
        if request.method == 'POST':
            testqdel = request.json['qids']
            if testqdel:
                if ',' in testqdel:
                    testqdel = testqdel.split(',')
                    for getid in testqdel:
                        question_to_delete = LongQA.query.filter_by(test_id=testid, qid=getid, uid=session['uid']).first()

                        if question_to_delete:
                            db.session.delete(question_to_delete)
                        db.session.commit()
                    resp = jsonify('<span style=\'color:green;\'>Questions deleted successfully</span>')
                    resp.status_code = 200
                    return resp
                else:
                    question_to_delete = LongQA.query.filter_by(test_id=testid, qid=testqdel, uid=session['uid']).first()
                    if question_to_delete:
                        db.session.delete(question_to_delete)
                    db.session().commit()
                    resp = jsonify('<span style=\'color:green;\'>Questions deleted successfully</span>')
                    resp.status_code = 200
                    return resp
    elif test_type == "practical":
        msg = '' 
        if request.method == 'POST':
            testqdel = request.json['qids']
            if testqdel:
                if ',' in testqdel:
                    testqdel = testqdel.split(',')
                    for getid in testqdel:
                        question_to_delete = PracticalQA.query.filter_by(test_id=testid, qid=getid, uid=session['uid']).first()
                        if question_to_delete:
                            db.session.delete(question_to_delete)
                        db.session().commit()
                    resp = jsonify('<span style=\'color:green;\'>Questions deleted successfully</span>')
                    resp.status_code = 200
                    return resp
            else:
                question_to_delete = Questions.query.filter_by(test_id=testid, qid=testqdel, uid=session['uid']).first()
                if question_to_delete:
                    db.session.delete(question_to_delete)
                resp = jsonify('<span style=\'color:green;\'>Questions deleted successfully</span>')
                resp.status_code = 200
                return resp
    else:
        flash("Some Error Occured!")
        return redirect(url_for('/deltidlist'))

@app.route('/<testid>/<qid>')
@user_role_professor
def del_qid(testid, qid):
    result = Questions.query.filter_by(test_id=testid, qid=qid, uid=session['uid']).delete()
    db.session.commit()
    if result > 0:
        msg = "Deleted successfully"
        flash('Deleted successfully.', 'success')
        return render_template("deldispques.html", success=msg)
    else:
        return redirect(url_for('deldispques'))

@app.route('/updatetidlist', methods=['GET'])
@user_role_professor
def updatetidlist():
    cresults = Teachers.query.filter_by(email=session['email'], uid=session['uid']).all()
    now = datetime.now()
    testids = [a.test_id for a in cresults if datetime.strptime(str(a.start), "%Y-%m-%d %H:%M:%S") > now]
    return render_template("updatetidlist.html", cresults=testids if testids else None)

@app.route('/updatedispques', methods=['GET', 'POST'])
@user_role_professor
def updatedispques():
    if request.method == 'POST':
        tidoption = request.form['choosetid']
        et = examtypecheck(tidoption)
        if et== "objective":
            temrp = Questions.query.filter_by(test_id=tidoption, uid=session['uid']).all()
            return render_template("updatedispques.html", callresults=temrp)
        elif et == "subjective":
            temrp = LongQA.query.filter_by(test_id=tidoption, uid=session['uid']).all()
            return render_template("updatedispquesLQA.html", callresults=temrp)
        elif et == "practical":
            temrp = PracticalQA.query.filter_by(test_id=tidoption, uid=session['uid']).all()
            return render_template("updatedispquesPQA.html", callresults=temrp)
        else:
            flash('Error occurred!')
            return redirect(url_for('updatetidlist'))

@app.route('/update/<testid>/<qid>', methods=['GET', 'POST'])
@user_role_professor
def update_quiz(testid, qid):
    if request.method == 'GET':
        uresults = Questions.query.filter_by(test_id=testid, qid=qid, uid=session['uid']).all()
        return render_template("updateQuestions.html", uresults=uresults)
    
    if request.method == 'POST':
        ques = request.form['ques']
        ao = request.form['ao']
        bo = request.form['bo']
        co = request.form['co']
        do = request.form['do']
        anso = request.form['anso']
        markso = request.form['mko']
        question = Questions.query.filter_by(test_id=testid, qid=qid, uid=session['uid']).first()
        if question:
            question.q = ques
            question.a = ao
            question.b = bo
            question.c = co
            question.d = do
            question.ans = anso
            question.marks = markso
            db.session.commit()
            flash('Updated successfully.', 'success')
            return redirect(url_for('updatetidlist'))
    
    flash('An error occurred.', 'error')
    return redirect(url_for('updatetidlist'))


@app.route('/updateLQA/<testid>/<qid>', methods=['GET', 'POST'])
@user_role_professor
def update_lqa(testid, qid):
    if request.method == 'GET':
        uresults = LongQA.query.filter_by(test_id=testid, qid=qid, uid=session['uid']).all()
        return render_template("updateQuestionsLQA.html", uresults=uresults)
    
    if request.method == 'POST':
        ques = request.form['ques']
        markso = request.form['mko']
        long_qa = LongQA.query.filter_by(test_id=testid, qid=qid, uid=session['uid']).first()
        if long_qa:
            long_qa.q = ques
            long_qa.marks = markso
            db.session.commit()
            flash('Updated successfully.', 'success')
            return redirect(url_for('updatetidlist'))
    
    flash('An error occurred.', 'error')
    return redirect(url_for('updatetidlist'))




@app.route('/updatePQA/<testid>/<qid>', methods=['GET', 'POST'])
@user_role_professor
def update_PQA(testid, qid):
    if request.method == 'GET':
        uresults = PracticalQA.query.filter_by(test_id=testid, qid=qid, uid=session['uid']).all()
        return render_template("updateQuestionsPQA.html", uresults=uresults)
    
    if request.method == 'POST':
        ques = request.form['ques']
        markso = request.form['mko']
        practical_qa = PracticalQA.query.filter_by(test_id=testid, qid=qid, uid=session['uid']).first()
        if practical_qa:
            practical_qa.q = ques
            practical_qa.marks = markso
            db.session.commit()
            flash('Updated successfully.', 'success')
            return redirect(url_for('updatetidlist'))
        else:
            flash('ERROR OCCURRED.', 'error')
            return redirect(url_for('updatetidlist'))


@app.route('/viewquestions', methods=['GET'])
@user_role_professor
def viewquestions():
    cresults = Teachers.query.filter_by(email=session['email'], uid=session['uid']).all()
    if cresults:
        test_ids = [result.test_id for result in cresults]
        return render_template("viewquestions.html", cresults=test_ids)
    else:
        return render_template("viewquestions.html", cresults=None)

def examtypecheck(tidoption):
    teacher = Teachers.query.filter_by(test_id=tidoption, email=session.get('email'), uid=session.get('uid')).first()
    if teacher:
        return teacher.test_type
    else:
        return None

@app.route('/displayquestions', methods=['GET','POST'])
@user_role_professor
def displayquestions():
    if request.method == 'POST':
        tidoption = request.form['choosetid']
        et = examtypecheck(tidoption)
        if et == "objective":
            callresults = Questions.query.filter_by(test_id=tidoption, uid=session['uid']).all()
            return render_template("displayquestions.html", callresults=callresults)
        elif et == "subjective":
            callresults = LongQA.query.filter_by(test_id=tidoption, uid=session['uid']).all()
            return render_template("displayquestionslong.html", callresults=callresults)
        elif et == "practical":
            callresults = PracticalQA.query.filter_by(test_id=tidoption, uid=session['uid']).all()
            return render_template("displayquestionspractical.html", callresults=callresults)
    else:
        return render_template("displayquestions.html")  


@app.route('/viewstudentslogs', methods=['GET'])
@user_role_professor
def viewstudentslogs():
    cresults = Teachers.query.filter(Teachers.email == session['email'], Teachers.uid == session['uid'], Teachers.proctoring_type == 0).all()
    print(cresults)
    if cresults:
        test_ids = [result.test_id for result in cresults]
        print(test_ids)
        return render_template("viewstudentslogs.html", cresults=test_ids)
    else:
        return render_template("viewstudentslogs.html", cresults=None)

@app.route('/insertmarkstid', methods=['GET'])
@user_role_professor
def insertmarkstid():
    cresults = Teachers.query.filter(Teachers.show_ans == 0, Teachers.email == session['email'], Teachers.uid == session['uid'], (Teachers.test_type == "subjective" or Teachers.test_type == "practical")).all()
    if cresults:
        now = datetime.now()
        testids = [result.test_id for result in cresults if datetime.strptime(str(result.end), "%Y-%m-%d %H:%M:%S") < now]
        return render_template("insertmarkstid.html", cresults=testids)
    else:
        return render_template("insertmarkstid.html", cresults=None)

@app.route('/displaystudentsdetails', methods=['GET', 'POST'])
# @user_role_professor
def displaystudentsdetails():
    if request.method == 'POST':
        tidoption = request.form['choosetid']
        callresults = ProctoringLog.query.filter_by(test_id=tidoption).with_entities(ProctoringLog.email, ProctoringLog.test_id).distinct().all()
        return render_template("displaystudentsdetails.html", callresults=callresults)

@app.route('/insertmarksdetails', methods=['GET', 'POST'])
# @user_role_professor
def insertmarksdetails():
    if request.method == 'POST':
        tidoption = request.form['choosetid']
        et = examtypecheck(tidoption)
        if et == "subjective":
            callresults = LongTest.query.filter_by(test_id=tidoption).with_entities(LongTest.email, LongTest.test_id).distinct().all()
            return render_template("subdispstudentsdetails.html", callresults=callresults)
        elif et == "practical":
            callresults = PracticalTest.query.filter_by(test_id=tidoption).with_entities(PracticalTest.email, PracticalTest.test_id).distinct().all()
            return render_template("pracdispstudentsdetails.html", callresults=callresults)
        else:
            flash("Some Error occurred!", 'error')
            return redirect(url_for('insertmarkstid'))

@app.route('/insertsubmarks/<testid>/<email>', methods=['GET', 'POST'])
# @user_role_professor
def insertsubmarks(testid, email):
    if request.method == "GET":
        callresults = LongTest.query.filter_by(test_id=testid, email=email).join(LongQA, and_(LongTest.test_id == LongQA.test_id, LongTest.qid == LongQA.qid)).order_by(LongTest.qid.asc()).all()
        return render_template("insertsubmarks.html", callresults=callresults)
    if request.method == "POST":
        results1 = LongTest.query.filter_by(test_id=testid, email=email).count()
        for sa in range(1, results1 + 1):
            marksByProfessor = request.form[str(sa)]
            LongTest.query.filter_by(test_id=testid, email=email, qid=sa).update({LongTest.marks: marksByProfessor})
            db.session.commit()
        flash('Marks Entered Successfully!', 'success')
        return redirect(url_for('insertmarkstid'))

@app.route('/insertpracmarks/<testid>/<email>', methods=['GET', 'POST'])
@user_role_professor
def insertpracmarks(testid, email):
    if request.method == "GET":
        callresults = PracticalTest.query.filter_by(test_id=testid, email=email).join(PracticalQA, and_(PracticalTest.test_id == PracticalQA.test_id, PracticalTest.qid == PracticalQA.qid)).order_by(PracticalTest.qid.asc()).all()
        return render_template("insertpracmarks.html", callresults=callresults)
    if request.method == "POST":
        results1 = PracticalTest.query.filter_by(test_id=testid, email=email).count()
        for sa in range(1, results1 + 1):
            marksByProfessor = request.form[str(sa)]
            PracticalTest.query.filter_by(test_id=testid, email=email, qid=sa).update({PracticalTest.marks: marksByProfessor})
            db.session.commit()
        flash('Marks Entered Successfully!', 'success')
        return redirect(url_for('insertmarkstid'))

def displaywinstudentslogs(testid, email):
    callresults = WindowEstimationLog.query.filter_by(test_id=testid, email=email, window_event=1).all()
    return callresults

def countwinstudentslogs(testid, email):
    wincount = WindowEstimationLog.query.filter_by(test_id=testid, email=email, window_event=1).count()
    return [wincount]

def countMobStudentslogs(testid, email):
    mobcount = ProctoringLog.query.filter_by(test_id=testid, email=email, phone_detection=1).count()
    return [mobcount]


def countMTOPstudentslogs(testid, email):
    perc = ProctoringLog.query.filter_by(test_id=testid, email=email, person_status=1).count()
    return [perc]

def countTotalstudentslogs(testid, email):
    tot = ProctoringLog.query.filter_by(test_id=testid, email=email).count()
    return [tot]

@app.route('/studentmonitoringstats/<testid>/<email>', methods=['GET','POST'])
@user_role_professor
def studentmonitoringstats(testid,email):
	return render_template("stat_student_monitoring.html", testid = testid, email = email)

@app.route('/ajaxstudentmonitoringstats/<testid>/<email>', methods=['GET','POST'])
@user_role_professor
def ajaxstudentmonitoringstats(testid,email):
	win = countwinstudentslogs(testid,email)
	mob = countMobStudentslogs(testid,email)
	per = countMTOPstudentslogs(testid,email)
	tot = countTotalstudentslogs(testid,email)
	return jsonify({"win":win,"mob":mob,"per":per,"tot":tot})


@app.route('/displaystudentslogs/<testid>/<email>', methods=['GET','POST'])
# @user_role_professor
def displaystudentslogs(testid, email):
    callresults = ProctoringLog.query.filter_by(test_id=testid, email=email).all()
    return render_template("displaystudentslogs.html", testid=testid, email=email, callresults=callresults)

@app.route('/mobdisplaystudentslogs/<testid>/<email>', methods=['GET','POST'])
# @user_role_professor
def mobdisplaystudentslogs(testid, email):
    callresults = ProctoringLog.query.filter_by(test_id=testid, email=email, phone_detection=1).all()
    return render_template("mobdisplaystudentslogs.html", testid=testid, email=email, callresults=callresults)

@app.route('/persondisplaystudentslogs/<testid>/<email>', methods=['GET','POST'])
# @user_role_professor
def persondisplaystudentslogs(testid, email):
    callresults = ProctoringLog.query.filter_by(test_id=testid, email=email, person_status=1).all()
    return render_template("persondisplaystudentslogs.html", testid=testid, email=email, callresults=callresults)


@app.route('/audiodisplaystudentslogs/<testid>/<email>', methods=['GET','POST'])
# @user_role_professor
def audiodisplaystudentslogs(testid, email):
    callresults = ProctoringLog.query.filter_by(test_id=testid, email=email).all()
    return render_template("audiodisplaystudentslogs.html", testid=testid, email=email, callresults=callresults)

@app.route('/wineventstudentslogs/<testid>/<email>', methods=['GET','POST'])
# @user_role_professor
def wineventstudentslogs(testid,email):
	callresults = displaywinstudentslogs(testid,email)
	return render_template("wineventstudentlog.html", testid = testid, email = email, callresults = callresults)

@app.route('/<email>/<testid>/share_details', methods=['GET','POST'])
@user_role_professor
def share_details(email, testid):
    callresults = Teachers.query.filter_by(test_id=testid, email=email).all()
    return render_template("share_details.html", callresults=callresults)

@app.route('/share_details_emails', methods=['GET','POST'])
@user_role_professor
def share_details_emails():
	if request.method == 'POST':
		tid = request.form['tid']
		subject = request.form['subject']
		topic = request.form['topic']
		duration = request.form['duration']
		start = request.form['start']
		end = request.form['end']
		password = request.form['password']
		neg_marks = request.form['neg_marks']
		calc = request.form['calc']
		emailssharelist = request.form['emailssharelist']
		msg1 = Message('EXAM DETAILS - MyProctor.ai', sender = sender, recipients = [emailssharelist])
		msg1.body = " ".join(["EXAM-ID:", tid, "SUBJECT:", subject, "TOPIC:", topic, "DURATION:", duration, "START", start, "END", end, "PASSWORD", password, "NEGATIVE MARKS in %:", neg_marks,"CALCULATOR ALLOWED:",calc ]) 
		mail.send(msg1)
		flash('Emails sended sucessfully!', 'success')
	return render_template('share_details.html')

@app.route("/publish-results-testid", methods=['GET','POST'])
@user_role_professor
def publish_results_testid():
    cresults = Teachers.query.filter(Teachers.test_type != "objectve", Teachers.show_ans == 0, Teachers.email == session['email'], Teachers.uid == session['uid']).all()
    if cresults > 0:
        now = datetime.now()
        now = now.strftime("%Y-%m-%d %H:%M:%S")
        now = datetime.strptime(now,"%Y-%m-%d %H:%M:%S")
        testids = []
        for a in cresults:
            if datetime.strptime(str(a['end']),"%Y-%m-%d %H:%M:%S") < now:
                testids.append(a['test_id'])
        return render_template("publish_results_testid.html", cresults = testids)
    else:
        return render_template("publish_results_testid.html", cresults = None)

@app.route('/viewresults', methods=['GET', 'POST'])
@user_role_professor
def viewresults():
    if request.method == 'POST':
        tidoption = request.form['choosetid']
        test_type = examtypecheck(tidoption)
        if test_type == "objective":
            callresults = db.session.query(func.sum(LongTest.marks).label('marks'), LongTest.email).filter_by(test_id=tidoption).group_by(LongTest.email).all()
            return render_template("publish_viewresults.html", callresults=callresults, tid=tidoption)
        if test_type == "subjective":
            callresults = db.session.query(func.sum(LongTest.marks).label('marks'), LongTest.email).filter_by(test_id=tidoption).group_by(LongTest.email).all()
            return render_template("publish_viewresults.html", callresults=callresults, tid=tidoption)
        elif test_type == "practical":
            callresults = db.session.query(func.sum(PracticalTest.marks).label('marks'), PracticalTest.email).filter_by(test_id=tidoption).group_by(PracticalTest.email).all()
            return render_template("publish_viewresults.html", callresults=callresults, tid=tidoption)
        else:
            flash("Some Error Occurred!")
            return redirect(url_for('publish-results-testid'))

@app.route('/publish_results', methods=['GET','POST'])
@user_role_professor
def publish_results():
    if request.method == 'POST':
        tidoption = request.form['testidsp']
        teacher = Teachers.query.filter_by(test_id=tidoption).first()
        if teacher:
            teacher.show_ans = 1
            db.session.commit()
            flash("Results published successfully!")
        else:
            flash("Teacher with specified test ID not found!")
        return redirect(url_for('professor_index'))

@app.route('/test_update_time', methods=['GET', 'POST'])
@user_role_student
def test_update_time():
    if request.method == 'POST':
        time_left = request.form['time']
        testid = request.form['testid']
        student_test_info = StudentTestInfo.query.filter_by(email=session['email'], test_id=testid, uid=session['uid'], completed=0).first()
        if student_test_info:
            student_test_info.time_left = time_left
        else:
            new_student_test_info = StudentTestInfo(email=session['email'], test_id=testid, time_left=time_left, uid=session['uid'])
            db.session.add(new_student_test_info)
        db.session.commit()
        return "Time recorded updated" if student_test_info else "Time recorded inserted"


@app.route("/give-test", methods=['GET', 'POST'])
@user_role_student
def give_test():
    global duration, marked_ans, calc, subject, topic, proctortype
    form = TestForm(request.form)
    if request.method == 'POST' and form.validate():
        test_id = form.test_id.data
        password_candidate = form.password.data
        imgdata1 = form.img_hidden_form.data
        user = users.query.filter_by(email=session['email'], user_type='student').first()
        if user:
            imgdata2 = user.user_image
            nparr1 = np.frombuffer(base64.b64decode(imgdata1), np.uint8)
            nparr2 = np.frombuffer(base64.b64decode(imgdata2), np.uint8)
            image1 = cv2.imdecode(nparr1, cv2.COLOR_BGR2GRAY)
            image2 = cv2.imdecode(nparr2, cv2.COLOR_BGR2GRAY)
            img_result = DeepFace.verify(image1, image2, enforce_detection=False)
            if img_result["verified"] == True:
                teacher = Teachers.query.filter_by(test_id=test_id).first()
                if teacher:
                    password = teacher.password
                    duration = teacher.duration
                    calc = teacher.calc
                    subject = teacher.subject
                    topic = teacher.topic
                    start = teacher.start
                    end = teacher.end
                    proctortype = teacher.proctoring_type
                    if password == password_candidate:
                        now = datetime.now()
                        if start < now < end:
                            student_test_info = StudentTestInfo.query.filter_by(email=session['email'],
                                                                                 test_id=test_id).first()
                            if student_test_info:
                                time_left = student_test_info.time_left
                                is_completed = student_test_info.completed
                                if is_completed == 0:
                                    print("Time Left: ",time_left)
                                    print("Duration",duration)
                                    if int(time_left) <= duration:
                                        duration = time_left
                                        student_answers = Students.query.filter_by(email=session['email'],
                                                                                      test_id=test_id,
                                                                                      uid=session['uid']).all()
                                        marked_ans = {}
                                        for answer in student_answers:
                                            qiddb = str(answer.qid)
                                            marked_ans[qiddb] = answer.ans
                                        marked_ans = json.dumps(marked_ans)
                                else:
                                    flash('Exam already given', 'success')
                                    return redirect(url_for('give_test'))
                            else:
                                new_test_info = StudentTestInfo(email=session['email'], test_id=test_id,
                                                                time_left=duration, uid=session['uid'])
                                db.session.add(new_test_info)
                                db.session.commit()
                                test_info = StudentTestInfo.query.filter_by(email=session['email'],
                                                                                test_id=test_id,
                                                                                uid=session['uid']).first()
                                if test_info:
                                    is_completed = test_info.completed
                                    if is_completed == 0:
                                        time_left = test_info.time_left
                                        if int(time_left) <= duration:
                                            duration = time_left
                                            marked_answers = {}
                                            student_answers = Students.query.filter_by(email=session['email'],
                                                                                            test_id=test_id,
                                                                                            uid=session['uid']).all()
                                            if student_answers:
                                                for row in student_answers:
                                                    marked_answers[row.qid] = row.ans
                                                marked_ans = json.dumps(marked_answers)
                        else:
                            if start > now:
                                flash(f'Exam start time is {start}', 'danger')
                            else:
                                flash(f'Exam has ended', 'danger')
                                return redirect(url_for('give_test'))
                        return redirect(url_for('test', testid=test_id))
                    else:
                        flash('Invalid password', 'danger')
                        return redirect(url_for('give_test'))
                else:
                    flash('Invalid testid', 'danger')
                    return redirect(url_for('give_test'))
            else:
                flash('Image not Verified', 'danger')
                return redirect(url_for('give_test'))
    return render_template('give_test.html', form=form)


@app.route('/give-test/<testid>', methods=['GET','POST'])
@user_role_student
def test(testid):
    test_type = db.session.query(Teachers.test_type).filter_by(test_id=testid).scalar()
    if test_type == "objective":
        global duration, marked_ans, calc, subject, topic, proctortype
        if request.method == 'GET':
            try:
                data = {'duration': duration, 'marks': '', 'q': '', 'a': '', 'b':'','c':'','d':'' }
                return render_template('testquiz.html' ,**data, answers=marked_ans, calc=calc, subject=subject, topic=topic, tid=testid, proctortype=proctortype)
            except:
                return redirect(url_for('give_test'))
        else:
            flag = request.form['flag']
            if flag == 'get':
                num = request.form['no']
                results = Questions.query.filter_by(test_id=testid, qid=num).first()
                if results:
                    results.ans=None
                    data_dict = {
                    'test_id': results.test_id,
                    'qid': results.qid,
                    'q': results.q,
                    'a': results.a,
                    'b': results.b,
                    'c': results.c,
                    'd': results.d,
                    'marks': results.marks
                }
                    return json.dumps(data_dict)
            elif flag=='mark':
                qid = request.form['qid']
                ans = request.form['ans']
                results = Students.query.filter_by(test_id=testid, qid=qid, email=session['email']).first()
                if results:
                    results.ans = ans 
                    db.session.commit()
                else:
                    new_student_record = Students(
                        email=session['email'],
                        test_id=testid,
                        qid=qid,
                        ans=ans,
                        uid=session['uid']
                    )
                    db.session.add(new_student_record)
                    db.session.commit()
            elif flag=='time':
                time_left = request.form['time']
                try:
                    student_test_info_record = StudentTestInfo.query.filter_by(test_id=testid, email=session['email'], uid=session['uid'], completed=0).first()
                    if student_test_info_record:
                        student_test_info_record.time_left = time_left  
                        db.session.commit()
                    return json.dumps({'time':'fired'})
                except:
                    pass
            else:
                student_test_info_record = StudentTestInfo.query.filter_by(test_id=testid, email=session['email'], uid=session['uid']).first()
                if student_test_info_record:
                    student_test_info_record.completed = 1
                    student_test_info_record.time_left = 0 
                    db.session.commit()
                flash("Exam submitted successfully", 'info')
                return json.dumps({'sql':'fired'})

    elif test_type == "subjective":
        if request.method == 'GET':
            callresults1 = LongQA.query.filter_by(test_id=testid).order_by(func.random()).all()
            student_test_info = StudentTestInfo.query.filter_by(test_id=testid, email=session['email'], uid=session['uid'], completed=0).first()
            if student_test_info != None:
                testDetails = Teachers.query.filter_by(test_id=testid).first()
                subject = testDetails.subject
                test_id = testDetails.test_id
                topic = testDetails.topic
                proctortypes = testDetails.proctoring_type
                return render_template("testsubjective.html", callresults = callresults1, subject = subject, duration = duration, test_id = test_id, topic = topic, proctortypes = proctortypes )
            else:
                testDetails = Teachers.query.filter_by(test_id=testid).first()
                subject = testDetails.subject
                duration = testDetails.duration
                test_id = testDetails.test_id
                topic = testDetails.topic
                return render_template("testsubjective.html", callresults = callresults1, subject = subject, duration = duration, test_id = test_id, topic = topic )
        elif request.method == 'POST':
            test_id = request.form["test_id"]
            results1 = LongQA.query.filter_by(test_id=testid).count()

            insertStudentData = None
            for sa in range(1,results1+1):
                answerByStudent = request.form[str(sa)]
                insertStudentData = LongTest(
                    email=session['email'],
                    test_id=testid,
                    qid=sa,
                    ans=answerByStudent,
                    uid=session['uid']
                )
                db.session.add(insertStudentData)
                db.session.commit()
            else:
                if insertStudentData > 0:
                    update_student_test_info = StudentTestInfo.query.filter_by(test_id=test_id, email=session['email'], uid=session['uid']).update({"completed": 1})

                    db.session.commit()
                    if update_student_test_info > 0:
                        flash('Successfully Exam Submitted', 'success')
                        return redirect(url_for('student_index'))
                    else:
                        flash('Some Error was occured!', 'error')
                        return redirect(url_for('student_index'))    
                else:
                    flash('Some Error was occured!', 'error')
                    return redirect(url_for('student_index'))

    elif test_type == "practical":
        if request.method == 'GET':
            callresults1 = PracticalQA.query.filter_by(test_id=testid).order_by(func.random()).all()
            student_test_info = StudentTestInfo.query.filter_by(test_id=testid, email=session['email'], uid=session['uid'], completed=0).first()
            if student_test_info != None:    
                testDetails = Teachers.query.filter_by(test_id=testid).first()
                subject = testDetails.subject
                test_id = testDetails.test_id
                topic = testDetails.topic
                proctortypep = testDetails.proctoring_type
                return render_template("testpractical.html", callresults = callresults1, subject = subject, duration = duration, test_id = test_id, topic = topic, proctortypep = proctortypep )
            else:
                testDetails = Teachers.query.filter_by(test_id=testid).first()
                subject = testDetails.subject
                duration = testDetails.duration
                test_id = testDetails.test_id
                topic = testDetails.topic
                return render_template("testpractical.html", callresults = callresults1, subject = subject, duration = duration, test_id = test_id, topic = topic )
        elif request.method == 'POST':
            test_id = request.form["test_id"]
            codeByStudent = request.form["codeByStudent"]
            inputByStudent = request.form["inputByStudent"]
            executedByStudent = request.form["executedByStudent"]
            insertStudentData = PracticalTest(
                email=session['email'],
                test_id=testid,
                qid="1",
                code=codeByStudent,
                input=inputByStudent,
                executed=executedByStudent,
                uid=session['uid']
            )
            db.session.add(insertStudentData)
            db.session.commit()
            if insertStudentData > 0:
                insertStudentTestInfoData = StudentTestInfo.query.filter_by(test_id=test_id, email=session['email'], uid=session['uid']).first()

                if insertStudentTestInfoData:
                    insertStudentTestInfoData.completed = 1
                    db.session.commit()
                if insertStudentTestInfoData > 0:
                    flash('Successfully Exam Submitted', 'success')
                    return redirect(url_for('student_index'))
                else:
                    flash('Some Error was occured!', 'error')
                    return redirect(url_for('student_index'))    
            else:
                flash('Some Error was occured!', 'error')
                return redirect(url_for('student_index'))
    # return redirect(url_for('student_index'))

@app.route('/randomize', methods=['POST'])
def random_gen():
    if request.method == "POST":
        test_id = request.form['id']
        try:
            question_count = Questions.query.filter_by(test_id=test_id).count()
            if question_count > 0:
                total = question_count
                nos = list(range(1, total + 1))
                random.Random(test_id).shuffle(nos)
                return json.dumps(nos)
            else:
                return "No questions found for the given test ID"
        except Exception as e:
            return str(e)

@app.route('/<email>/<testid>')
def check_result(email, testid):
    if email == session['email']:
        try:
            teacher = Teachers.query.filter_by(test_id=testid).first()
            if teacher:
                check = teacher.show_ans
                if check == 1:
                    results = db.session.query(Questions.q, Questions.a, Questions.b, Questions.c, Questions.d, Questions.marks, Questions.qid.label('qid'), 
                                               Questions.ans.label('correct'), db.func.ifnull(Students.ans, 0).label('marked')) \
                                        .outerjoin(Students, (Students.test_id == Questions.test_id) & (Students.test_id == testid) & (Students.email == email) & 
                                                   (Students.uid == session['uid']) & (Students.qid == Questions.qid)) \
                                        .filter(Students.test_id == testid, Students.email == email, Students.uid == session['uid'], Students.qid == Questions.qid) \
                                        .group_by(Questions.qid) \
                                        .order_by(db.func.LPAD(db.func.lower(Questions.qid), 10, '0').asc()) \
                                        .all()
                    if results:
                        return render_template('tests_result.html', results=results)
                    else:
                        flash('No results found', 'danger')
                        return redirect(url_for('tests_given', email=email))
                else:
                    flash('You are not authorized to check the result', 'danger')
                    return redirect(url_for('tests_given', email=email))
        except Exception as e:
            flash(str(e), 'danger')
            return redirect(url_for('student_index'))
    else:
        return redirect(url_for('student_index'))


def neg_marks(email, testid, negm):
    # Query to fetch data from the database
    results = db.session.query(Questions.marks,
                               Questions.qid.label('qid'),
                               Questions.ans.label('correct'),
                               func.ifnull(Students.ans, 0).label('marked')) \
                       .join(Students, (Students.test_id == Questions.test_id) & (Students.qid == Questions.qid)) \
                       .filter(Students.test_id == testid, Students.email == email, Students.qid == Questions.qid) \
                       .group_by(Questions.qid) \
                       .order_by(Questions.qid.asc()) \
                       .all()

    total_marks = 0.0
    for row in results:
        if row.marked.upper() != '0':
            if row.marked.upper() != row.correct.upper():
                total_marks -= (negm / 100) * int(row.marks)
            elif row.marked.upper() == row.correct.upper():
                total_marks += int(row.marks)

    return total_marks


def totmarks(email, tests):
    total_marks = 0.0
    for test in tests:
        test_id = test.test_id
        result = db.session.query(Teachers.neg_marks).filter_by(test_id=test_id).first()
        negm = result.neg_marks if result else 0
        marks = neg_marks(email, test_id, negm)
        total_marks += marks

    return total_marks


def marks_calc(email, testid):
    teacher = Teachers.query.filter_by(test_id=testid).first()
    negm = teacher.neg_marks if teacher else 0
    return neg_marks(email, testid, negm)

@app.route('/<email>/tests-given', methods=['POST', 'GET'])
@user_role_student
def tests_given(email):
    if request.method == "GET":
        if email == session['email']:
            resultsTestids = StudentTestInfo.query.filter(StudentTestInfo.email == session['email'], StudentTestInfo.completed == 1).join(Teachers, Teachers.test_id == StudentTestInfo.test_id).filter(Teachers.show_ans == 1).with_entities(StudentTestInfo.test_id).all()
            return render_template('tests_given.html', cresults=resultsTestids)
        else:
            flash('You are not authorized', 'danger')
            return redirect(url_for('student_index'))
    elif request.method == "POST":
        tidoption = request.form['choosetid']
        teacher = Teachers.query.filter_by(test_id=tidoption).first()
        if teacher:
            if teacher.test_type == "objective":
                results = Students.query.filter(Students.email == email, Students.test_id == tidoption).join(StudentTestInfo, StudentTestInfo.test_id == Students.test_id).filter(StudentTestInfo.completed == 1).all()
                student_results = [(result, neg_marks(result.email, result.test_id, teacher.neg_marks)) for result in results]
                return render_template('obj_result_student.html', tests=student_results)
            elif teacher.test_type == "subjective":
                student_results = LongTest.query.with_entities(func.sum(LongTest.marks).label('marks'), LongTest.test_id.label('test_id'), Teachers.subject, Teachers.topic).filter(LongTest.email == email, LongTest.test_id == tidoption, LongTest.test_id == Teachers.test_id, StudentTestInfo.test_id == Teachers.test_id, LongTest.email == StudentTestInfo.email, StudentTestInfo.completed == 1, Teachers.show_ans == 1).group_by(LongTest.test_id).all()
                return render_template('sub_result_student.html', tests=student_results)
            elif teacher.test_type == "practical":
                student_results = PracticalTest.query.with_entities(func.sum(PracticalTest.marks).label('marks'), PracticalTest.test_id.label('test_id'), Teachers.subject, Teachers.topic).filter(PracticalTest.email == email, PracticalTest.test_id == tidoption, PracticalTest.test_id == Teachers.test_id, StudentTestInfo.test_id == Teachers.test_id, PracticalTest.email == StudentTestInfo.email, StudentTestInfo.completed == 1, Teachers.show_ans == 1).group_by(PracticalTest.test_id).all()
                return render_template('prac_result_student.html', tests=student_results)
        else:
            flash('Test not found', 'danger')
            return redirect(url_for('student_index'))
    else:
        flash('You are not authorized', 'danger')
        return redirect(url_for('student_index'))

@app.route('/<email>/tests-created')
def tests_created(email):
    if email == session.get('email'):
        tests = Teachers.query.filter_by(email=email, uid=session.get('uid'), show_ans=1).all()
        return render_template('tests_created.html', tests=tests)
    else:
        flash('You are not authorized', 'danger')
        return redirect(url_for('professor_index'))



@app.route('/<email>/tests-created/<testid>', methods=['POST', 'GET'])
@user_role_professor
def student_results(email, testid):
    if email == session.get('email'):
        et = examtypecheck(testid)
        if request.method == 'GET':
            if et == "objective":
                # Query the database using SQLAlchemy to fetch student results for objective tests
                students = db.session.query(users.name.label('name'), users.email.label('email'), StudentTestInfo.test_id.label('test_id')) \
                            .join(StudentTestInfo, StudentTestInfo.email == users.email) \
                            .filter(StudentTestInfo.test_id == testid, StudentTestInfo.completed == 1, users.user_type == 'student') \
                            .all()
                final = []
                names = []
                scores = []
                count = 1
                for student in students:
                    score = marks_calc(student.email, student.test_id)
                    final.append([count, student.name, score])
                    names.append(student.name)
                    scores.append(score)
                    count += 1
                return render_template('student_results.html', data=final, labels=names, values=scores)
            elif et== "subjective":
                # Query the database using SQLAlchemy to fetch student results for subjective tests
                students = db.session.query(users.name.label('name'), users.email.label('email'), LongTest.test_id.label('test_id'), db.func.sum(LongTest.marks).label('marks')) \
                            .join(LongTest, LongTest.email == users.email) \
                            .filter(LongTest.test_id == testid, users.user_type == 'student') \
                            .group_by(users.name, users.email, LongTest.test_id) \
                            .all()
                names = [student.name for student in students]
                scores = [student.marks for student in students]
                return render_template('student_results_lqa.html', data=students, labels=names, values=scores)
            elif et == "practical":
                # Query the database using SQLAlchemy to fetch student results for practical tests
                students = db.session.query(users.name.label('name'), users.email.label('email'), PracticalTest.test_id.label('test_id'), db.func.sum(PracticalTest.marks).label('marks')) \
                            .join(PracticalTest, PracticalTest.email == users.email) \
                            .filter(PracticalTest.test_id == testid, users.user_type == 'student') \
                            .group_by(users.name, users.email, PracticalTest.test_id) \
                            .all()
                names = [student.name for student in students]
                scores = [student.marks for student in students]
                return render_template('student_results_pqa.html', data=students, labels=names, values=scores)
    else:
        flash('You are not authorized', 'danger')
        return redirect(url_for('professor_index'))

@app.route('/<email>/disptests')
@user_role_professor
def disptests(email):
    if email == session.get('email'):
        # Query the database using SQLAlchemy to fetch the tests created by the professor
        tests = Teachers.query.filter_by(email=email, uid=session['uid']).all()
        return render_template('disptests.html', tests=tests)
    else:
        flash('You are not authorized', 'danger')
        return redirect(url_for('professor_index'))

@app.route('/<email>/student_test_history')
@user_role_student
def student_test_history(email):
    if email == session.get('email'):
        tests = db.session.query(StudentTestInfo.test_id, Teachers.subject, Teachers.topic) \
                          .join(Teachers, StudentTestInfo.test_id == Teachers.test_id) \
                          .filter(StudentTestInfo.email == email, StudentTestInfo.completed == 1) \
                          .all()
        return render_template('student_test_history.html', tests=tests)
    else:
        flash('You are not authorized', 'danger')
        return redirect(url_for('student_index'))

@app.route('/test_generate', methods=["GET", "POST"])
@user_role_professor
def test_generate():
    if request.method == "POST":
        inputText = request.form["itext"]
        testType = request.form["test_type"]
        noOfQues = request.form["noq"]
        if testType == "objective":
            print(inputText)
            objective_generator = ObjectiveTest(inputText, noOfQues)
            question_list, answer_list = objective_generator.generate_test()
            testgenerate = zip(question_list, answer_list)
            return render_template('generatedtestdata.html', cresults=testgenerate)
        elif testType == "subjective":
            subjective_generator = SubjectiveTest(inputText, noOfQues)
            question_list, answer_list = subjective_generator.generate_test()
            testgenerate = zip(question_list, answer_list)
            return render_template('generatedtestdata.html', cresults=testgenerate)
        else:
            return None


if __name__ == "__main__":
	app.run(host = "0.0.0.0",debug=False)

