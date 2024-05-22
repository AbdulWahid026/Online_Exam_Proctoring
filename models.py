from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

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
class Users(db.Model):
    uid = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.Text, nullable=False)
    email = db.Column(db.Text, nullable=False)
    password = db.Column(db.Text, nullable=False)
    register_time = db.Column(db.TIMESTAMP, nullable=False, server_default=db.func.current_timestamp())
    user_type = db.Column(db.Text, nullable=False)
    user_image = db.Column(db.Text, nullable=False)
    user_login = db.Column(db.Integer, nullable=False)
    examcredits = db.Column(db.Integer, nullable=False, default=7)


