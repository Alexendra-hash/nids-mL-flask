from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from sqlalchemy.engine import URL
from sqlalchemy import func
from datetime import datetime
import joblib
import numpy as np
from flask_mail import Mail, Message
from scapy.all import sniff

app = Flask(__name__)

app.config['SECRET_KEY'] = 'nids_secret_key_abu_2026'

app.config["SQLALCHEMY_DATABASE_URI"] = URL.create(
    drivername="mysql+pymysql",
    username="root",
    password="MySQL@2026!",
    host="localhost",
    port=3306,
    database="nids_db"
)

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'alexaobioha@gmail.com'
app.config['MAIL_PASSWORD'] = 'lqff kovd hmcs ftvm'
app.config['MAIL_DEFAULT_SENDER'] = 'alexaobioha@gmail.com'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
mail = Mail(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'warning'

model = joblib.load('nids_model.pkl')
label_encoder = joblib.load('label_encoder.pkl')

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='user')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    detections = db.relationship('Detection', backref='user', lazy=True)

class Detection(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # Detection Result
    result = db.Column(db.String(30), nullable=False)
    attack_type = db.Column(db.String(50))
    attack_category = db.Column(db.String(30))

    confidence = db.Column(db.Float, nullable=False)

    # Network Information
    protocol_type = db.Column(db.Float)
    src_bytes = db.Column(db.Float)
    dst_bytes = db.Column(db.Float)

    source_ip = db.Column(db.String(50))
    destination_ip = db.Column(db.String(50))

    count = db.Column(db.Float)
    serror_rate = db.Column(db.Float)

    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

def packet_callback(packet):
    print(packet.summary())
    
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm = request.form['confirm_password']
        role = request.form.get('role', 'user')

        if password != confirm:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('register'))

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered!', 'danger')
            return redirect(url_for('register'))

        existing_username = User.query.filter_by(username=username).first()
        if existing_username:
            flash('Username already taken!', 'danger')
            return redirect(url_for('register'))

        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(
            username=username,
            email=email,
            password=hashed_pw,
            role=role
        )

        db.session.add(user)
        db.session.commit()

        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('auth/register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash(f'Welcome back, {user.username}!', 'success')
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('dashboard'))
        flash('Invalid email or password!', 'danger')
    return render_template('auth/login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    detections = Detection.query.filter_by(user_id=current_user.id).order_by(Detection.timestamp.desc()).limit(10).all()
    total = Detection.query.filter_by(user_id=current_user.id).count()
    normal = Detection.query.filter_by(
    user_id=current_user.id,
    result='NORMAL'
).count() 
    attacks = Detection.query.filter(
    Detection.user_id == current_user.id,
    Detection.result != 'NORMAL'
).count()
    return render_template('dashboard.html', detections=detections, total=total, attacks=attacks, normal=normal)

@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('Access denied!', 'danger')
        return redirect(url_for('dashboard'))

    # Users
    users = User.query.all()
    total_users = User.query.count()

    # Detection statistics
    total_detections = Detection.query.count()

    total_normal = Detection.query.filter_by(
        result='NORMAL'
    ).count()

    total_attacks = Detection.query.filter(
        Detection.result != 'NORMAL'
    ).count()

    # Recent detections
    recent = Detection.query.order_by(
        Detection.timestamp.desc()
    ).limit(10).all()

    # Timeline chart
    timeline_data = (
        db.session.query(
            func.date(Detection.timestamp),
            func.count(Detection.id)
        )
        .group_by(func.date(Detection.timestamp))
        .order_by(func.date(Detection.timestamp))
        .all()
    )

    timeline_labels = [str(item[0]) for item in timeline_data]
    timeline_counts = [item[1] for item in timeline_data]

    # Attack Category Chart
    category_data = (
        db.session.query(
            Detection.attack_category,
            func.count(Detection.id)
        )
        .group_by(Detection.attack_category)
        .all()
    )

    category_labels = [row[0] for row in category_data]
    category_counts = [row[1] for row in category_data]

    return render_template(
        'admin.html',

        users=users,
        total_users=total_users,

        total_detections=total_detections,
        total_attacks=total_attacks,
        total_normal=total_normal,

        recent=recent,

        timeline_labels=timeline_labels,
        timeline_counts=timeline_counts,

        category_labels=category_labels,
        category_counts=category_counts
    )
@app.route('/admin/users')
@login_required
def manage_users():
    if current_user.role != 'admin':
        flash('Access denied!', 'danger')
        return redirect(url_for('dashboard'))
    users = User.query.all()
    return render_template('manage_users.html', users=users)

@app.route('/admin/delete_user/<int:user_id>')
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        flash('Access denied!', 'danger')
        return redirect(url_for('dashboard'))
    user = User.query.get_or_404(user_id)
    if user.role == 'admin':
        flash('Cannot delete admin account!', 'danger')
        return redirect(url_for('manage_users'))
    Detection.query.filter_by(user_id=user_id).delete()
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully!', 'success')
    return redirect(url_for('manage_users'))

ATTACK_CATEGORIES = {
    "normal":"Normal",

    "neptune":"DoS",
    "smurf":"DoS",
    "back":"DoS",
    "teardrop":"DoS",
    "pod":"DoS",
    "land":"DoS",

    "ipsweep":"Probe",
    "portsweep":"Probe",
    "nmap":"Probe",
    "satan":"Probe",

    "ftp_write":"R2L",
    "guess_passwd":"R2L",
    "imap":"R2L",
    "multihop":"R2L",
    "phf":"R2L",
    "spy":"R2L",
    "warezclient":"R2L",
    "warezmaster":"R2L",

    "buffer_overflow":"U2R",
    "loadmodule":"U2R",
    "perl":"U2R",
    "rootkit":"U2R"
}

@app.route('/analyse', methods=['GET', 'POST'])
@login_required
def analyse():
    if request.method == 'POST':
        try:
            features = [
                float(request.form['duration']),
                float(request.form['protocol_type']),
                float(request.form['service']),
                float(request.form['flag']),
                float(request.form['src_bytes']),
                float(request.form['dst_bytes']),
                float(request.form['land']),
                float(request.form['wrong_fragment']),
                float(request.form['urgent']),
                float(request.form['hot']),
                float(request.form['num_failed_logins']),
                float(request.form['logged_in']),
                float(request.form['num_compromised']),
                float(request.form['root_shell']),
                float(request.form['su_attempted']),
                float(request.form['num_root']),
                float(request.form['num_file_creations']),
                float(request.form['num_shells']),
                float(request.form['num_access_files']),
                float(request.form['num_outbound_cmds']),
                float(request.form['is_host_login']),
                float(request.form['is_guest_login']),
                float(request.form['count']),
                float(request.form['srv_count']),
                float(request.form['serror_rate']),
                float(request.form['srv_serror_rate']),
                float(request.form['rerror_rate']),
                float(request.form['srv_rerror_rate']),
                float(request.form['same_srv_rate']),
                float(request.form['diff_srv_rate']),
                float(request.form['srv_diff_host_rate']),
                float(request.form['dst_host_count']),
                float(request.form['dst_host_srv_count']),
                float(request.form['dst_host_same_srv_rate']),
                float(request.form['dst_host_diff_srv_rate']),
                float(request.form['dst_host_same_src_port_rate']),
                float(request.form['dst_host_srv_diff_host_rate']),
                float(request.form['dst_host_serror_rate']),
                float(request.form['dst_host_srv_serror_rate']),
                float(request.form['dst_host_rerror_rate']),
                float(request.form['dst_host_srv_rerror_rate']),
            ]

            input_data = np.array([features])

            prediction = model.predict(input_data)[0]
            probability = model.predict_proba(input_data)[0]

            confidence = round(max(probability) * 100, 2)

            attack_name = label_encoder.inverse_transform([prediction])[0]


            attack_categories = {
                "normal": "Normal",
                "neptune": "DoS",
                "smurf": "DoS",
                "teardrop": "DoS",
                "back": "DoS",
                "pod": "DoS",
                "land": "DoS",

                "ipsweep": "Probe",
                "nmap": "Probe",
                "portsweep": "Probe",
                "satan": "Probe",

                "ftp_write": "R2L",
                "guess_passwd": "R2L",
                "imap": "R2L",
                "multihop": "R2L",
                "phf": "R2L",
                "spy": "R2L",
                "warezclient": "R2L",
                "warezmaster": "R2L",

                "buffer_overflow": "U2R",
                "loadmodule": "U2R",
                "perl": "U2R",
                "rootkit": "U2R"
            }


            attack_category = attack_categories.get(
                attack_name.lower(),
                "Unknown"
            )


            print("Prediction:", attack_name)
            print("Category:", attack_category)
            print("Confidence:", confidence)


            if attack_name.lower() == "normal":
                result = "NORMAL"
                alert = "success"

            else:
                result = attack_name.upper()
                alert = "danger"

                msg = Message(
                    subject="🚨 Network Intrusion Alert",
                    recipients=["alexaobioha@gmail.com"]
                )

                msg.body = f"""
NETWORK INTRUSION DETECTED

Attack Type: {attack_name.upper()}
Confidence: {confidence}%

Time: {datetime.now()}
"""

                mail.send(msg)


            source_ip = request.remote_addr
            destination_ip = "Server"

            detection = Detection(
                user_id=current_user.id,
                result=result,
                attack_type=attack_name.upper(),
                attack_category=attack_category,

                confidence=confidence,

                protocol_type=features[1],
                src_bytes=features[4],
                dst_bytes=features[5],

                source_ip=source_ip,
                destination_ip=destination_ip,

                count=features[22],
                serror_rate=features[24]
            )


            db.session.add(detection)
            db.session.commit()


            return render_template(
                "analyse.html",
                result=result,
                confidence=confidence,
                alert=alert,
                attack_name=attack_name,
                attack_category=attack_category
            )


        except Exception as e:
            print("ERROR:", str(e))
            flash(f'Error: {str(e)}', 'danger')
            return render_template('analyse.html')


    return render_template('analyse.html')

@app.route('/history')
@login_required
def history():
    if current_user.role == 'admin':
        detections = Detection.query.order_by(
            Detection.timestamp.desc()
        ).all()
    else:
        detections = Detection.query.filter_by(
            user_id=current_user.id
        ).order_by(
            Detection.timestamp.desc()
        ).all()

    return render_template('history.html', detections=detections)


with app.app_context():
    db.create_all()

    admin = User.query.filter_by(role='admin').first()

    if not admin:
        hashed_pw = bcrypt.generate_password_hash('admin123').decode('utf-8')

        admin = User(
            username='admin',
            email='admin@nids.com',
            password=hashed_pw,
            role='admin'
        )

        db.session.add(admin)
        db.session.commit()

        print("Default admin created!")


@app.route('/test-email')
def test_email():
    try:
        msg = Message(
            subject='NIDS Test Email',
            recipients=['alexaobioha@gmail.com']
        )

        msg.body = """
Congratulations!

Your Machine Learning Network Intrusion Detection System
has successfully sent its first email.

This is a test email.
"""

        mail.send(msg)

        return "Email sent successfully!"

    except Exception as e:
        return f"Error: {str(e)}"


if __name__ == '__main__':
    app.run(debug=True)