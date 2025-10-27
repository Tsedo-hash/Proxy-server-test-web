from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# SQLite мэдээллийн санг тохируулах
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Flask-Login тохиргоо
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "signin"  # Нэвтрэх шаардлагатай бол энэ хуудсанд шилжүүлнэ

# Хэрэглэгчийн мэдээллийн сангийн загвар
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

# Мэдээллийн санг үүсгэх
with app.app_context():
    db.create_all()

# Бүртгэл
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password)

        if User.query.filter_by(email=email).first():
            flash("Энэ имэйл аль хэдийн бүртгэгдсэн байна.")
            return redirect(url_for('signup'))
        else:
            new_user = User(username=username, email=email, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash("Амжилттай бүртгэгдлээ!")
            return redirect(url_for('signin'))

    return render_template('signup.html')

# Нэвтрэх
@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)  # Нэвтрэх
            flash("Амжилттай нэвтэрлээ!")
            return redirect(url_for('index'))
        else:
            flash("Имэйл эсвэл нууц үг буруу байна.")
            return redirect(url_for('signin'))

    return render_template('signin.html')

# Нүүр хуудас
@app.route('/')
@login_required  # Хэрэглэгч нэвтэрсэн тохиолдолд л нэвтрэх
def index():
    return render_template('index.html')

# Нэвтрэх хэсэг
@app.route('/logout')
@login_required
def logout():
    logout_user()  # Хэрэглэгчийн сессийг хаах
    flash("Та амжилттай гарав.")
    return redirect(url_for('signin'))

# Flask-Login тохиргоо - хэрэглэгчийг сэргээх
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

if __name__ == '__main__':
    app.run(debug=True)
