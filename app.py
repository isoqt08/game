from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, EqualTo

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///game_kingdom.db'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# 資料表定義
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)

class Game(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255), nullable=True)

    def __repr__(self):
        return f"<Game {self.name}>"

# 初始化資料庫
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# 表單定義
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6, max=20)])
    confirm_password = PasswordField('Confirm Password', validators=[EqualTo('password')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Login')

# 路由定義
@app.route('/')
def index():
    if current_user.is_authenticated:  # 檢查是否已登入
        return render_template('index.html')  # 顯示首頁
    return redirect(url_for('login'))  # 未登入則跳轉到登入頁面

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash('該帳號已經存在，請選擇其他帳號', 'danger')
        else:
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            new_user = User(username=form.username.data, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('註冊成功，請登入', 'success')
            return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('登入成功！', 'success')
            return redirect(url_for('index'))  # 登入後跳轉到首頁
        flash('登入失敗，請檢查您的帳號和密碼', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('您已登出', 'info')
    return redirect(url_for('login'))  # 登出後跳轉回登入頁面

# 遊戲頁面路由
@app.route('/game/snake')
def snake_game():
    return render_template('game_snake.html')

@app.route('/game/ooxx')
def ooxx_game():
    return render_template('game_ooxx.html')

@app.route('/game/1a2b')
def one_two_b_game():
    return render_template('game_1a2b.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # 創建資料庫
    app.run(debug=True)
