from flask import Flask, render_template, request, redirect, url_for
from flask_login import (LoginManager, UserMixin,
                         current_user, login_required, login_user, logout_user)
from flask_sqlalchemy import SQLAlchemy
from commands import create_tables
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


db = SQLAlchemy(app)

app.config['SECRET_KEY'] = 'secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///qa.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.cli.add_command(create_tables)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    password_hash = db.Column(db.String(100))
    expert = db.Column(db.Boolean)
    admin = db.Column(db.Boolean)
    questions_asked = db.relationship(
        'Question', foreign_keys='Question.asked_by_id',
        backref='asker', lazy=True)
    answers_requested = db.relationship(
        'Question', foreign_keys='Question.expert_id',
        backref='expert', lazy=True)

    @property
    def password(self):
        raise AttributeError('Password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.Text)
    answer = db.Column(db.Text)
    asked_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    expert_id = db.Column(db.Integer, db.ForeignKey('user.id'))


@app.route('/')
def index():
    questions = Question.query.filter(Question.answer is not None).all()
    context = {
        'questions': questions
    }
    return render_template('home.html', **context)


@login_required
@app.route('/ask', methods=['GET', 'POST'])
def ask():
    if request.method == 'POST':
        question = request.form['question']
        expert = request.form['expert']

        question = Question(question=question,
                            expert_id=expert, asked_by_id=current_user)

        db.session.add(question)
        db.session.commit()

        return redirect(url_for('index'))

    experts = User.query.filter_by(expert=True).all()

    return render_template('ask.html', experts=experts)


@app.route('/answer/<int:question_id>', methods=['GET', 'POST'])
@login_required
def answer(question_id):
    if not current_user.expert:
        return redirect(url_for('index'))

    question = Question.query.get_or_404(question_id)

    if request.method == 'POST':
        question.answer = request.form['answer']
        db.session.commit()

        return redirect(url_for('unanswered'))

    context = {
        'question': question
    }

    return render_template('answer.html', **context)


@app.route('/question/<int:question_id>')
def question(question_id):
    question = Question.query.get_or_404(question_id)

    context = {
        'question': question
    }

    return render_template('question.html', **context)


@app.route('/unanswered')
@login_required
def unanswered():
    if not current_user.expert:
        return redirect(url_for('index'))

    unanswered_questions = Question.query\
        .filter_by(expert_id=current_user.id)\
        .filter(Question.answer is None)\
        .all()

    context = {
        'unanswered_questions': unanswered_questions
    }

    return render_template('unanswered.html', **context)


@app.route('/users')
@login_required
def users():
    if not current_user.admin:
        return redirect(url_for('index'))

    users = User.query.filter_by(admin=False).all()

    context = {
        'users': users
    }

    return render_template('users.html', **context)


@app.route('/promote/<int:user_id>')
@login_required
def promote(user_id):
    if not current_user.admin:
        return redirect(url_for('index'))

    user = User.query.get_or_404(user_id)

    user.expert = True
    db.session.commit()

    return redirect(url_for('users'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        password_hash = request.form['password']

        user = User(
            name=name,
            password=password_hash,
            admin=False,
            expert=False
        )

        db.session.add(user)
        db.session.commit()

        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        name = request.form['name']
        password = request.form['password']

        user = User.query.filter_by(name=name).first()

        error_message = ''

        if not user or not check_password_hash(user.password, password):
            error_message = 'Could not login. Please check and try again.'

        if not error_message:
            login_user(user)
            return redirect(url_for('index'))

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))
