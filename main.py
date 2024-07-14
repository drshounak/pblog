import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from werkzeug.utils import secure_filename
from datetime import datetime
import markdown
import bleach
from bs4 import BeautifulSoup
import json
from slugify import slugify

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://username:password@localhost/blogdb'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your-email@gmail.com'
app.config['MAIL_PASSWORD'] = 'your-email-password'
app.config['UPLOAD_FOLDER'] = 'static/uploads'

db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    posts = db.relationship('Post', backref='author', lazy=True)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    slug = db.Column(db.String(200), unique=True, nullable=False)
    content = db.Column(db.Text, nullable=False)
    meta_title = db.Column(db.String(200))
    meta_description = db.Column(db.String(300))
    feature_image = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comments = db.relationship('Comment', backref='post', lazy=True)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Newsletter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    confirmed = db.Column(db.Boolean, default=False)
    token = db.Column(db.String(100), unique=True, nullable=True)

class NewsletterIssue(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    sent_at = db.Column(db.DateTime, nullable=True)

class Page(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    slug = db.Column(db.String(200), unique=True, nullable=False)
    content = db.Column(db.Text, nullable=False)
    meta_title = db.Column(db.String(200))
    meta_description = db.Column(db.String(300))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Helper functions
def send_email(to, subject, template):
    msg = Message(
        subject,
        recipients=[to],
        html=template,
        sender=app.config['MAIL_USERNAME']
    )
    mail.send(msg)

def generate_otp():
    return ''.join([str(random.randint(0, 9)) for _ in range(6)])

def save_image(file):
    if file:
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return filename
    return None

# Routes
@app.route('/')
def index():
    posts = Post.query.order_by(Post.created_at.desc()).limit(10).all()
    return render_template('index.html', posts=posts)

@app.route('/post/<string:slug>')
def post(slug):
    post = Post.query.filter_by(slug=slug).first_or_404()
    return render_template('post.html', post=post)

@app.route('/page/<string:slug>')
def page(slug):
    page = Page.query.filter_by(slug=slug).first_or_404()
    return render_template('page.html', page=page)

@app.route('/author/<int:user_id>')
def author(user_id):
    author = User.query.get_or_404(user_id)
    posts = Post.query.filter_by(user_id=user_id).order_by(Post.created_at.desc()).all()
    return render_template('author.html', author=author, posts=posts)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form['email']).first()
        if user and bcrypt.check_password_hash(user.password, request.form['password']):
            otp = generate_otp()
            send_email(user.email, 'Login OTP', f'Your OTP is: {otp}')
            session['login_otp'] = otp
            session['user_id'] = user.id
            return redirect(url_for('verify_otp'))
        flash('Invalid email or password')
    return render_template('login.html')

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if 'login_otp' not in session or 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        if request.form['otp'] == session['login_otp']:
            user = User.query.get(session['user_id'])
            login_user(user)
            session.pop('login_otp')
            session.pop('user_id')
            return redirect(url_for('admin'))
        flash('Invalid OTP')
    return render_template('verify_otp.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        abort(403)
    posts = Post.query.order_by(Post.created_at.desc()).all()
    return render_template('admin/index.html', posts=posts)

@app.route('/admin/post/new', methods=['GET', 'POST'])
@login_required
def new_post():
    if not current_user.is_admin:
        abort(403)
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        meta_title = request.form['meta_title']
        meta_description = request.form['meta_description']
        feature_image = save_image(request.files.get('feature_image'))
        slug = slugify(title)
        
        post = Post(title=title, content=content, meta_title=meta_title,
                    meta_description=meta_description, feature_image=feature_image,
                    slug=slug, user_id=current_user.id)
        db.session.add(post)
        db.session.commit()
        flash('Post created successfully')
        return redirect(url_for('admin'))
    return render_template('admin/new_post.html')

@app.route('/admin/post/<int:post_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    if not current_user.is_admin:
        abort(403)
    post = Post.query.get_or_404(post_id)
    if request.method == 'POST':
        post.title = request.form['title']
        post.content = request.form['content']
        post.meta_title = request.form['meta_title']
        post.meta_description = request.form['meta_description']
        feature_image = save_image(request.files.get('feature_image'))
        if feature_image:
            post.feature_image = feature_image
        post.slug = slugify(post.title)
        db.session.commit()
        flash('Post updated successfully')
        return redirect(url_for('admin'))
    return render_template('admin/edit_post.html', post=post)

@app.route('/admin/post/<int:post_id>/delete', methods=['POST'])
@login_required
def delete_post(post_id):
    if not current_user.is_admin:
        abort(403)
    post = Post.query.get_or_404(post_id)
    db.session.delete(post)
    db.session.commit()
    flash('Post deleted successfully')
    return redirect(url_for('admin'))

@app.route('/newsletter/signup', methods=['POST'])
def newsletter_signup():
    email = request.form['email']
    subscriber = Newsletter.query.filter_by(email=email).first()
    if subscriber is None:
        token = serializer.dumps(email, salt='email-confirm-salt')
        subscriber = Newsletter(email=email, token=token)
        db.session.add(subscriber)
        db.session.commit()
        confirm_url = url_for('confirm_email', token=token, _external=True)
        html = render_template('email/confirm_email.html', confirm_url=confirm_url)
        subject = "Please confirm your email"
        send_email(email, subject, html)
        flash('A confirmation email has been sent. Please check your inbox.')
    elif not subscriber.confirmed:
        flash('Please confirm your subscription. Check your email for the confirmation link.')
    else:
        flash('You are already subscribed to our newsletter.')
    return redirect(url_for('index'))

@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = serializer.loads(token, salt='email-confirm-salt', max_age=3600)
    except:
        flash('The confirmation link is invalid or has expired.')
        return redirect(url_for('index'))
    subscriber = Newsletter.query.filter_by(email=email).first_or_404()
    if subscriber.confirmed:
        flash('Account already confirmed.')
    else:
        subscriber.confirmed = True
        subscriber.token = None
        db.session.commit()
        flash('You have confirmed your account. Thanks!')
    return redirect(url_for('index'))

@app.route('/admin/newsletter/new', methods=['GET', 'POST'])
@login_required
def new_newsletter():
    if not current_user.is_admin:
        abort(403)
    if request.method == 'POST':
        subject = request.form['subject']
        content = request.form['content']
        newsletter = NewsletterIssue(subject=subject, content=content)
        db.session.add(newsletter)
        db.session.commit()
        flash('Newsletter created successfully')
        return redirect(url_for('admin_newsletters'))
    return render_template('admin/new_newsletter.html')

@app.route('/admin/newsletter/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit_newsletter(id):
    if not current_user.is_admin:
        abort(403)
    newsletter = NewsletterIssue.query.get_or_404(id)
    if request.method == 'POST':
        newsletter.subject = request.form['subject']
        newsletter.content = request.form['content']
        db.session.commit()
        flash('Newsletter updated successfully')
        return redirect(url_for('admin_newsletters'))
    return render_template('admin/edit_newsletter.html', newsletter=newsletter)

@app.route('/admin/newsletter/<int:id>/delete', methods=['POST'])
@login_required
def delete_newsletter(id):
    if not current_user.is_admin:
        abort(403)
    newsletter = NewsletterIssue.query.get_or_404(id)
    db.session.delete(newsletter)
    db.session.commit()
    flash('Newsletter deleted successfully')
    return redirect(url_for('admin_newsletters'))

@app.route('/admin/newsletter/<int:id>/send', methods=['POST'])
@login_required
def send_newsletter(id):
    if not current_user.is_admin:
        abort(403)
    newsletter = NewsletterIssue.query.get_or_404(id)
    subscribers = Newsletter.query.filter_by(confirmed=True).all()
    for subscriber in subscribers:
        send_email(subscriber.email, newsletter.subject, newsletter.content)
    newsletter.sent_at = datetime.utcnow()
    db.session.commit()
    flash('Newsletter sent successfully')
    return redirect(url_for('admin_newsletters'))

@app.route('/admin/newsletters')
@login_required
def admin_newsletters():
    if not current_user.is_admin:
        abort(403)
    newsletters = NewsletterIssue.query.order_by(NewsletterIssue.created_at.desc()).all()
    return render_template('admin/newsletters.html', newsletters=newsletters)

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        message = request.form['message']
        send_email(app.config['MAIL_USERNAME'], f'Contact Form: {name}', f'From: {email}\n\n{message}')
        flash('Thank you for your message. We will get back to you soon.')
        return redirect(url_for('contact'))
    return render_template('contact.html')

@app.route('/post/<int:post_id>/comment', methods=['POST'])
@login_required
def add_comment(post_id):
    post = Post.query.get_or_404(post_id)
    content = request.form['content']
    comment = Comment(content=content, post_id=post.id, user_id=current_user.id)
    db.session.add(comment)
    db.session.commit()
    flash('Your comment has been added.')
    return redirect(url_for('post', slug=post.slug))

@app.route('/sitemap.xml')
def sitemap():
    pages = []
    ten_days_ago = datetime.now() - timedelta(days=10)
    
    # Add static pages
    for rule in app.url_map.iter_rules():
        if "GET" in rule.methods and len(rule.arguments) == 0:
            pages.append([url_for(rule.endpoint, _external=True), 'weekly'])

    # Add dynamic pages
    posts = Post.query.order_by(Post.created_at.desc()).all()
    for post in posts:
        url = url_for('post', slug=post.slug, _external=True)
        modified_time = post.updated_at.isoformat()
        pages.append([url, modified_time])

    sitemap_xml = render_template('sitemap.xml', pages=pages)
    response = make_response(sitemap_xml)
    response.headers["Content-Type"] = "application/xml"
    return response

@app.route('/robots.txt')
def robots():
    return send_from_directory(app.static_folder, 'robots.txt')

# JSON-LD Schema
@app.context_processor
def inject_schema():
    def generate_schema(post=None):
        if post:
            schema = {
                "@context": "http://schema.org",
                "@type": "BlogPosting",
                "headline": post.title,
                "datePublished": post.created_at.isoformat(),
                "dateModified": post.updated_at.isoformat(),
                "author": {
                    "@type": "Person",
                    "name": post.author.username
                },
                "description": post.meta_description
            }
        else:
            schema = {
                "@context": "http://schema.org",
                "@type": "WebSite",
                "name": "Your Blog Name",
                "url": url_for('index', _external=True)
            }
        return json.dumps(schema)
    return dict(generate_schema=generate_schema)

@app.cli.command("create-admin")
def create_admin():
    username = input("Enter admin username: ")
    email = input("Enter admin email: ")
    password = input("Enter admin password: ")
    
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    admin = User(username=username, email=email, password=hashed_password, is_admin=True)
    
    db.session.add(admin)
    db.session.commit()
    print(f"Admin user {username} created successfully.")

# Run this command with: flask create-admin

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=True)
