import os
import logging
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_login import LoginManager
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix

# Configure logging
logging.basicConfig(level=logging.DEBUG)

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)
jwt = JWTManager()
login_manager = LoginManager()

def create_app():
    """Application factory pattern"""
    app = Flask(__name__)
    
    # Configuration
    app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key-change-in-production")
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///qss4.db")
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_recycle": 300,
        "pool_pre_ping": True,
    }
    app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY", "jwt-secret-change-in-production")
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = 3600  # 1 hour
    app.config["JWT_REFRESH_TOKEN_EXPIRES"] = 2592000  # 30 days
    
    # Proxy fix for production deployment
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
    
    # Initialize extensions
    db.init_app(app)
    jwt.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    
    # Import models to ensure tables are created
    with app.app_context():
        import models
        db.create_all()
    
    # Configure Flask-Login user loader
    @login_manager.user_loader
    def load_user(user_id):
        from models import User
        return User.query.get(user_id)
    
    # Register blueprints
    from api.v1.auth import auth_bp
    from api.v1.files import files_bp
    from api.v1.users import users_bp
    from api.v1.health import health_bp
    
    app.register_blueprint(auth_bp, url_prefix='/api/v1/auth')
    app.register_blueprint(files_bp, url_prefix='/api/v1/files')
    app.register_blueprint(users_bp, url_prefix='/api/v1/users')
    app.register_blueprint(health_bp, url_prefix='/api/v1/health')
    
    # Web interface routes
    from flask import render_template, redirect, url_for
    from flask_login import login_required, current_user
    
    @app.route('/')
    def index():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        return render_template('index.html')
    
    @app.route('/dashboard')
    @login_required
    def dashboard():
        return render_template('files.html')
    
    @app.route('/upload')
    @login_required
    def upload():
        return render_template('upload.html')
    
    return app

# Create app instance
app = create_app()
