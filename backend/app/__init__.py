from flask import Flask

from app.config import Config
from app.extensions import db, migrate, jwt, bcrypt


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)
    bcrypt.init_app(app)

    # Import models so Flask-Migrate can see them
    from app.models import user, key, message, group, file  # noqa: F401

    # Register blueprints
    from app.auth.routes import auth_bp
    from app.crypto.key_routes import crypto_bp
    from app.messaging.routes import messaging_bp
    from app.groups.routes import groups_bp
    from app.files.routes import files_bp

    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(crypto_bp, url_prefix="/api/keys")
    app.register_blueprint(messaging_bp, url_prefix="/api/messages")
    app.register_blueprint(groups_bp, url_prefix="/api/groups")
    app.register_blueprint(files_bp, url_prefix="/api/files")

    from flask import render_template

    @app.route("/")
    def index():
        return render_template("base.html")

    return app