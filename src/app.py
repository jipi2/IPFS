#imports
from flask import Flask, render_template
from config import Config
from database.models import init_db
from routes import api_bp  # Import the Blueprint from routes/__init__.py
from flask_jwt_extended import JWTManager, jwt_required

app = Flask(__name__)

app.config.from_object(Config)

init_db(app)

app.register_blueprint(api_bp)

jwt  = JWTManager(app)


if __name__=="__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)