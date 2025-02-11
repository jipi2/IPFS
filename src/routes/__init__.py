from flask import Blueprint

# Create a Blueprint for all routes
api_bp = Blueprint("api_bp", __name__)

# Import route files and register them
from routes.user_routes import user_bp

api_bp.register_blueprint(user_bp)