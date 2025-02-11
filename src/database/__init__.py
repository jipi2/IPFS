# from flask import Flask
# from flask_sqlalchemy import SQLAlchemy
# from database.models import User

# db = SQLAlchemy()

# def init_db(app):
#     db.init_app(app)
#     with app.app_context():
#         from database import models
#         db.create_all()
#         print("Tables Created")