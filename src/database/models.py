from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = "users"
    userID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    mail = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False) # hashed password

    def __repr__(self):
        return f"<User {self.username}>"
    
def init_db(app):
    db.init_app(app)
    with app.app_context():
        db.create_all()
        print("Tables Created")