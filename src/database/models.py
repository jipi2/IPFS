from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = "users"
    userID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    mail = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False) # hashed password

    def __repr__(self):
        return f"<User {self.username}>"
    
class File(db.Model):
    __tablename__="files"
    fileID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    filename = db.Column(db.String(100), nullable=False)
    latestVersion = db.Column(db.Integer, nullable=False)
    
    def __repr__(self):
        return f"<File {self.filename}>"

class UserFile(db.Model):
    __tablename__="userfile"
    userID = db.Column(db.Integer, db.ForeignKey("users.userID"), primary_key=True)
    fileID = db.Column(db.Integer, db.ForeignKey("files.fileID"), primary_key=True)
    accessMode = db.Column(db.Integer, nullable=False)

    def __repr__(self):
        return f"<UserFile User:{self.userID} File:{self.fileID} AccessMode:{self.accessMode}>"

class Version(db.Model):
    __tablename__ = "versions"
    fileID = db.Column(db.Integer, db.ForeignKey("files.fileID"), primary_key=True)  # Foreign key to Files
    versionNumber = db.Column(db.Integer, primary_key=True)  # Version number acts as part of primary key
    fileCID = db.Column(db.String(255), nullable=False)  # IPFS CID

    def __repr__(self):
        return f"<Version File:{self.fileID} Version:{self.versionNumber}>"

def init_db(app):
    db.init_app(app)
    with app.app_context():
        db.create_all()
        print("Tables Created")