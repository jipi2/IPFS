import os

DB_USER = "root"
DB_PASSWORD = "root"
DB_HOST = "localhost"  # If using Docker, replace with "mysql"
DB_PORT = "3311"  # Specify the port here
DB_NAME = "mydb"

class Config:
    SQLALCHEMY_DATABASE_URI = f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = "SUPER_SECRET_KEY"
    JWT_SECRET_KEY="SUPER_SECRET_JWT_KEY"
    JWT_TOKEN_LOCATION="cookies"
    JWT_COOKIE_CSRF_PROTECT=False