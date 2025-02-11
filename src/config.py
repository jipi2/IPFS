import os

DB_USER = "root"
DB_PASSWORD = "root"
DB_HOST = "localhost"  # If using Docker, replace with "mysql"
DB_PORT = "3311"  # Specify the port here
DB_NAME = "mydb"

class Config:
    SQLALCHEMY_DATABASE_URI = f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False