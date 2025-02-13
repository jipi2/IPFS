from flask import Blueprint, request, jsonify, render_template, flash, redirect, url_for, Response, stream_with_context
from database.models import User, File, UserFile, Version
from database.models import db
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, set_access_cookies, JWTManager, unset_jwt_cookies
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename 
import datetime
import os
import requests

user_bp = Blueprint("user_bp", __name__)
UPLOAD_FOLDER = os.path.abspath(os.path.join(os.getcwd(), "..", "tmp"))
folderPath = "../tmp/"
ipfsServiceUrl = "http://localhost:3000/upload"
ipfsServiceUrlDelete = "http://localhost:3000/delete"


if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def deleteCIDFromIPFS(fileID:int):
    try:
        versions = Version.query.filter_by(fileID=fileID).all()
        for v in versions:
            anotherVersionFile = Version.query.filter(Version.fileID!=v.fileID, Version.fileCID==v.fileCID ).first()
            if anotherVersionFile is None:
                payload = { "cid": v.fileCID }
                response = requests.post(ipfsServiceUrlDelete, json=payload)
                if response.status_code == 200:
                else:
                    raise Exception("Error:", response.json().get("error"))
    except Exception as e:
        print(f"An error occurred: {e}")
        return None
    

def deleteFile(email:str, filename:str):
    try:
        ownerUser = User.query.filter_by(mail=email).first()
        if ownerUser is None:
            raise Exception("Owner not found")
        file = File.query.filter_by(filename=filename, ownerID=ownerUser.userID).first()
        if file is None:
            raise Exception("File not found")
        
        deleteCIDFromIPFS(file.fileID)
        
        Version.query.filter_by(fileID=file.fileID).delete()
        UserFile.query.filter_by(fileID=file.fileID).delete()
        File.query.filter_by(fileID=file.fileID).delete()
        
        db.session.commit()

        return True   
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def saveNewIPFSDataInDB(user:User, cid:str, filename:str):
    try:
        newFile = File(ownerID=user.userID, filename=filename, latestVersion=1)
        db.session.add(newFile)
        db.session.commit()
        newVersion = Version(fileID=newFile.fileID, versionNumber=1, fileCID=cid)
        db.session.add(newVersion)
        db.session.commit()
        newUserFile = UserFile(userID=user.userID, fileID=newFile.fileID, accessMode=2)
        db.session.add(newUserFile)
        db.session.commit()
            
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def updateVersion(ownerEmail:str, delegateEmail:str ,filename:str, cid:str):
    try:
        ownerUser = User.query.filter_by(mail=ownerEmail).first()
        if ownerUser is None:
            raise Exception("Owner not found")
        
        delegateUser = User.query.filter_by(mail=delegateEmail).first()
        if delegateUser is None:
            raise Exception("Delegate not found")    
        
        
        file = File.query.filter_by(filename=filename, ownerID=ownerUser.userID).first()
        if file is None:
            raise Exception("File not found")
        
        if ownerUser.userID != delegateUser.userID:
            userFile = UserFile.query.filter_by(userID=delegateUser.userID, fileID=file.fileID).first()
            if userFile.accessMode != 1: 
                raise Exception("Delegate does not have access to file")
        
        ltVersion = file.latestVersion+1
        newVersion = Version(fileID=file.fileID, versionNumber=ltVersion, fileCID=cid)
        file.latestVersion = ltVersion
        db.session.add(newVersion)
        db.session.commit()
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def uploadFileToIPFS(email:str, ownerEmail:str ,filename:str, newFile:bool):
    try:
        user = User.query.filter_by(mail=email).first()
        if user is None:
            raise Exception("User not found")
        payload = { "fileName": filename }
        response = requests.post(ipfsServiceUrl, json=payload)
        
        if response.status_code == 200:
            cid_obj = response.json().get("cid")
            cid_str = cid_obj.get('/') if isinstance(cid_obj, dict) else cid_obj
            
            if newFile is True:
                saveNewIPFSDataInDB(user, cid_str, filename)
            else:
                updateVersion(ownerEmail, email ,filename, cid_str)
                
            os.remove(folderPath+filename)
            
    except Exception as e:
        print(f"An error occurred: {e}")
        return None


def shareAccess(ownerEmail:str, delegateEmail:str, filename:str, accessMode:int):
    try:
        ownerUser = User.query.filter_by(mail=ownerEmail).first()
        if ownerUser is None:
            raise Exception("Owner not found")
        delegateUser = User.query.filter_by(mail=delegateEmail).first()
        if delegateUser is None:
            raise Exception("Delegate not found")
        
        file = File.query.filter_by(filename=filename, ownerID=ownerUser.userID).first()
        if file is None:
            raise Exception("File not found")
        
        userFile = UserFile.query.filter_by(userID=delegateUser.userID, fileID=file.fileID).first()
        
        if userFile is None and accessMode!=-1:
            newUserFile = UserFile(userID=delegateUser.userID, fileID=file.fileID, accessMode=accessMode)
            db.session.add(newUserFile)
        else:
            if accessMode==-1:
                db.session.delete(userFile)
            else:
                userFile.accessMode = accessMode
        db.session.commit()
        
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def downloadFile(email:str, ownerEmail:str, filename:str, versionNumber:int):
    try:
        
        user = User.query.filter_by(mail=email).first()
        if user is None:
            raise Exception("User not found")
        
        ownerUser = User.query.filter_by(mail=ownerEmail).first()
        if ownerUser is None:
            raise Exception("Owner not found")
        
        file = File.query.filter_by(filename=filename, ownerID=ownerUser.userID).first()
        if file is None:
            raise Exception("File not found")
        
        userFile = UserFile.query.filter_by(userID=user.userID, fileID=file.fileID).first()
        if userFile is None:
            raise Exception("User does not have access to file")
        elif userFile.accessMode < 0:
            raise Exception("User does not have access to file")
        
        version = Version.query.filter_by(fileID=file.fileID, versionNumber=versionNumber).first()
        if version is None:
            raise Exception("Version not found")
        
        downloadLink = f"https://{version.fileCID}.ipfs.w3s.link"
        print(downloadLink)
        r = requests.get(downloadLink, stream=True)
        if r.status_code != 200:
            raise Exception("Failed to download file from IPFS")
        
        return Response(
            stream_with_context(r.iter_content(chunk_size=1024)),
            content_type=r.headers.get("Content-Type"),
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
        
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

@user_bp.route("/logout")
@jwt_required()
def logout():
    resp = redirect(url_for('api_bp.user_bp.login'))
    unset_jwt_cookies(resp)
    return resp

@user_bp.route("/", methods=["GET","POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        passWord = request.form["password"]

        user = User.query.filter_by(mail=email).first()
        if user is not None:
            if check_password_hash(user.password, passWord):
                accessToken = create_access_token(identity={'email': email}, expires_delta=datetime.timedelta(minutes=120))
                resp = redirect(url_for('api_bp.user_bp.home'))
                set_access_cookies(resp, accessToken)
                return resp

        flash("Bad username or password", 'danger')
        return redirect(url_for('api_bp.user_bp.login'))
    
    return render_template("login.html")  

@user_bp.route("/register", methods=["POST", "GET"])
def register():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        if password != confirm_password:
            flash("Passwords do not match!", 'danger')
            return redirect(url_for('api_bp.user_bp.register')) 

        user = User.query.filter_by(mail=email).first()
        if user:
            flash("Email already registered!", 'danger')
            return redirect(url_for('api_bp.user_bp.register'))

        hashed_password = generate_password_hash(password)

        new_user = User(mail=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful!", 'success')
        return redirect(url_for('api_bp.user_bp.login')) 

    return render_template("register.html")

@user_bp.route("/home")
@jwt_required()
def home():
    user_identity = get_jwt_identity()  
    user_email = user_identity.get("email")

    user = User.query.filter_by(mail=user_email).first()
    if not user:
        return {"error": "User not found"}, 404

    user_id = user.userID

    files = (
        db.session.query(
            File.fileID,
            File.filename,
            User.mail.label("ownerEmail"),
            UserFile.accessMode
        )
        .join(User, File.ownerID == User.userID) 
        .outerjoin(UserFile, (File.fileID == UserFile.fileID) & (UserFile.userID == user_id)) 
        .filter((File.ownerID == user_id) | (UserFile.userID == user_id))  
        .all()
    )


    files_list = [
        {
            "Name": file.filename,
            "User": file.ownerEmail,
            "Permissions": file.accessMode 
        }
        for file in files
    ]
    return render_template("home.html", files=files_list)


@user_bp.route("/upload", methods=["POST"])
@jwt_required()
def upload_file():
    if "file" not in request.files:
        return jsonify({"message": "No file uploaded"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"message": "No selected file"}), 400

    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)

    filename = secure_filename(file.filename)
    file_path = os.path.join(UPLOAD_FOLDER, filename)

    try:
        file.save(file_path)
        current_user = get_jwt_identity()
        user_email = current_user.get("email")
        print(user_email, file_path, filename)
        uploadFileToIPFS(user_email, user_email, filename, True)
        
        return jsonify({"message": f"File '{filename}' uploaded successfully"}), 200
    except Exception as e:
        return jsonify({"error": f"Failed to save file: {str(e)}"}), 500


@user_bp.route("/get-users", methods=["GET"])
@jwt_required()
def get_users():
    users = User.query.all()
    users_list = [{"mail": user.mail} for user in users]
    return jsonify(users_list), 200


@user_bp.route("/modify-access", methods=["POST"])
@jwt_required()
def modify_access():
    try:
        current_user = get_jwt_identity()
        owner_email = current_user.get("email") 

        data = request.get_json()
        delegate_email = data.get("delegateEmail")
        filename = data.get("filename")
        access_mode = int(data.get("accessMode"))  

        if not delegate_email or not filename:
            return jsonify({"error": "Missing required parameters"}), 400

        access_mapping = {
            0: 0,   
            1: 1,   
            -1: -1  
        }

        if access_mode not in access_mapping:
            return jsonify({"error": "Invalid access mode"}), 400

        shareAccess(owner_email, delegate_email, filename, access_mapping[access_mode])

        return jsonify({"message": f"Access for {delegate_email} on {filename} updated successfully!"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@user_bp.route('/edit-file', methods=['GET', 'POST'])
@jwt_required()
def edit_file():
    current_user = get_jwt_identity() 
    user_email = current_user.get("email")  

    if request.method == 'GET':
        ownerEmail = request.args.get("ownerEmail")
        filename = request.args.get("filename")

        owner=User.query.filter_by(mail=ownerEmail).first()
        file=File.query.filter_by(filename=filename, ownerID=owner.userID).first()
        versionNumber=file.latestVersion

        response = downloadFile(user_email, ownerEmail, filename, versionNumber)
        if isinstance(response, tuple): 
            flash("Error retrieving file", "danger")
            return redirect(url_for('api_bp.user_bp.home'))

        file_content = response.get_data(as_text=True)

        return render_template("edit_file.html",
                               email=user_email,
                               ownerEmail=ownerEmail,
                               filename=filename,
                               versionNumber=versionNumber,
                               content=file_content)
    else:
        updated_content = request.form['content']
        ownerEmail = request.form['ownerEmail']
        filename = request.form['filename']
        versionNumber = int(request.form['versionNumber'])

        temp_file_path = f"../tmp/{filename}"
        with open(temp_file_path, "w", encoding="utf-8") as f:
            f.write(updated_content)

        new_cid = uploadFileToIPFS(user_email, ownerEmail, filename, False)

        if new_cid is None:
            flash("File update failed", "danger")
        else:
            flash("File updated successfully", "success")

        return redirect(url_for('api_bp.user_bp.home'))

@user_bp.route("/view/<filename>", methods=["GET"])
@jwt_required()
def view_file(filename):
    user_identity = get_jwt_identity()
    user_email = user_identity.get("email")

    file = File.query.filter_by(filename=filename).first()
    if not file:
        flash("File not found!", "danger")
        return redirect(url_for("api_bp.user_bp.home"))

    latest_version = file.latestVersion

    versions = Version.query.filter_by(fileID=file.fileID).all()

    latest_version_data = Version.query.filter_by(fileID=file.fileID, versionNumber=latest_version).first()
    file_cid = latest_version_data.fileCID if latest_version_data else None

    if not file_cid:
        flash("No versions found!", "danger")
        return redirect(url_for("api_bp.user_bp.home"))

    file_owner = User.query.filter_by(userID=file.ownerID).first()
    owner_email = file_owner.mail if file_owner else None  

    return render_template(
        "view_file.html",
        filename=filename,
        versions=versions,
        latest_version=latest_version,
        file_cid=file_cid,
        file_owner=owner_email,  
        file_url=f"https://{file_cid}.ipfs.w3s.link",
    )


@user_bp.route("/get-version-cid/<filename>/<int:version>", methods=["GET"])
@jwt_required()
def get_version_cid(filename, version):
    file = File.query.filter_by(filename=filename).first()
    
    if not file:
        return jsonify({"error": "File not found"}), 404

    version_data = Version.query.filter_by(fileID=file.fileID, versionNumber=version).first()
    
    if not version_data:
        return jsonify({"error": "Version not found"}), 404

    return jsonify({"cid": version_data.fileCID}), 200

@user_bp.route("/download/<fileOwner>/<filename>/<version>", methods=["GET"])
@jwt_required()
def download(fileOwner, filename, version):
    current_user = get_jwt_identity() 
    user_email = current_user.get("email")  

    print(f"Downloading {filename}, Version: {version}, Owner: {fileOwner}, Requested by: {user_email}")

    return downloadFile(user_email, fileOwner, filename, version)


@user_bp.route("/delete-file/<filename>", methods=["POST"])
@jwt_required()
def delete_file(filename):
    current_user = get_jwt_identity()  
    email = current_user.get("email")  

    if not filename:
        return jsonify({"error": "Missing filename"}), 400

    try:
        result = deleteFile(email, filename)  

        if result is None:
            return jsonify({"error": "File deletion failed"}), 500

        return jsonify({"success": True, "message": "File deleted successfully!"}), 200  
    except Exception as e:
        print(f"Error deleting file: {str(e)}")
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500



