from flask import Flask, request, jsonify, send_file
from google.cloud import datastore, storage

import requests
import json
import io

from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'

client = datastore.Client()

USERS = 'users'
LOGIN = 'login'
ID = 'id'
ROLE = 'role'
SUB = 'sub'
AVATAR = 'avatar'
AVATARS = 'avatars'
COURSES = 'courses'
SUBJECT = 'subject'
NUMBER = 'number'
TITLE = 'title'
TERM = 'term'
INSTRUCTOR_ID = 'instructor_id'
STUDENTS = 'students'
FILE_NAME = 'file_name'
SELF = 'self'
ADMIN = 'admin'
USERNAME = 'username'
PASSWORD = 'password'
ENROLLMENTS = 'enrollments'
COURSE_ID = 'course_id'
STUDENT_ID = 'student_id'
ADD = 'add'
REMOVE = 'remove'
ERROR_NOT_FOUND = {"Error" : "No business with this business_id exists"}, 404

# Update the values of the following 3 variables
CLIENT_ID = 'i3WKuxXtIFMitz5ZuN84dUDoxNrvmzZ7'
CLIENT_SECRET = 'Cy7OAr0d5_adMWU-34Q_UV126PhMFS3EN0nAHyU7ewTEIapD1fs-m8QbGzoePvAa'
DOMAIN = 'dev-5gqj05vrcxzy8dcc.us.auth0.com'
# For example
# DOMAIN = '493-24-spring.us.auth0.com'
# Note: don't include the protocol in the value of the variable DOMAIN

PHOTO_BUCKET = 'hw6-ng-avatars'
ALGORITHMS = ["RS256"]

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
)

# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                            "description":
                                "Authorization header is missing"}, 401)
    
    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://"+ DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)


@app.route('/')
def index():
    return "Please navigate to /users/login to use this API"
    
# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload          
        

#1. Generate JWT from Auth0 dinaub abd return it, using HW5 set up
@app.route('/' + USERS + '/' + LOGIN, methods=['POST'])
def login_user():
    content = request.get_json()
    #check if attributes are provided 
    attributes = [USERNAME, PASSWORD]
    for attribute in attributes:
        if attribute not in content:
            return {"Error": "The request body is invalid"}, 400
    
    username = content["username"]
    password = content["password"]
    body = {'grant_type':'password','username':username,
            'password':password,
            'client_id':CLIENT_ID,
            'client_secret':CLIENT_SECRET
           }
    headers = { 'content-type': 'application/json' }
    url = 'https://' + DOMAIN + '/oauth/token'
    r = requests.post(url, json=body, headers=headers)

    #get id_token
    try:
        token = r.json()["id_token"]
        return {'token':token}, 200, {'Content-Type':'application/json'}
    except:
        return {'Error':'Unauthorized'}, 401
    

#2. Get all Users
@app.route('/' + USERS, methods=['GET'])
def get_users():
    try:
        payload = verify_jwt(request)
    except AuthError:
        return {'Error': 'Unauthorized'}, 401
    query = client.query(kind=USERS)
    query.add_filter(SUB, "=", payload[SUB])
    result = list(query.fetch())
    if result[0][ROLE] != ADMIN:
        return {'Error':"You don't have permission on this resource"}, 403
    else:
        query1 = client.query(kind=USERS)
        results = list(query1.fetch())
        users = []
        for r in results:
            new = {
                ID : r.key.id,
                ROLE : r[ROLE],
                SUB : r[SUB]
            }
            users.append(new)
        
        return users

#3 Get a user 
@app.route('/' + USERS + '/<int:id>', methods=['GET'])
def get_user(id):
    
    #Get user
    user_key = client.key(USERS, id)
    user = client.get(key=user_key)
    if user is None:
        return {"Error": "The JWT is valid, but the user doesn’t exist."}, 403
    
    try:
        payload = verify_jwt(request)
    except AuthError:
        return {'Error': 'Unauthorized'}, 401

    #requester
    query = client.query(kind=USERS)
    query.add_filter(SUB, "=", payload[SUB])
    result = list(query.fetch())

    print(result[0][ROLE])
    #Verify authorization 
    if (result[0][ROLE] != ADMIN) and (payload[SUB] != user[SUB]):
        return {"Error": "You don't have permission on this resource"}, 403
    
    #Prep object
    user_json = {
        ID: user.key.id,
        ROLE: user[ROLE],
        SUB: user[SUB]
    }
    print('here2')
    
    #if instructor
    if user[ROLE] == 'instructor':
        course_list = list()
        query = client.query(kind=COURSES)
        print(user_json[ID])
        query.add_filter(INSTRUCTOR_ID, '=', user_json[ID])
        results = list(query.fetch())
        for r in results:
            course_list.append(request.host_url + COURSES + '/' + str(r.key.id)) 
        user_json[COURSES] = course_list

    elif user[ROLE] == 'student':
        course_list = list()
        query = client.query(kind=ENROLLMENTS)
        query.add_filter(STUDENT_ID, '=', user_json[ID])
        results = list(query.fetch())
        for r in results:
            course_list.append(request.host_url + COURSES + '/' + str(r.key.id))
        user_json[COURSES] = course_list

    #check for avatar
    avatar_key = client.key(AVATARS, id)
    avatar = client.get(key=avatar_key)
    if avatar is not None: 
        user_json['avatar_url'] = request.url + '/' + AVATAR
    
    return user_json


#4 Create/Update avatar
@app.route('/' + USERS + '/<int:id>/' + AVATAR, methods=['POST'])
def post_avatar(id):
    #check if file exists 
    if 'file' not in request.files:
        return {"Error": "The request body is invalid"}, 400
    try:
        payload = verify_jwt(request)
    except AuthError:
        return {'Error': 'Unauthorized'}, 401
    user_key = client.key(USERS, id)
    user = client.get(key=user_key)
    
    if payload[SUB] != user[SUB]:
        return {"Error": "You don't have permission on this resource"}, 403
    

    file_obj = request.files['file']
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(PHOTO_BUCKET)
    
    blob = bucket.blob(file_obj.filename)

    file_obj.seek(0)
    blob.upload_from_file(file_obj)

    #store avatar and user pairs 
    avatar_key = client.key(AVATARS, id)
    avatar = client.get(key=avatar_key)
    if avatar is not None:
        #delete old avatar
        client.delete(avatar_key)
        blob2 = bucket.blob(avatar["file_name"])
        blob2.delete()
        
    #upload new avatar into new kinds table that tracks user avatars
    #Let user id be the key for avatars 
    new_avatar = datastore.Entity(key = client.key(AVATARS, id))
    new_avatar.update({
        "file_name": file_obj.filename,
    })
    client.put(new_avatar)

    return {"avatar_url" : request.url}

#5 Get user avatar
@app.route('/' + USERS + '/<int:id>/' + AVATAR, methods=['GET'])
def get_avatar(id):
    try:
        payload = verify_jwt(request)
    except AuthError:
        return {'Error': 'Unauthorized'}, 401
    user_key = client.key(USERS, id)
    user = client.get(key=user_key)
    
    if payload[SUB] != user[SUB]:
        return {"Error": "You don't have permission on this resource"}, 403
    
    avatar_key = client.key(AVATARS, id)
    avatar = client.get(key=avatar_key)
    if avatar is None:
        return {"Error": "Not found"}, 404
    else:
        #Get image (code from exploration)
        storage_client = storage.Client()
        bucket = storage_client.get_bucket(PHOTO_BUCKET)
        blob = bucket.blob(avatar[FILE_NAME])

        file_obj = io.BytesIO()

        blob.download_to_file(file_obj)

        file_obj.seek(0)

        return send_file(file_obj, mimetype='image/x-png', download_name=avatar[FILE_NAME])
    
#6 Delete a user's avatar 
@app.route('/' + USERS + '/<int:id>/' + AVATAR, methods=['DELETE'])
def delete_avatar(id):
    try:
        payload = verify_jwt(request)
    except AuthError:
        return {'Error': 'Unauthorized'}, 401
    user_key = client.key(USERS, id)
    user = client.get(key=user_key)
    
    if payload[SUB] != user[SUB]:
        return {"Error": "You don't have permission on this resource"}, 403
    
    avatar_key = client.key(AVATARS, id)
    avatar = client.get(key=avatar_key)
    if avatar is None:
        return {"Error": "Not found"}, 404
    else:
        storage_client = storage.Client()
        bucket = storage_client.get_bucket(PHOTO_BUCKET)
        blob = bucket.blob(avatar[FILE_NAME])
        blob.delete()
        client.delete(avatar_key)
        return '', 204

#7 Create a course 
@app.route('/' + COURSES, methods=['POST'])
def create_course():
    content = request.get_json()
    
    try:
        payload = verify_jwt(request)
    except AuthError:
        return {'Error': 'Unauthorized'}, 401

    #check admin rights
    query = client.query(kind=USERS)
    query.add_filter(SUB, "=", payload[SUB])
    result = list(query.fetch())
    if result[0][ROLE] != ADMIN:
        return {'Error':"You don't have permission on this resource"}, 403
    else:
        #check if all properties are present in the content
        attributes = [SUBJECT, NUMBER, TITLE, TERM, INSTRUCTOR_ID]
        for attribute in attributes:
            if attribute not in content:
                return {"Error": "The request body is invalid"}, 400
        
        #verify instructor id
        instructor_key = client.key(USERS, content[INSTRUCTOR_ID])
        instructor = client.get(key=instructor_key)
        if instructor is None:
            return {"Error": "The request body is invalid"}, 400
        elif instructor[ROLE] != "instructor":
            return {"Error": "The request body is invalid"}, 400
        
        new_course = datastore.Entity(key = client.key(COURSES))
        new_course.update({
            SUBJECT: content[SUBJECT],
            NUMBER: content[NUMBER],
            TITLE: content[TITLE],
            TERM: content[TERM],
            INSTRUCTOR_ID: content[INSTRUCTOR_ID]
        })
        client.put(new_course)
        new_course[ID] = new_course.key.id
        new_course[SELF] = request.url + '/' + str(new_course[ID])
        return (new_course, 201)

#8 Get all courses
@app.route('/' + COURSES, methods = ['GET'])
def get_courses():
    offset = request.args.get('offset', type=int)
    limit = request.args.get('limit', type=int)

    query = client.query(kind=COURSES)
    query.order = [SUBJECT]
    results = list(query.fetch())

    courses = []
    
    #pagnation implementation
    if offset:
        length = len(results)
        if (offset + limit) > length:
            for r in results[offset:]:
                new_course = {
                    ID: r.key.id,
                    INSTRUCTOR_ID: r[INSTRUCTOR_ID],
                    NUMBER: r[NUMBER],
                    SELF: request.host_url + COURSES + '/' + str(r.key.id),
                    SUBJECT: r[SUBJECT],
                    TERM: r[TERM],
                    TITLE: r[TITLE]
                }
                courses.append(new_course)
        else:
            for r in results[offset:(offset+limit)]:
                new_course = {
                    ID: r.key.id,
                    INSTRUCTOR_ID: r[INSTRUCTOR_ID],
                    NUMBER: r[NUMBER],
                    SELF: request.host_url + COURSES + '/' + str(r.key.id),
                    SUBJECT: r[SUBJECT],
                    TERM: r[TERM],
                    TITLE: r[TITLE]
                }
                courses.append(new_course) 
        
        next = request.host_url + COURSES + "?limit=" + str((offset+limit)) + "&offset=" + str(limit)
        
        return {COURSES : courses, "next": next}
    
    else: 
        for r in results[:3]:
            new_course = {
                ID: r.key.id,
                INSTRUCTOR_ID: r[INSTRUCTOR_ID],
                NUMBER: r[NUMBER],
                SELF: request.url + '/' + str(r.key.id),
                SUBJECT: r[SUBJECT],
                TERM: r[TERM],
                TITLE: r[TITLE]
            }
            courses.append(new_course)
        next = request.url + "?limit=3&offset=3"
        return {COURSES: courses, "next": next}
    

#9 Get a course
@app.route('/' + COURSES + '/<int:id>', methods=['GET'])
def get_course(id):
    course_key = client.key(COURSES, id)
    course = client.get(key=course_key)

    if course is None:
        return {"Error": "Not found"}, 404
    else: 
        return {
            ID: id,
            INSTRUCTOR_ID: course[INSTRUCTOR_ID],
            NUMBER: course[NUMBER],
            SELF: request.url,
            SUBJECT: course[SUBJECT],
            TERM: course[TERM],
            TITLE: course[TITLE]
        }
    
#10 Update a course 
@app.route('/' + COURSES + '/<int:id>', methods=['PATCH'])
def update_course(id):
    content = request.get_json()
    try:
        payload = verify_jwt(request)
    except AuthError:
        return {'Error': 'Unauthorized'}, 401

    #check admin rights
    query = client.query(kind=USERS)
    query.add_filter(SUB, "=", payload[SUB])
    result = list(query.fetch())
    if result[0][ROLE] != ADMIN:
        return {'Error':"You don't have permission on this resource"}, 403
    else:
        #check if course exists
        course_key = client.key(COURSES, id)
        course = client.get(key=course_key)

        if course is None:
            return {"Error": "You don't have permission on this resource"}, 403
        
        #check if instructor_id is in contents
        if INSTRUCTOR_ID in content: 
            #verify instructor id
            instructor_key = client.key(USERS, content[INSTRUCTOR_ID])
            instructor = client.get(key=instructor_key)
            if instructor is None:
                return {"Error": "The request body is invalid"}, 400
            elif instructor[ROLE] != "instructor":
                return {"Error": "The request body is invalid"}, 400
        
        #update corresponding values
        attributes = [SUBJECT, NUMBER, TITLE, TERM, INSTRUCTOR_ID]
        for attribute in attributes:
            if attribute in content:
                course[attribute] = content[attribute]
        
        client.put(course)

        return {
            ID: id,
            INSTRUCTOR_ID: course[INSTRUCTOR_ID],
            NUMBER: course[NUMBER],
            SELF: request.url,
            SUBJECT: course[SUBJECT],
            TERM: course[TERM],
            TITLE: course[TITLE]
        }
        
#11 Delete a course 
@app.route('/' + COURSES + '/<int:id>', methods=['DELETE'])
def delete_course(id):    
    try:
        payload = verify_jwt(request)
    except AuthError:
        return {'Error': 'Unauthorized'}, 401

    #check admin rights
    query = client.query(kind=USERS)
    query.add_filter(SUB, "=", payload[SUB])
    result = list(query.fetch())
    if result[0][ROLE] != ADMIN:
        return {'Error':"You don't have permission on this resource"}, 403
    else:
        #check if course exists
        course_key = client.key(COURSES, id)
        course = client.get(key=course_key)

        if course is None:
            return {"Error": "You don't have permission on this resource"}, 403
        else:
            query = client.query(kind=ENROLLMENTS)
            query.add_filter(COURSE_ID, '=', id)
            #delete any enrollment 
            results = list(query.fetch())
            for r in results:
                client.delete(r.key)
            client.delete(course_key)
            return('', 204)

#12 Update enrollment in a course
@app.route('/' + COURSES + '/<int:id>/' + STUDENTS, methods=['PATCH'])
def update_enrollment(id):
    try:
        payload = verify_jwt(request)
    except AuthError:
        return {'Error': 'Unauthorized'}, 401

    #check admin rights
    query = client.query(kind=USERS)
    query.add_filter(SUB, "=", payload[SUB])
    result = list(query.fetch())

    #check if course exists
    course_key = client.key(COURSES, id)
    course = client.get(key=course_key)


    if course is None:
        return {"Error": "You don't have permission on this resource"}, 403
    #get instructor for verification
    user_key = client.key(USERS, course[INSTRUCTOR_ID])
    user = client.get(key=user_key)
        
    #check if admin or instructor
    if result[0][ROLE] != ADMIN and user[SUB] != payload[SUB]:
        return {'Error':"You don't have permission on this resource"}, 403
    else:  
        content = request.get_json()
        #check if valid student ids
        for student_id in content[ADD]:
            student_key = client.key(USERS, student_id)
            temp = client.get(student_key)
            print(temp[ROLE])
            if temp[ROLE] != 'student':
                return {'Error': 'Enrollment data is invalid'}, 409
        
        for student_id in content[REMOVE]:
            student_key = client.key(USERS, student_id)
            temp = client.get(student_key)
            if temp[ROLE] != 'student':
                return {'Error': 'Enrollment data is invalid'}, 409

        #check if ids in common
        for student_id in content[ADD]:
            if student_id in content[REMOVE]:
                return {'Error': 'Enrollment data is invalid'}, 409
            
        query1 = client.query(kind=ENROLLMENTS)
        query1.add_filter(COURSE_ID, '=', id)
        results = list(query1.fetch())

        #add students who aren't enrolled
        for student_id in content[ADD]:
            exist = False
            for enrollment in results:
                if enrollment[STUDENT_ID] == student_id:
                    exist = True
            
            if not exist:
                new_enrollment = datastore.Entity(key=client.key(ENROLLMENTS))
                new_enrollment.update({
                    COURSE_ID: id,
                    STUDENT_ID: student_id
                })
                client.put(new_enrollment)
        
        #remove students who are enrolled 
        for student_id in content[REMOVE]:
            for enrollment in results:
                if enrollment[STUDENT_ID] == student_id:
                    client.delete(enrollment.key)
        
        return ('', 200)

#13 Get enrollment for a course 
@app.route('/' + COURSES + '/<int:id>/' + STUDENTS, methods=['GET'])
def get_enrollments(id):
    try:
        payload = verify_jwt(request)
    except AuthError:
        return {'Error': 'Unauthorized'}, 401

    #check admin rights
    query = client.query(kind=USERS)
    query.add_filter(SUB, "=", payload[SUB])
    result = list(query.fetch())

    #check if course exists
    course_key = client.key(COURSES, id)
    course = client.get(key=course_key)


    if course is None:
        return {"Error": "You don't have permission on this resource"}, 403
    #get instructor for verification
    user_key = client.key(USERS, course[INSTRUCTOR_ID])
    user = client.get(key=user_key)

    #check if admin or instructor
    if result[0][ROLE] != ADMIN and user[SUB] != payload[SUB]:
        return {'Error':"You don't have permission on this resource"}, 403
    else: 
        query1 = client.query(kind=ENROLLMENTS)
        query1.add_filter(COURSE_ID, '=', id)
        results = list(query1.fetch())
        student_ids = []
        for r in results:
            student_ids.append(r[STUDENT_ID])
        
        return student_ids

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)

