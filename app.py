from flask import Flask, render_template, request, redirect, url_for, session
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from bson.objectid import ObjectId
import re

app = Flask(__name__)
app.secret_key = '221499'
app.config["MONGO_URI"] = "mongodb://localhost:27017/complaint_management"

try:
    mongo = PyMongo(app)
    bcrypt = Bcrypt(app)
except Exception as e:
    print(f"Error connecting to MongoDB: {e}")
    mongo = None

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        if not mongo:
            return render_template('register.html', error="Database connection error.")

        # Validate email pattern
        email_pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        if not re.match(email_pattern, email):
            return render_template('register.html', error="Invalid email format.")

        # Validate username (only characters)
        if not name.isalpha():
            return render_template('register.html', error="Username must contain only characters.")

        # Check if email is already registered
        if mongo.db.user_data.find_one({"email": email}):
            return render_template('register.html', error="Email already registered.")

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        mongo.db.user_data.insert_one({"name": name, "email": email, "password": hashed_password})

        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        if not mongo:
            return render_template('login.html', error="Database connection error.")

        user = mongo.db.user_data.find_one({"email": email})
        if user and bcrypt.check_password_hash(user['password'], password):
            session['user_id'] = str(user['_id'])
            session['user_name'] = user['name']
            session['is_admin'] = user.get('is_admin', False)
            return redirect(url_for('dashboard'))

        return render_template('login.html', error="Invalid credentials.")

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if not mongo:
        return render_template('dashboard.html', error="Database connection error.")

    complaints = mongo.db.complaint_data.find({"user_id": session['user_id']})
    admin_button = session.get('is_admin', False)
    return render_template('dashboard.html', complaints=complaints, user_name=session['user_name'], admin_button=admin_button)

@app.route('/add_complaint', methods=['GET', 'POST'])
def add_complaint():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if not mongo:
        return render_template('add_complaint.html', error="Database connection error.")

    if request.method == 'POST':
        category = request.form['category']
        description = request.form['description']
        location = request.form['location']
        priority = request.form['priority']

        mongo.db.complaint_data.insert_one({
            "user_id": session['user_id'],
            "category": category,
            "description": description,
            "location": location,
            "priority": priority,
            "status": "Pending"
        })

        return redirect(url_for('dashboard'))
    
    return render_template('add_complaint.html')

@app.route('/delete_complaint/<complaint_id>')
def delete_complaint(complaint_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if not mongo:
        return redirect(url_for('dashboard', error="Database connection error."))

    mongo.db.complaint_data.delete_one({"_id": ObjectId(complaint_id), "user_id": session['user_id']})
    return redirect(url_for('dashboard'))

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username == 'admin' and password == 'admin123':
            print("Admin logged in!")
            print(f"Admin Status: Logged In")
            return redirect(url_for('admin'))

        return render_template('admin_login.html', error="Invalid admin credentials.")

    return render_template('admin_login.html')

@app.route('/admin')
def admin():
    if not mongo:
        return render_template('admin.html', error="Database connection error.")

    complaints = list(mongo.db.complaint_data.find())
    for complaint in complaints:
        complaint['_id'] = str(complaint['_id'])
        complaint['user_id'] = str(complaint['user_id']) 

    users = {str(user['_id']): user['name'] for user in mongo.db.user_data.find()}

    return render_template('admin.html', complaints=complaints, users=users)

@app.route('/resolve_complaint/<complaint_id>')
def resolve_complaint(complaint_id):
    if not mongo:
        return redirect(url_for('admin', error="Database connection error."))

    mongo.db.complaint_data.update_one(
        {"_id": ObjectId(complaint_id)},
        {"$set": {"status": "Resolved"}}
    )

    return redirect(url_for('admin'))

@app.route('/pending_complaints')
def pending_complaints():
    if not mongo:
        return render_template('pending_complaints.html', error="Database connection error.")
    
    # Fetch complaints with status "Pending"
    complaints = list(mongo.db.complaint_data.find({"status": "Pending"}))
    
    # Fetch user data for each complaint
    for complaint in complaints:
        complaint['_id'] = str(complaint['_id'])
        complaint['user_id'] = str(complaint['user_id'])
        user = mongo.db.user_data.find_one({"_id": ObjectId(complaint['user_id'])})
        if user:
            complaint['user_name'] = user['name']  # Add user name
        else:
            complaint['user_name'] = "Unknown"
    
    return render_template('pending_complaints.html', complaints=complaints)


@app.route('/resolved_complaints')
def resolved_complaints():
    if not mongo:
        return render_template('resolved_complaints.html', error="Database connection error.")
    
    # Fetch complaints with status "Resolved"
    complaints = list(mongo.db.complaint_data.find({"status": "Resolved"}))
    
    # Fetch user data for each complaint
    for complaint in complaints:
        complaint['_id'] = str(complaint['_id'])
        complaint['user_id'] = str(complaint['user_id'])
        user = mongo.db.user_data.find_one({"_id": ObjectId(complaint['user_id'])})
        if user:
            complaint['user_name'] = user['name']  # Add user name
        else:
            complaint['user_name'] = "Unknown"
    
    return render_template('resolved_complaints.html', complaints=complaints)


@app.route('/users')
def users():
    if not mongo:
        return render_template('users.html', error="Database connection error.")
    users = {str(user['_id']): user['name'] for user in mongo.db.user_data.find()}
    return render_template('users.html', users=users)


@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if not mongo:
        return render_template('edit_profile.html', error="Database connection error.")

    user_id = session['user_id']
    user = mongo.db.user_data.find_one({"_id": ObjectId(user_id)})

    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        cnic = request.form['cnic']
        nationality = request.form['nationality']
        gender = request.form['gender']
        address = request.form['address']

        # Validate email pattern
        email_pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        if not re.match(email_pattern, email):
            return render_template('edit_profile.html', user=user, error="Invalid email format.")

        # Validate username (only characters)
        if not name.isalpha():
            return render_template('edit_profile.html', user=user, error="Username must contain only characters.")

        # Check if email is already registered by another user
        if mongo.db.user_data.find_one({"email": email, "_id": {"$ne": ObjectId(user_id)}}):
            return render_template('edit_profile.html', user=user, error="Email already registered.")

        mongo.db.user_data.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {
                "name": name,
                "email": email,
                "cnic": cnic,
                "nationality": nationality,
                "gender": gender,
                "address": address
            }}
        )

        return redirect(url_for('dashboard'))

    return render_template('edit_profile.html', user=user)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

