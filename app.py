from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_bcrypt import Bcrypt
from flask_pymongo import PyMongo
from flask_socketio import SocketIO, emit, join_room, leave_room
from datetime import datetime, timedelta, timezone
from collections import deque
import os
import threading

# ------------------ App Initialization ------------------ #
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "f3A9vL7xQ2mB8rT1yZ6pW4sK0nD5jHcX")
app.permanent_session_lifetime = timedelta(minutes=30)

# ------------------ MongoDB Config ------------------ #
app.config["MONGO_URI"] = os.environ.get(
    "MONGO_URI",
    "mongodb+srv://mgiftsonraj04:5OSQIOy0M4bMrScq@cluster1.5qfr84g.mongodb.net/mobile_tracker?retryWrites=true&w=majority"
)
mongo = PyMongo(app)
bcrypt = Bcrypt(app)

# ------------------ Socket.IO ------------------ #
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# ------------------ Global Queue for Top Locations ------------------ #
recent_locations = deque(maxlen=3)  # newest at front, max 3

# ------------------ Utility Functions ------------------ #
def prune_old_locations():
    """Keep only locations from the last 1 minute in the queue"""
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=1)
    while recent_locations and recent_locations[-1]["timestamp"] < cutoff:
        recent_locations.pop()

def push_location(location):
    """Push a location to the queue and prune old ones"""
    recent_locations.appendleft(location)
    prune_old_locations()

def get_top_locations_data():
    """Return top 3 locations with timestamp as string"""
    prune_old_locations()
    result = []
    for loc in list(recent_locations):
        result.append({
            "username": loc["username"],
            "latitude": loc["latitude"],
            "longitude": loc["longitude"],
            "timestamp": loc["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
        })
    return result

ROLE_ENDPOINTS = {"admin": "admin_dashboard", "client": "user_dashboard"}

# ------------------ Routes ------------------ #
@app.route("/")
def home():
    if "user" in session:
        return redirect(url_for(ROLE_ENDPOINTS.get(session.get("role"), "login")))
    return redirect(url_for("login"))

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        password = bcrypt.generate_password_hash(request.form["password"]).decode("utf-8")
        role = request.form["role"]

        if mongo.db.users.find_one({"username": username}):
            return jsonify({"error": "User already exists!"}), 400

        mongo.db.users.insert_one({"username": username, "password": password, "role": role})
        return jsonify({"message": "Signup successful"}), 200

    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        role = request.form["role"]

        user = mongo.db.users.find_one({"username": username, "role": role})
        if user and bcrypt.check_password_hash(user["password"], password):
            session.permanent = True
            session["user"] = username
            session["role"] = role
            return redirect(url_for(ROLE_ENDPOINTS.get(role)))

        return jsonify({"error": "Invalid credentials!"}), 401

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ------------------ Dashboards ------------------ #
@app.route("/admin_dashboard")
def admin_dashboard():
    if "user" not in session or session.get("role") != "admin":
        return redirect(url_for("login"))
    users = list(mongo.db.users.find({}, {"_id": 0, "password": 0}))
    locations = list(mongo.db.locations.find({}, {"_id": 0}))
    for loc in locations:
        if "timestamp" in loc:
            loc["timestamp"] = loc["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
    return render_template("admin_dashboard.html", users=users, locations=locations)

@app.route("/user_dashboard")
def user_dashboard():
    if "user" not in session or session.get("role") != "client":
        return redirect(url_for("login"))
    locations = list(mongo.db.locations.find({"username": session["user"]}, {"_id": 0}))
    for loc in locations:
        if "timestamp" in loc:
            loc["timestamp"] = loc["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
    return render_template("user_dashboard.html", username=session["user"], locations=locations)

# ------------------ APIs ------------------ #
@app.route("/save_location", methods=["POST"])
def save_location():
    if "user" not in session or session.get("role") != "client":
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    location = {
        "username": session["user"],
        "latitude": data["latitude"],
        "longitude": data["longitude"],
        "timestamp": datetime.now(timezone.utc)
    }

    mongo.db.locations.insert_one(location)
    push_location(location)

    socketio.emit("new_location", {
        "username": location["username"],
        "latitude": location["latitude"],
        "longitude": location["longitude"],
        "timestamp": location["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
    }, room="admins")

    socketio.emit("top_locations", get_top_locations_data(), room="admins")
    return jsonify({"message": "Location saved!"})

@app.route("/get_locations")
def get_locations():
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    if session.get("role") == "client":
        locations = list(mongo.db.locations.find({"username": session["user"]}, {"_id": 0}))
    else:
        locations = list(mongo.db.locations.find({}, {"_id": 0}))

    for loc in locations:
        if "timestamp" in loc:
            loc["timestamp"] = loc["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
    return jsonify(locations)

@app.route("/get_top_locations")
def get_top_locations():
    if "user" not in session or session.get("role") != "admin":
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(get_top_locations_data())

# ------------------ Socket.IO Events ------------------ #
@socketio.on("connect")
def handle_connect():
    if "user" in session:
        role = session.get("role")
        if role == "admin":
            join_room("admins")
        else:
            join_room(session["user"])
    emit("status", {"msg": f"{session.get('user')} connected."})

@socketio.on("disconnect")
def handle_disconnect():
    if "user" in session:
        role = session.get("role")
        if role == "admin":
            leave_room("admins")
        else:
            leave_room(session["user"])
        print(f"{session.get('user')} disconnected.")

# ------------------ Background Thread ------------------ #
def emit_top_locations():
    while True:
        socketio.sleep(60)
        socketio.emit("top_locations", get_top_locations_data(), room="admins")

def start_background_thread():
    thread = threading.Thread(target=emit_top_locations)
    thread.daemon = True
    thread.start()

# ------------------ Prevent Browser Back After Logout ------------------ #
@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response

# ------------------ Main ------------------ #
if __name__ == "__main__":
    start_background_thread()
    socketio.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
