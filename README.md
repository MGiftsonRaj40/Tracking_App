# Mobile Tracker App

A real-time location tracking web application built using **Flask**, **MongoDB**, and **Socket.IO**. Admins can monitor client locations live, while clients can share their location securely. The application includes user authentication, live map updates, and top-location tracking.

---

### Install dependencies:

pip install -r requirements.txt

## Features

- **User Authentication**
  - Sign up and log in as **Admin** or **Client**.
  - Passwords are hashed using **bcrypt** for security.
  - Role-based dashboards with restricted access.

- **Real-Time Tracking**
  - Clients send location updates to the server every time they move.
  - Admins can see live markers for all clients on a map.
  - Socket.IO enables instant updates without refreshing the page.

- **Location History**
  - Clients can view their own past location history.
  - Admins can view all clients’ location histories.

- **Top Locations**
  - Maintains the last 1 minute of location updates in a queue.
  - Shows the top 3 most recent locations for quick monitoring.

- **Security**
  - Session-based login and logout.
  - Disables browser back/forward navigation after logout.
  - Role-based dashboard access to prevent unauthorized viewing.

- **Interactive Maps**
  - Uses **Leaflet.js** for rendering maps and markers.
  - Draws paths connecting client locations.
  - Always focuses on **Tamil Nadu, India** by default.

---

## Tech Stack

- **Backend:** Python, Flask, Flask-Bcrypt, Flask-PyMongo, Flask-SocketIO
- **Database:** MongoDB Atlas
- **Frontend:** HTML, CSS, JavaScript, Leaflet.js
- **Real-Time Communication:** Socket.IO

---

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/mobile-tracker.git
   cd mobile-tracker
