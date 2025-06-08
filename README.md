# NetDisk

NetDisk is a lightweight Flask based network disk application. It provides
simple user registration, login and file management through a web interface.
The admin user can view upload/download logs and manage all registered users.

## Features
- User registration and login with password hashing
- File upload, download and preview
- Folder management (create/delete)
- Admin panel with user list, upload/download logs and user removal
- Optional mDNS service advertisement via `zeroconf`

## Setup
1. Create a virtual environment (optional):
   ```bash
   python -m venv venv
   source venv/bin/activate
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. (Optional) Create a `.env` file to override the default admin account:
   ```bash
   ADMIN_USERNAME=admin
   ADMIN_PASSWORD=admin123
   ```
4. Run the server:
   ```bash
   python main.py
   ```
   By default the application listens on port `5000`.

Uploaded files and metadata will be stored inside the `uploads/` directory and
various `*.json` files in the project root.

## Requirements
All required third‑party packages are listed in `requirements.txt`.
