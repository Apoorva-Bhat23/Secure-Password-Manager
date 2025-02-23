# Secure Password Manager

A secure, locally hosted **Password Manager** built with Flask, using **Argon2 Hashing & Fernet Encryption** to store and manage user credentials safely. It includes an **Autofill Feature**, **Session Timeout**, and **Clipboard Clearing** for enhanced security.

---

## 🚀 Features
- 🔐 **Strong Encryption**: Uses **Fernet encryption** to store credentials securely.
- 🔑 **Argon2 Hashing**: Protects master password against brute-force attacks.
- ⚡ **Autofill Functionality**: Automatically fills in login credentials.
- ⏳ **Session Timeout**: Auto-logout after inactivity for extra security.
- 📋 **Clipboard Management**: Clears copied passwords to prevent leakage.
- 🌐 **Flask-Based Web UI**: Simple and easy-to-use interface.

---

## 📥 Installation

1. **Clone the Repository**
```sh
 git clone https://github.com/your-username/secure-password-manager.git
 cd secure-password-manager
```

2. **Create a Virtual Environment (Optional but Recommended)**
```sh
 python -m venv venv
 source venv/bin/activate  # On macOS/Linux
 venv\Scripts\activate    # On Windows
```

3. **Install Dependencies**
```sh
 pip install -r requirements.txt
```

4. **Run the Application**
```sh
 python app.py
```

---

## 🎯 Usage
1. **Set up a Master Password** on first run.
2. **Login using the Master Password**.
3. **Add, Retrieve, Edit, or Delete** saved credentials.
4. **Use the Autofill feature** for quick login access.

---

## 🛠️ Technologies Used
- **Flask** (Python web framework)
- **Fernet Encryption** (for secure password storage)
- **Argon2 Hashing** (for master password security)
- **Pyperclip** (for clipboard management)
- **HTML, CSS, JavaScript** (for web UI)

---

## 🏷️ Topics
`password-manager` `cybersecurity` `flask` `encryption` `argon2` `secure-storage` `autofill` `session-timeout` `clipboard-management`

---

## 📜 License
This project is licensed under the **MIT License**.

---

💡 **Contributions & Feedback**: Feel free to open an **Issue** or **Pull Request** if you’d like to contribute!
