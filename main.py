
# Main application file for Cyber Esports App
# This application provides secure credential management for gaming platforms
# Features include:
# - User authentication with 2FA
# - Secure storage of gaming credentials
# - Password strength validation
# - Compromised password checking
# - Safe communication guidelines
# - Incident response information

import tkinter as tk
from tkinter import messagebox
import hashlib  # For password hashing
import re  # For password validation
import sqlite3  # For database operations
import os
import random  # For 2FA code generation
import json  # For compromised password list
from cryptography.fernet import Fernet  # For encryption/decryption

class User:
    """Handles user-related operations including authentication and password management"""

    def __init__(self, db):
        self.db = db
        self.two_factor_code = None  # Stores temporary 2FA code

    def create_account(self, username, password):
        """
        Creates a new user account with security checks
        Args:
            username: User's chosen username
            password: User's chosen password
        Returns:
            bool: True if account creation successful, False otherwise
        """
        # Check for duplicate username
        if self.db.is_duplicate(username):
            messagebox.showerror("Account Creation Failed",
                                 "Username already in use.")
            return

        # Hash the entered password for security
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        # Verify password isn't in compromised list
        if hashed_password in self.db.compromised_passwords:
            messagebox.showerror(
                "Account Creation Failed",
                "The password you entered is compromised. Please choose a different, stronger password."
            )
            return
            
        # Validate password strength
        if not self.evaluate_password(password):
            messagebox.showerror(
                "Account Creation Failed",
                "Your password is invalid. Please follow the instructions to create a stronger password."
            )
            return

        # Store credentials securely
        self.db.store_credentials(username, password)
        return True

    def generate_two_factor_code(self):
        """
        Generates a random 4-digit code for 2FA
        Returns:
            str: 4-digit verification code
        """
        self.two_factor_code = str(random.randint(1000, 9999))
        return self.two_factor_code

    def evaluate_password(self, password):
        """
        Evaluates password strength against security criteria
        Args:
            password: Password string to evaluate
        Returns:
            bool: True if password meets all criteria, False otherwise
        """
        if len(password) < 8:  # Minimum length check
            return False
        if not re.search(r'[A-Z]', password):  # Uppercase check
            return False
        if not re.search(r'[a-z]', password):  # Lowercase check
            return False
        if not re.search(r'[0-9]', password):  # Number check
            return False
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):  # Special character check
            return False
        return True

    def verify_credentials(self, username, password):
        """
        Verifies user credentials
        Args:
            username: User's username
            password: User's password
        Returns:
            bool: True if credentials are valid
        """
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        return self.db.verify_login(username, hashed_password)

    def alert_compromised_passwords(self):
        """Checks stored passwords against compromised list and alerts users"""
        self.cursor.execute("SELECT username, password_hash FROM users")
        users = self.cursor.fetchall()

        for encrypted_username, hashed_password in users:
            if hashed_password in self.compromised_passwords:
                decrypted_username = self.db.decrypt(encrypted_username)
                messagebox.showwarning(
                    "Compromised Password Alert",
                    f"The password for user '{decrypted_username}' is in the compromised list. "
                    "Please change your password immediately."
                )

    def update_compromised_passwords(self, file_path='Comptimised_Passwords.json'):
        """
        Updates compromised password list and rechecks database
        Args:
            file_path: Path to compromised passwords JSON file
        """
        self.compromised_passwords = self.db.load_hashed_compromised_passwords(file_path)
        self.alert_compromised_passwords()

class Credential:
    """Handles storage and management of gaming platform credentials"""

    def __init__(self, db):
        self.db = db

    def store_gaming_credentials(self, username, twitch, discord, steam):
        """
        Stores gaming platform credentials securely
        Args:
            username: User's username
            twitch: Twitch credentials
            discord: Discord credentials
            steam: Steam credentials
        """
        if not twitch and not discord and not steam:
            messagebox.showerror(
                "Input Error",
                "Please fill in at least one field for gaming credentials.")
            return

        # Hash credentials for security check
        hashed_credentials = {
            'twitch': hashlib.sha256(twitch.encode()).hexdigest() if twitch else None,
            'discord': hashlib.sha256(discord.encode()).hexdigest() if discord else None,
            'steam': hashlib.sha256(steam.encode()).hexdigest() if steam else None,
        }

        # Check for compromised passwords
        for service, hashed_password in hashed_credentials.items():
            if hashed_password and hashed_password in self.db.compromised_passwords:
                messagebox.showerror(
                    "Compromised Password",
                    f"The password for {service} is compromised. Please choose a different, stronger password."
                )
                return
                
        self.db.store_gaming_credentials(username, twitch, discord, steam)
        messagebox.showinfo("Success",
                            "Gaming credentials stored successfully!")

class Database:
    """Handles all database operations and encryption"""
    
    def __init__(self, db_name="CyberEsportsApp.db"):
        self.connection = sqlite3.connect(db_name)
        self.cursor = self.connection.cursor()
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)
        self.create_tables()
        self.compromised_passwords = self.load_hashed_compromised_passwords()

    def create_tables(self):
        """Creates necessary database tables if they don't exist"""
        # Users table for authentication
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL
            )
        ''')

        # Gaming credentials table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS gaming_credentials (
                username TEXT PRIMARY KEY,
                twitch TEXT,
                discord TEXT,
                steam TEXT,
                FOREIGN KEY (username) REFERENCES users(username)
            )
        ''')

        self.connection.commit()

    def encrypt(self, data):
        """Encrypts data using Fernet encryption"""
        return self.cipher.encrypt(data.encode()).decode()

    def decrypt(self, data):
        """Decrypts Fernet-encrypted data"""
        return self.cipher.decrypt(data.encode()).decode()

    def verify_login(self, username, password):
        """
        Verifies user login credentials
        Args:
            username: User's username
            password: User's password hash
        Returns:
            bool: True if credentials are valid
        """
        encrypted_username = self.encrypt(username)
        try:
            self.cursor.execute(
                "SELECT * FROM users WHERE username = ? AND password_hash = ?",
                (encrypted_username, password))
            result = self.cursor.fetchone()
            return result is not None
        except Exception:
            return False

    def store_gaming_credentials(self, username, twitch, discord, steam):
        """
        Stores encrypted gaming credentials
        Args:
            username: User's username
            twitch: Twitch credentials
            discord: Discord credentials
            steam: Steam credentials
        """
        try:
            # Encrypt credentials before storage
            if twitch:
                twitch = self.encrypt(twitch)
            if discord:
                discord = self.encrypt(discord)
            if steam:
                steam = self.encrypt(steam)

            self.cursor.execute(
                '''INSERT OR REPLACE INTO gaming_credentials (username, twitch, discord, steam) 
                               VALUES (?, ?, ?, ?)''',
                (username, twitch, discord, steam))
            self.connection.commit()
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"Failed to store credentials: {str(e)}")
            raise

    def is_duplicate(self, username):
        """
        Checks for duplicate usernames
        Args:
            username: Username to check
        Returns:
            bool: True if username exists
        """
        encrypted_username = self.encrypt(username)
        self.cursor.execute("SELECT username FROM users WHERE username = ?", (encrypted_username,))
        return self.cursor.fetchone() is not None

    def close(self):
        """Closes database connection safely"""
        if self.connection:
            self.connection.close()

    def store_credentials(self, username, password):
        """
        Stores new user credentials securely
        Args:
            username: User's username
            password: User's password
        """
        encrypted_username = self.encrypt(username)
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        self.cursor.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (encrypted_username, hashed_password))
        self.connection.commit()

    def check_compromised_passwords(self):
        """Checks all stored passwords against compromised password list"""
        with open('Compromised_Passwords.json', 'r') as f:
            compromised_passwords = json.load(f)

        self.cursor.execute("SELECT username, password_hash FROM users")
        users = self.cursor.fetchall()

        for username, password_hash in users:
            if password_hash in compromised_passwords:
                messagebox.showwarning(
                    "Compromised Password",
                    f"The password for username '{self.decrypt(username)}' has been compromised. "
                    "Please change your password immediately."
                )

    def load_hashed_compromised_passwords(self, file_path='Compromised_Passwords.json'):
        """
        Loads and hashes compromised passwords from JSON file
        Args:
            file_path: Path to compromised passwords file
        Returns:
            set: Set of hashed compromised passwords
        """
        with open(file_path, 'r') as f:
            compromised_passwords = json.load(f)
        return {hashlib.sha256(password.encode()).hexdigest() for password in compromised_passwords}

# GUI Classes for different pages
class Page(tk.Frame):
    """Base class for all pages in the application"""

    def __init__(self, parent, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.parent = parent
        self.grid(row=0, column=0, sticky="nsew")

class LandingPage(Page):
    """Initial landing page with login/signup options"""

    def __init__(self, parent, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.landing_label = tk.Label(self,
                                      text="Welcome to Cyber Esports App",
                                      font=("Arial", 16))
        self.landing_label.pack(pady=20)

        self.create_account_button = tk.Button(
            self,
            text="Create Account",
            command=lambda: self.parent.show_page("CreateAccountPage"))
        self.create_account_button.pack(pady=10)

        self.login_button_landing = tk.Button(
            self,
            text="Login",
            command=lambda: self.parent.show_page("LoginPage"))
        self.login_button_landing.pack(pady=10)

class TwoFactorPage(Page):
    """Two-factor authentication page"""
    
    def __init__(self, parent, user, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.user = user

        self.label = tk.Label(self, text="Enter 2FA Code", font=("Arial", 16))
        self.label.pack(pady=10)

        self.code_entry = tk.Entry(self)
        self.code_entry.pack(pady=10)

        self.submit_button = tk.Button(self, text="Verify Code", command=self.verify_code)
        self.submit_button.pack(pady=10)

    def verify_code(self):
        """Verifies entered 2FA code"""
        entered_code = self.code_entry.get()

        if entered_code == self.user.two_factor_code:
            messagebox.showinfo("Success", "2FA Verified!")
            self.parent.show_page("CredentialsPage")
        else:
            messagebox.showerror("Error", "Invalid 2FA Code")

class CreateAccountPage(Page):
    """Account creation page with password strength validation"""

    def __init__(self, parent, user, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.user = user

        # UI Components
        self.create_account_label = tk.Label(self,
                                             text="Create Account",
                                             font=("Arial", 16))
        self.create_account_label.pack(pady=10)

        self.username_label_create = tk.Label(self, text="Username:")
        self.username_label_create.pack(pady=5)
        self.username_entry_create = tk.Entry(self)
        self.username_entry_create.pack(pady=5)

        self.password_label_create = tk.Label(self, text="Password:")
        self.password_label_create.pack(pady=5)
        self.password_entry_create = tk.Entry(self, show="*")
        self.password_entry_create.pack(pady=5)

        # Password requirements display
        self.password_instructions = tk.Label(
            self,
            text=("Password Strength Requirements:\n"
                  "1. At least 8 characters long (Strong if 13+)\n"
                  "2. At least 1 uppercase and 1 lowercase letter\n"
                  "3. At least 1 number and 1 symbol"),
        )
        self.password_instructions.pack(pady=5)

        self.password_strength_label_create = tk.Label(self, text="")
        self.password_strength_label_create.pack(pady=5)

        # Bind password strength checker
        self.password_entry_create.bind("<KeyRelease>",
                                        self.update_password_strength_create)

        self.create_account_button_final = tk.Button(
            self, text="Create Account", command=self.create_account)
        self.create_account_button_final.pack(pady=20)

        self.back_to_landing_button = tk.Button(
            self,
            text="Back",
            command=lambda: self.parent.show_page("LandingPage"))
        self.back_to_landing_button.pack(pady=10)

    def update_password_strength_create(self, event=None):
        """Updates password strength indicator in real-time"""
        password = self.password_entry_create.get()
        password_strength = self.user.evaluate_password(password)

        if password_strength:
            self.password_strength_label_create.config(
                text="Password Strength: Strong", fg="green")
        else:
            self.password_strength_label_create.config(
                text="Password Strength: Invalid", fg="red")

    def create_account(self):
        """Handles account creation process"""
        username = self.username_entry_create.get()
        password = self.password_entry_create.get()

        if self.user.create_account(username, password):
            self.parent.show_page("CredentialsPage")

class LoginPage(Page):
    """Login page with 2FA integration"""

    def __init__(self, parent, user, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.user = user

        self.login_label = tk.Label(self, text="Login", font=("Arial", 16))
        self.login_label.pack(pady=10)

        self.username_label_login = tk.Label(self, text="Username:")
        self.username_label_login.pack(pady=5)
        self.username_entry_login = tk.Entry(self)
        self.username_entry_login.pack(pady=5)

        self.password_label_login = tk.Label(self, text="Password:")
        self.password_label_login.pack(pady=5)
        self.password_entry_login = tk.Entry(self, show="*")
        self.password_entry_login.pack(pady=5)

        self.login_button_final = tk.Button(self,
                                            text="Login",
                                            command=self.login)
        self.login_button_final.pack(pady=20)

        self.back_to_landing_button_login = tk.Button(
            self,
            text="Back",
            command=lambda: self.parent.show_page("LandingPage"))
        self.back_to_landing_button_login.pack(pady=10)

    def login(self):
        """Handles login process with security checks"""
        username = self.username_entry_login.get()
        password = self.password_entry_login.get()
        
        if not username or not password:
            messagebox.showerror("Login Failed", "Please enter both username and password.")
            return

        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        
        # Check for compromised password
        if hashed_password in self.user.db.compromised_passwords:
            messagebox.showerror(
                "Login Failed",
                "The password you entered is compromised. Please reset your password immediately."
            )
            return

        if self.user.verify_credentials(username, hashed_password):
            self.user.db.check_compromised_passwords()
            two_factor_code = self.user.generate_two_factor_code()
            messagebox.showinfo("2FA Code", f"Your verification code is: {two_factor_code}")
            self.parent.logged_in_user = username
            self.parent.show_page("TwoFactorPage")
        else:
            messagebox.showerror("Login Failed", "Invalid username or password.")

class CredentialsPage(Page):
    """Page for managing gaming platform credentials"""

    def __init__(self, parent, credential, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.credential = credential

        # UI Components
        self.credentials_label = tk.Label(self,
                                          text="Enter Your Gaming Credentials",
                                          font=("Arial", 16))
        self.credentials_label.pack(pady=10)

        # Twitch credentials
        self.twitch_label = tk.Label(self, text="Twitch Username:")
        self.twitch_label.pack(pady=5)
        self.twitch_entry = tk.Entry(self)
        self.twitch_entry.pack(pady=5)
        self.twitch_label = tk.Label(self, text="Twitch Password:")
        self.twitch_label.pack(pady=5)
        self.twitch_entry = tk.Entry(self, show="*")
        self.twitch_entry.pack(pady=5)

        # Discord credentials
        self.discord_label = tk.Label(self, text="Discord Username:")
        self.discord_label.pack(pady=5)
        self.discord_entry = tk.Entry(self)
        self.discord_entry.pack(pady=5)
        self.discord_label = tk.Label(self, text="Discord Password:")
        self.discord_label.pack(pady=5)
        self.discord_entry = tk.Entry(self, show="*")
        self.discord_entry.pack(pady=5)

        # Steam credentials
        self.steam_label = tk.Label(self, text="Steam Username:")
        self.steam_label.pack(pady=5)
        self.steam_entry = tk.Entry(self)
        self.steam_entry.pack(pady=5)
        self.steam_label = tk.Label(self, text="Steam Password:")
        self.steam_label.pack(pady=5)
        self.steam_entry = tk.Entry(self, show="*")
        self.steam_entry.pack(pady=5)

        # Store credentials button
        self.store_button = tk.Button(self,
                                      text="Store Credentials",
                                      command=self.store_gaming_credentials)
        self.store_button.pack(pady=20)

        # Navigation frame
        self.nav_frame = tk.Frame(self)
        self.nav_frame.pack(pady=10)

        self.safe_communication_button = tk.Button(
            self.nav_frame,
            text="Safe Communication Practices",
            command=lambda: self.parent.show_page("SafeCommunicationPage"),
        )
        self.safe_communication_button.pack(side="left", padx=5)

        self.incident_response_button = tk.Button(
            self.nav_frame,
            text="Incident Response",
            command=lambda: self.parent.show_page("IncidentResponsePage"),
        )
        self.incident_response_button.pack(side="left", padx=5)

        self.logout_button = tk.Button(
            self.nav_frame,
            text="Logout",
            command=lambda: self.parent.show_page("LandingPage"))
        self.logout_button.pack(side="left", padx=5)

    def store_gaming_credentials(self):
        """Stores gaming credentials securely"""
        twitch = self.twitch_entry.get()
        discord = self.discord_entry.get()
        steam = self.steam_entry.get()
        self.credential.store_gaming_credentials(self.parent.logged_in_user,
                                                 twitch, discord, steam)

class SafeCommunicationPage(Page):
    """Page displaying safe communication practices"""

    def __init__(self, parent, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.safe_communication_label = tk.Label(
            self, text="Safe Communication Practices", font=("Arial", 16))
        self.safe_communication_label.pack(pady=10)

        self.back_to_credentials_button_safe = tk.Button(
            self,
            text="Back to Credentials",
            command=lambda: self.parent.show_page("CredentialsPage"),
        )
        self.back_to_credentials_button_safe.pack(pady=10)

class IncidentResponsePage(Page):
    """Page displaying incident response information"""

    def __init__(self, parent, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.incident_response_label = tk.Label(
            self,
            text="Incident Response and Recovery Plans",
            font=("Arial", 16),
        )
        self.incident_response_label.pack(pady=10)

        self.back_to_credentials_button_incident = tk.Button(
            self,
            text="Back to Credentials",
            command=lambda: self.parent.show_page("CredentialsPage"),
        )
        self.back_to_credentials_button_incident.pack(pady=10)

class App(tk.Tk):
    """Main application class"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.title("Cyber Esports App")
        self.geometry("414x896")
        self.logged_in_user = None

        # Initialize core components
        self.db = Database()
        self.user = User(self.db)
        self.credential = Credential(self.db)

        # Initialize all pages
        self.pages = {
            "LandingPage": LandingPage(self),
            "CreateAccountPage": CreateAccountPage(self, self.user),
            "LoginPage": LoginPage(self, self.user),
            "CredentialsPage": CredentialsPage(self, self.credential),
            "SafeCommunicationPage": SafeCommunicationPage(self),
            "IncidentResponsePage": IncidentResponsePage(self),
            "TwoFactorPage": TwoFactorPage(self, self.user),
        }

    def show_page(self, page_name):
        """
        Shows the specified page and hides others
        Args:
            page_name: Name of the page to display
        """
        for page in self.pages.values():
            page.grid_remove()
        self.pages[page_name].grid()

if __name__ == "__main__":
    app = App()
    app.db.check_compromised_passwords()  # Check for compromised passwords on startup
    app.show_page("LandingPage")  # Show initial page
    app.mainloop()  # Start application
