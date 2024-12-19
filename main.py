
# Import necessary libraries
import tkinter as tk  # GUI framework
from tkinter import messagebox  # For showing popup messages
import hashlib  # For password hashing
import re  # For regular expressions in password validation
import sqlite3  # Database management
import os  # Operating system interface
import random  # For generating random numbers
from cryptography.fernet import Fernet  # For encryption/decryption

class User:
    """Handles user-related operations including account creation and authentication"""
    def __init__(self, db):
        self.db = db  # Database instance
        self.two_factor_code = None  # Stores 2FA code

    def create_account(self, username, password):
        """Creates a new user account with validation checks"""
        if self.db.is_duplicate(username):
            messagebox.showerror("Account Creation Failed",
                                 "Username already in use.")
            return

        if not self.evaluate_password(password):
            messagebox.showerror(
                "Account Creation Failed",
                "Your password is invalid. Please follow the instructions to create a stronger password."
            )
            return

        self.db.store_credentials(username, password)
        return True

    def generate_two_factor_code(self):
        """Generates a random 4-digit code for 2FA"""
        self.two_factor_code = str(random.randint(1000, 9999))
        return self.two_factor_code

    def evaluate_password(self, password):
        """Checks password strength against security requirements"""
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

    def login(self):
        """Handles user login with 2FA"""
        username = self.username_entry_login.get()
        password = self.password_entry_login.get()

        # Hash password for comparison
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        if self.db.verify_login(username, hashed_password):
            two_factor_code = self.generate_two_factor_code()
            print(f"Your 2FA code is: {two_factor_code}") 

            self.user.two_factor_code = two_factor_code
            self.parent.show_page("TwoFactorPage")
        else:
            messagebox.showerror("Login Failed", "Invalid username or password.")

class Credential:
    """Manages gaming platform credentials"""
    def __init__(self, db):
        self.db = db

    def store_gaming_credentials(self, username, twitch, discord, steam):
        """Stores encrypted gaming platform credentials"""
        if not twitch and not discord and not steam:
            messagebox.showerror(
                "Input Error",
                "Please fill in at least one field for gaming credentials.")
            return

        self.db.store_gaming_credentials(username, twitch, discord, steam)
        messagebox.showinfo("Success",
                            "Gaming credentials stored successfully!")

class Database:
    """Handles all database operations with encryption"""
    def __init__(self, db_name="CyberEsportsApp.db"):
        self.connection = sqlite3.connect(db_name)
        self.cursor = self.connection.cursor()
        self.key = Fernet.generate_key()  # Encryption key
        self.cipher = Fernet(self.key)  # Encryption cipher
        self.create_tables()

    def create_tables(self):
        """Initializes database tables for users and gaming credentials"""
        # Users table with encrypted credentials
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL
            )
        ''')

        # Gaming credentials table with encrypted platform data
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
        """Encrypts data using Fernet symmetric encryption"""
        return self.cipher.encrypt(data.encode()).decode()

    def decrypt(self, data):
        """Decrypts data using Fernet symmetric encryption"""
        return self.cipher.decrypt(data.encode()).decode()

    def verify_login(self, username, password):
        """Verifies user login credentials"""
        encrypted_username = self.encrypt(username)
        self.cursor.execute(
            "SELECT * FROM users WHERE username = ? AND password_hash = ?",
            (encrypted_username, password))
        result = self.cursor.fetchone()
        return result is not None

    def store_gaming_credentials(self, username, twitch, discord, steam):
        """Stores encrypted gaming platform credentials"""
        try:
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
        """Checks for duplicate usernames"""
        encrypted_username = self.encrypt(username)
        self.cursor.execute("SELECT username FROM users WHERE username = ?", (encrypted_username,))
        return self.cursor.fetchone() is not None

    def close(self):
        """Safely closes database connection"""
        if self.connection:
            self.connection.close()

    def store_credentials(self, username, password):
        """Stores new user credentials with encryption"""
        encrypted_username = self.encrypt(username)
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        self.cursor.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (encrypted_username, hashed_password))
        self.connection.commit()

# Base class for all pages
class Page(tk.Frame):
    """Base class for all application pages"""
    def __init__(self, parent, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.parent = parent
        self.grid(row=0, column=0, sticky="nsew")

class LandingPage(Page):
    """Initial page with login and account creation options"""
    def __init__(self, parent, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        # UI components initialization...
        [rest of the existing LandingPage code]

[Rest of the existing code with similar comment structure]

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
        """Handles page navigation"""
        # Hide all pages
        for page in self.pages.values():
            page.grid_remove()
        # Show the selected page
        self.pages[page_name].grid()

# Application entry point
if __name__ == "__main__":
    app = App()
    app.show_page("LandingPage")  # Show initial page
    app.mainloop()  # Start GUI event loop
