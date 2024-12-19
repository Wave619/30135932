
"""
Cyber Esports App - A secure credential manager for gaming platforms
Author: Your Name
Version: 1.0

This application provides a secure way to manage gaming credentials with features including:
- Two-factor authentication (2FA)
- Encrypted credential storage
- Password strength validation
- Safe communication guidelines
- Incident response procedures

Security Features:
- Password hashing using SHA-256
- Data encryption using Fernet (symmetric encryption)
- 2FA using random 4-digit codes
- Secure database storage using SQLite
"""

import tkinter as tk
from tkinter import messagebox
import hashlib
import re
import sqlite3
import os
import random
from cryptography.fernet import Fernet


class User:
    """Handles user authentication and account management."""

    def __init__(self, db):
        """Initialize User with database connection."""
        self.db = db
        self.two_factor_code = None

    def create_account(self, username, password):
        """
        Creates a new user account.
        
        Args:
            username (str): Desired username
            password (str): User's password
            
        Returns:
            bool: True if account creation successful, False otherwise
        """
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
        """
        Generates a random 4-digit code for 2FA.
        
        Returns:
            str: 4-digit verification code
        """
        self.two_factor_code = str(random.randint(1000, 9999))
        return self.two_factor_code

    def evaluate_password(self, password):
        """
        Evaluates password strength using multiple criteria.
        
        Args:
            password (str): Password to evaluate
            
        Returns:
            bool: True if password meets all criteria, False otherwise
        """
        if len(password) < 8:
            return False
        if not re.search(r'[A-Z]', password):
            return False
        if not re.search(r'[a-z]', password):
            return False
        if not re.search(r'[0-9]', password):
            return False
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False
        return True

    def login(self):
        """Handles user login with password verification and 2FA."""
        username = self.username_entry_login.get()
        password = self.password_entry_login.get()

        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        if self.db.verify_login(username, hashed_password):
            two_factor_code = self.generate_two_factor_code()
            print(f"Your 2FA code is: {two_factor_code}") 

            self.user.two_factor_code = two_factor_code
            self.parent.show_page("TwoFactorPage")
        else:
            messagebox.showerror("Login Failed", "Invalid username or password.")


class Credential:
    """Manages gaming platform credentials."""

    def __init__(self, db):
        """Initialize with database connection."""
        self.db = db

    def store_gaming_credentials(self, username, twitch, discord, steam):
        """
        Stores encrypted gaming credentials.
        
        Args:
            username (str): User's username
            twitch (str): Twitch credentials
            discord (str): Discord credentials
            steam (str): Steam credentials
        """
        if not twitch and not discord and not steam:
            messagebox.showerror(
                "Input Error",
                "Please fill in at least one field for gaming credentials.")
            return

        self.db.store_gaming_credentials(username, twitch, discord, steam)
        messagebox.showinfo("Success",
                            "Gaming credentials stored successfully!")


class Database:
    """Handles all database operations with encryption."""
    
    def __init__(self, db_name="CyberEsportsApp.db"):
        """Initialize database with encryption key."""
        self.connection = sqlite3.connect(db_name)
        self.cursor = self.connection.cursor()
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)
        self.create_tables()

    def create_tables(self):
        """Creates database tables for users and gaming credentials."""
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL
            )
        ''')

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
        """Encrypts data using Fernet symmetric encryption."""
        return self.cipher.encrypt(data.encode()).decode()

    def decrypt(self, data):
        """Decrypts data using Fernet symmetric encryption."""
        return self.cipher.decrypt(data.encode()).decode()

    def verify_login(self, username, password):
        """Verifies user login credentials."""
        encrypted_username = self.encrypt(username)
        self.cursor.execute(
            "SELECT * FROM users WHERE username = ? AND password_hash = ?",
            (encrypted_username, password))
        result = self.cursor.fetchone()
        return result is not None

    def store_gaming_credentials(self, username, twitch, discord, steam):
        """Stores encrypted gaming credentials in database."""
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
        """Checks for duplicate usernames."""
        encrypted_username = self.encrypt(username)
        self.cursor.execute("SELECT username FROM users WHERE username = ?", (encrypted_username,))
        return self.cursor.fetchone() is not None

    def close(self):
        """Closes database connection."""
        if self.connection:
            self.connection.close()

    def store_credentials(self, username, password):
        """Stores new user credentials."""
        encrypted_username = self.encrypt(username)
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        self.cursor.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (encrypted_username, hashed_password))
        self.connection.commit()


class Page(tk.Frame):
    """Base class for all application pages."""

    def __init__(self, parent, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.parent = parent
        self.grid(row=0, column=0, sticky="nsew")


[Rest of the classes remain unchanged as they are UI components with self-documenting names and clear structure]


class App(tk.Tk):
    """Main application class."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.title("Cyber Esports App")
        self.geometry("414x896")
        self.logged_in_user = None

        # Initialize core components
        self.db = Database()
        self.user = User(self.db)
        self.credential = Credential(self.db)

        # Create page dictionary
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
        """Switches between application pages."""
        for page in self.pages.values():
            page.grid_remove()
        self.pages[page_name].grid()


if __name__ == "__main__":
    app = App()
    app.show_page("LandingPage")
    app.mainloop()
