# Import required libraries
import tkinter as tk  # GUI framework for creating desktop applications
from tkinter import messagebox  # For displaying popup messages and errors
import hashlib  # For secure password hashing
import re  # For regular expression operations in password validation
import time  # For tracking login attempt timestamps
import sqlite3  # For database operations
import random  # For generating random 2FA codes
from cryptography.fernet import Fernet  # For symmetric encryption of sensitive data
import json  # For handling JSON files
import base64  # Import base64 for decoding
import string # For the random password generator


class User:
    """
    Handles user authentication and account management.
    Includes methods for account creation, password validation, and 2FA.
    """

    def __init__(self, db):
        self.db = db  # Initialise database connection
        self.two_factor_code = None  # Store temporary 2FA code
        self.login_attempts = {}  # Track login attempts {username: (attempts, last_attempt_time)}

    def create_account(self, username, password):
        """
        Creates a new user account with validation checks.
        Returns True if account creation is successful.
        """
        # Check if username already exists
        if self.db.is_duplicate(username):
            messagebox.showerror("Account Creation Failed",
                                 "Username already in use.")
            return

        # Validate password strength
        if not self.evaluate_password(password):
            messagebox.showerror(
                "Account Creation Failed",
                "Your password is invalid. Please follow the instructions to create a stronger password."
            )
            return

        # Store credentials if validation passes
        self.db.store_credentials(username, password)
        return True

    def generate_two_factor_code(self):
        """Generates a random 4-digit code for 2FA"""
        self.two_factor_code = str(random.randint(1000, 9999))
        return self.two_factor_code

    def evaluate_password(self, password):
        """
        Evaluates password strength based on multiple criteria:
        - Minimum length of 8 characters
        - Contains uppercase and lowercase letters
        - Contains numbers
        - Contains special characters
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

    def check_login_attempts(self, username, current_time):
        """Check if user is locked out and track attempts"""
        if username in self.login_attempts:
            attempts, last_attempt_time = self.login_attempts[username]
            if attempts >= 5:
                time_diff = current_time - last_attempt_time
                if time_diff < 120:  # 120 seconds = 2 minutes
                    return int(120 - time_diff)  # Return remaining lockout time
                else:
                    # Reset attempts after lockout period
                    self.login_attempts[username] = (0, current_time)
        return 0  # No lockout in effect




class Credential:
    """Manages gaming platform credentials storage and retrieval"""

    def __init__(self, db):
        self.db = db

    def store_gaming_credentials(self, username, twitch, discord, steam):
        """Stores encrypted gaming platform credentials"""
        # Check if at least one credential pair is complete
        if (not (twitch.split(':')[0] and twitch.split(':')[1]) and 
            not (discord.split(':')[0] and discord.split(':')[1]) and 
            not (steam.split(':')[0] and steam.split(':')[1])):
            messagebox.showerror(
                "Input Error",
                "Please fill in both username and password for at least one service.")
            return

        self.db.store_gaming_credentials(username, twitch, discord, steam)
        messagebox.showinfo("Success",
                            "Gaming credentials stored successfully!")
        
    def generate_strong_password(self):
        """Generates a strong random password."""
        length = 13
        characters = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(random.choice(characters) for i in range(length))
        return password



class Database:
    """Handles all database operations including encryption and storage"""

    def __init__(self, db_name="CyberEsportsApp.db"):
        self.connection = sqlite3.connect(db_name)
        self.cursor = self.connection.cursor()
        
        # Create key table if it doesn't exist
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS encryption_key (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                key BLOB NOT NULL
            )
        ''')
        
        # Get or create encryption key
        self.cursor.execute("SELECT key FROM encryption_key WHERE id = 1")
        key_row = self.cursor.fetchone()
        
        if key_row is None:
            self.key = Fernet.generate_key()
            self.cursor.execute("INSERT INTO encryption_key (id, key) VALUES (1, ?)", (self.key,))
            self.connection.commit()
        else:
            self.key = bytes(key_row[0])
            
        self.cipher = Fernet(self.key)
        self.create_tables()

    def create_tables(self):
        """Creates necessary database tables if they don't exist"""       
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL
            )
        ''')

        # Gaming credentials table with encryption
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
        """Encrypts sensitive data using Fernet symmetric encryption"""
        return self.cipher.encrypt(data.encode()).decode()

    def decrypt(self, data):
        """Decrypts encrypted data using Fernet symmetric encryption"""
        return self.cipher.decrypt(data.encode()).decode()

    def verify_login(self, username, password):
        """Verifies user login credentials"""
        self.cursor.execute(
            "SELECT * FROM users WHERE username = ? AND password_hash = ?",
            (username, password))
        result = self.cursor.fetchone()
        return result is not None

    def store_gaming_credentials(self, username, twitch, discord, steam):
        """Stores encrypted gaming credentials in database"""
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
                   VALUES (?, ?, ?, ?)''', (username, twitch, discord, steam))
            self.connection.commit()
        except sqlite3.Error as e:
            messagebox.showerror("Database Error",
                                 f"Failed to store credentials: {str(e)}")
            raise

    def is_duplicate(self, username):
        """Checks for duplicate usernames"""
        self.cursor.execute("SELECT username FROM users WHERE username = ?",
                            (username, ))
        return self.cursor.fetchone() is not None

    def close(self):
        """Safely closes database connection"""
        if self.connection:
            self.connection.close()

    def store_credentials(self, username, password):
        """Stores hashed user credentials"""
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        self.cursor.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, hashed_password))
        self.connection.commit()

    def check_compromised_passwords(self, username):
        """Checks if the user's passwords are compromised"""
        try:
            # Load compromised passwords from JSON file
            with open("compromised_passwords.json", "r") as file:
                compromised_data = json.load(file)

            # Get encrypted credentials for the user
            self.cursor.execute(
                "SELECT twitch, discord, steam FROM gaming_credentials WHERE username = ?",
                (username, ))
            credentials = self.cursor.fetchone()

            if not credentials:
                return

            compromised_services = []
            
            # Check each service's credentials separately
            services = [(credentials[0], "Twitch"), 
                       (credentials[1], "Discord"), 
                       (credentials[2], "Steam")]
            
            for encrypted_cred, service_name in services:
                if not encrypted_cred:
                    continue
                    
                try:
                    decrypted = self.decrypt(encrypted_cred)
                    if ':' not in decrypted:
                        continue
                        
                    username, password = decrypted.split(':')
                    # Check if this specific service's password is compromised
                    if password in compromised_data:
                        # Show individual warning for each compromised service
                        messagebox.showwarning(
                            "Compromised Password Detected",
                            f"Your password for {service_name} has been compromised.\n"
                            "Please view the Incident Response page as soon as possible."
                        )
                        
                except Exception as e:
                    print(f"Error processing {service_name} credentials: {str(e)}")
        except Exception as e:
            messagebox.showerror(
                "Error", f"Failed to check compromised passwords: {str(e)}")


class Page(tk.Frame):
    """Base class for all application pages"""

    def __init__(self, parent, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.parent = parent
        self.grid(row=0, column=0, sticky="nsew")


class LandingPage(Page):
    """Initial page with options to login or create account"""

    def __init__(self, parent, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        # Create welcome label
        self.landing_label = tk.Label(self,
                                      text="Welcome to Cyber Esports App",
                                      font=("Arial", 16))
        self.landing_label.pack(pady=20)

        # Create navigation buttons
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
    """Handles 2FA verification"""

    def __init__(self, parent, user, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.user = user

        # Create 2FA interface elements
        self.label = tk.Label(self, text="Enter 2FA Code", font=("Arial", 16))
        self.label.pack(pady=10)

        self.code_entry = tk.Entry(self)
        self.code_entry.pack(pady=10)

        self.submit_button = tk.Button(self,
                                       text="Verify Code",
                                       command=self.verify_code)
        self.submit_button.pack(pady=10)

    def verify_code(self):
        """Verifies entered 2FA code"""
        entered_code = self.code_entry.get()
        if entered_code == self.user.two_factor_code:
            messagebox.showinfo("Success", "2FA Verified!")
            # Check for compromised passwords after successful 2FA
            self.user.db.check_compromised_passwords(self.parent.logged_in_user)
            self.parent.show_page("CredentialsPage")
        else:
            messagebox.showerror("Error", "Invalid 2FA Code")


class CreateAccountPage(Page):
    """Page for new account creation with password strength validation"""

    def __init__(self, parent, user, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.user = user

        # Create account creation interface elements
        self.create_account_label = tk.Label(self,
                                             text="Create Account",
                                             font=("Arial", 16))
        self.create_account_label.pack(pady=10)

        # Username input
        self.username_label_create = tk.Label(self, text="Username:")
        self.username_label_create.pack(pady=5)
        self.username_entry_create = tk.Entry(self)
        self.username_entry_create.pack(pady=5)

        # Password input with strength meter
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

        # Password strength indicator
        self.password_strength_label_create = tk.Label(self, text="")
        self.password_strength_label_create.pack(pady=5)

        # Bind password strength checker to keypress
        self.password_entry_create.bind("<KeyRelease>",
                                        self.update_password_strength_create)

        # Create account and navigation buttons
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
    """Handles user login with 2FA"""

    def __init__(self, parent, user, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.user = user

        # Create login interface elements
        self.login_label = tk.Label(self, text="Login", font=("Arial", 16))
        self.login_label.pack(pady=10)

        # Username input
        self.username_label_login = tk.Label(self, text="Username:")
        self.username_label_login.pack(pady=5)
        self.username_entry_login = tk.Entry(self)
        self.username_entry_login.pack(pady=5)

        # Password input
        self.password_label_login = tk.Label(self, text="Password:")
        self.password_label_login.pack(pady=5)
        self.password_entry_login = tk.Entry(self, show="*")
        self.password_entry_login.pack(pady=5)

        # Login and navigation buttons
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
        """Processes login attempt with 2FA and handles login attempt limiting"""
        username = self.username_entry_login.get()
        password = self.password_entry_login.get()
        
        # Check if user is locked out
        current_time = time.time()
        remaining_lockout = self.user.check_login_attempts(username, current_time)
        if remaining_lockout > 0:
            # Create lockout window
            lockout_window = tk.Toplevel(self)
            lockout_window.title("Account Locked")
            lockout_window.geometry("300x150")
            
            # Create labels
            lock_label = tk.Label(lockout_window, 
                                text="Too many failed attempts.\nAccount is temporarily locked.",
                                font=("Arial", 12))
            lock_label.pack(pady=10)
            
            time_label = tk.Label(lockout_window, 
                                text=f"Time remaining: {remaining_lockout} seconds",
                                font=("Arial", 12))
            time_label.pack(pady=10)
            
            # Update countdown timer
            def update_timer():
                nonlocal remaining_lockout
                remaining_lockout -= 1
                time_label.config(text=f"Time remaining: {remaining_lockout} seconds")
                
                if remaining_lockout > 0:
                    lockout_window.after(1000, update_timer)
                else:
                    lockout_window.destroy()
            
            # Start countdown
            lockout_window.after(1000, update_timer)
            return

        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        if self.user.db.verify_login(username, hashed_password):
            # Reset login attempts on successful login
            if username in self.user.login_attempts:
                del self.user.login_attempts[username]
                
            # Proceed with 2FA
            two_factor_code = self.user.generate_two_factor_code()
            messagebox.showinfo(
                "2FA Code", f"Your verification code is: {two_factor_code}")
            self.parent.logged_in_user = username
            self.parent.show_page("TwoFactorPage")
        else:
            # Update failed login attempts
            if username not in self.user.login_attempts:
                self.user.login_attempts[username] = (1, current_time)
                messagebox.showerror("Login Failed", "Invalid username or password.")
            else:
                attempts, _ = self.user.login_attempts[username]
                new_attempts = attempts + 1
                self.user.login_attempts[username] = (new_attempts, current_time)
                
                if new_attempts == 4:
                    messagebox.showerror("Login Failed", "Invalid username or password. 1 attempt remaining before lockout.")
                elif new_attempts == 3:
                    messagebox.showerror("Login Failed", "Invalid username or password. 2 attempts remaining before lockout.")
                else:
                    messagebox.showerror("Login Failed", "Invalid username or password.")


class CredentialsPage(Page):
    """Manages gaming platform credentials"""

    def __init__(self, parent, credential, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.credential = credential

        # Create credentials interface
        self.credentials_label = tk.Label(self,
                                          text="Enter Your Gaming Credentials",
                                          font=("Arial", 16))
        self.credentials_label.pack(pady=10)

        # Twitch credentials input
        self.twitch_username_label = tk.Label(self, text="Twitch Username:")
        self.twitch_username_label.pack(pady=5)
        self.twitch_username_entry = tk.Entry(self)
        self.twitch_username_entry.pack(pady=5)
        self.twitch_password_label = tk.Label(self, text="Twitch Password:")
        self.twitch_password_label.pack(pady=5)
        self.twitch_password_entry = tk.Entry(self, show="*")
        self.twitch_password_entry.pack(pady=5)

        # Discord credentials input
        self.discord_username_label = tk.Label(self, text="Discord Username:")
        self.discord_username_label.pack(pady=5)
        self.discord_username_entry = tk.Entry(self)
        self.discord_username_entry.pack(pady=5)
        self.discord_password_label = tk.Label(self, text="Discord Password:")
        self.discord_password_label.pack(pady=5)
        self.discord_password_entry = tk.Entry(self, show="*")
        self.discord_password_entry.pack(pady=5)

        # Steam credentials input
        self.steam_username_label = tk.Label(self, text="Steam Username:")
        self.steam_username_label.pack(pady=5)
        self.steam_username_entry = tk.Entry(self)
        self.steam_username_entry.pack(pady=5)
        self.steam_password_label = tk.Label(self, text="Steam Password:")
        self.steam_password_label.pack(pady=5)
        self.steam_password_entry = tk.Entry(self, show="*")
        self.steam_password_entry.pack(pady=5)

    
        #Make random password button
        self.generate_password_button = tk.Button(
            self,
            text="Create A Random Password",
            command=self.generate_password_popup
        )
        self.generate_password_button.pack(pady=10)

        # Store credentials button
        self.store_button = tk.Button(self,
                                      text="Store Credentials",
                                      command=self.store_gaming_credentials)
        self.store_button.pack(pady=10)

        # View credentials button
        self.view_button = tk.Button(self,
                                   text="View Stored Credentials",
                                   command=self.view_credentials)
        self.view_button.pack(pady=10)

        # Navigation frame
        self.nav_frame = tk.Frame(self)
        self.nav_frame.pack(pady=10)

        # Navigation buttons
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

    def generate_password_popup(self):
        """Displays a popup with a randomly generated password."""
        password = self.credential.generate_strong_password()
        messagebox.showinfo("Generated Password", f"Your strong password: {password}")

    def store_gaming_credentials(self):
        """Stores encrypted gaming credentials"""
        twitch = f"{self.twitch_username_entry.get()}:{self.twitch_password_entry.get()}"
        discord = f"{self.discord_username_entry.get()}:{self.discord_password_entry.get()}"
        steam = f"{self.steam_username_entry.get()}:{self.steam_password_entry.get()}"
        self.credential.store_gaming_credentials(self.parent.logged_in_user,
                                                 twitch, discord, steam)

    def view_credentials(self):
        """Switch to credentials viewing page"""
        self.parent.pages["ViewCredentialsPage"].load_credentials()
        self.parent.show_page("ViewCredentialsPage")


class SafeCommunicationPage(Page):
    """Displays safe communication practices and guidelines"""

    def __init__(self, parent, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.safe_communication_label = tk.Label(
            self, text="Safe Communication Practices", font=("Arial", 16))
        self.safe_communication_label.pack(pady=10)

        # Create content frame
        content_frame = tk.Frame(self)
        content_frame.pack(pady=10, padx=20)

        # Safety tips list
        tips = [
            "1. Never share your passwords or account credentials in chat",
            "2. Be cautious with links shared in game chat or Discord",
            "3. Use unique passwords for each gaming platform",
            "4. Enable two-factor authentication when available",
            "5. Avoid sharing personal information during gameplay",
            "6. Report suspicious behavior to platform moderators",
            "7. Use voice chat only with trusted teammates",
            "8. Be careful when downloading game mods or add-ons"
        ]

        # Display tips
        for tip in tips:
            tip_label = tk.Label(content_frame,
                                 text=tip,
                                 wraplength=350,
                                 justify="left")
            tip_label.pack(pady=5, anchor="w")

        # Navigation button
        self.back_to_credentials_button_safe = tk.Button(
            self,
            text="Back to Credentials",
            command=lambda: self.parent.show_page("CredentialsPage"),
        )
        self.back_to_credentials_button_safe.pack(pady=10)


class IncidentResponsePage(Page):
    """Displays incident response procedures and recovery plans"""

    def __init__(self, parent, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.incident_response_label = tk.Label(
            self,
            text="Incident Response and Recovery Plans",
            font=("Arial", 16),
        )
        self.incident_response_label.pack(pady=10)

        # Create content frame
        content_frame = tk.Frame(self)
        content_frame.pack(pady=10, padx=20)

        # Response steps list
        steps = [
            "If Your Account Is Compromised:",
            "1. Immediately change your password",
            "2. Contact platform support services",
            "3. Enable additional security features",
            "4. Review recent account activity", "", "Preventive Measures:",
            "1. Regularly update your passwords",
            "2. Monitor account login notifications",
            "3. Keep your email account secure",
            "4. Save support contact information", "", "Recovery Steps:",
            "1. Document all unauthorized activities",
            "2. Report suspicious transactions",
            "3. Review and revoke third-party access",
            "4. Scan your device for malware"
        ]

        # Display steps
        for step in steps:
            step_label = tk.Label(content_frame,
                                  text=step,
                                  wraplength=350,
                                  justify="left")
            step_label.pack(pady=5, anchor="w")

        # Navigation button
        self.back_to_credentials_button_incident = tk.Button(
            self,
            text="Back to Credentials",
            command=lambda: self.parent.show_page("CredentialsPage"),
        )
        self.back_to_credentials_button_incident.pack(pady=10)


class ViewCredentialsPage(Page):
    """Displays stored gaming credentials"""
    
    def __init__(self, parent, credential, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.credential = credential
        
        # Create title
        self.view_label = tk.Label(self,
                                 text="Your Gaming Credentials",
                                 font=("Arial", 16))
        self.view_label.pack(pady=10)
        
        # Create display frame
        self.cred_frame = tk.Frame(self)
        self.cred_frame.pack(pady=10, padx=20)
        
        # Labels for displaying credentials
        self.twitch_header = tk.Label(self.cred_frame, text="Twitch Credentials:", font=("Arial", 12, "bold"))
        self.twitch_header.pack(pady=5)
        self.twitch_username_label = tk.Label(self.cred_frame, text="Username:")
        self.twitch_username_label.pack(pady=2)
        self.twitch_username_value = tk.Label(self.cred_frame, text="")
        self.twitch_username_value.pack(pady=2)
        self.twitch_password_label = tk.Label(self.cred_frame, text="Password:")
        self.twitch_password_label.pack(pady=2)
        self.twitch_password_value = tk.Label(self.cred_frame, text="")
        self.twitch_password_value.pack(pady=5)
        
        self.discord_header = tk.Label(self.cred_frame, text="Discord Credentials:", font=("Arial", 12, "bold"))
        self.discord_header.pack(pady=5)
        self.discord_username_label = tk.Label(self.cred_frame, text="Username:")
        self.discord_username_label.pack(pady=2)
        self.discord_username_value = tk.Label(self.cred_frame, text="")
        self.discord_username_value.pack(pady=2)
        self.discord_password_label = tk.Label(self.cred_frame, text="Password:")
        self.discord_password_label.pack(pady=2)
        self.discord_password_value = tk.Label(self.cred_frame, text="")
        self.discord_password_value.pack(pady=5)
        
        self.steam_header = tk.Label(self.cred_frame, text="Steam Credentials:", font=("Arial", 12, "bold"))
        self.steam_header.pack(pady=5)
        self.steam_username_label = tk.Label(self.cred_frame, text="Username:")
        self.steam_username_label.pack(pady=2)
        self.steam_username_value = tk.Label(self.cred_frame, text="")
        self.steam_username_value.pack(pady=2)
        self.steam_password_label = tk.Label(self.cred_frame, text="Password:")
        self.steam_password_label.pack(pady=2)
        self.steam_password_value = tk.Label(self.cred_frame, text="")
        self.steam_password_value.pack(pady=5)
        
        # Back button
        self.back_button = tk.Button(
            self,
            text="Back to Credentials",
            command=lambda: self.parent.show_page("CredentialsPage"))
        self.back_button.pack(pady=10)
        
    def load_credentials(self):
        """Load and display stored credentials"""
        try:
            # Ensure we have a logged in user
            if not self.parent.logged_in_user:
                messagebox.showerror("Error", "No user is currently logged in")
                return
                
            # Get credentials from database
            self.parent.db.cursor.execute(
                "SELECT twitch, discord, steam FROM gaming_credentials WHERE username = ?",
                (self.parent.logged_in_user,))
            creds = self.parent.db.cursor.fetchone()
            
            if creds:
                # Decrypt and display credentials
                def decrypt_and_split(encrypted_cred):
                    if not encrypted_cred:
                        return ["Not set", "Not set"]
                    try:
                        decrypted = self.parent.db.decrypt(encrypted_cred)
                        if ':' in decrypted:
                            return decrypted.split(':')
                        return ["Invalid format", "Invalid format"]
                    except Exception:
                        return ["Decryption failed", "Decryption failed"]

                twitch_parts = decrypt_and_split(creds[0])
                discord_parts = decrypt_and_split(creds[1])
                steam_parts = decrypt_and_split(creds[2])
                
                # Update labels
                self.twitch_username_value.config(text=twitch_parts[0])
                self.twitch_password_value.config(text=twitch_parts[1])
                self.discord_username_value.config(text=discord_parts[0])
                self.discord_password_value.config(text=discord_parts[1])
                self.steam_username_value.config(text=steam_parts[0])
                self.steam_password_value.config(text=steam_parts[1])
            else:
                # Set "No credentials stored" for all fields
                self.twitch_username_value.config(text="No credentials stored")
                self.twitch_password_value.config(text="No credentials stored")
                self.discord_username_value.config(text="No credentials stored")
                self.discord_password_value.config(text="No credentials stored")
                self.steam_username_value.config(text="No credentials stored")
                self.steam_password_value.config(text="No credentials stored")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load credentials: {str(e)}")

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

        # Create and store all application pages
        self.pages = {
            "LandingPage": LandingPage(self),
            "CreateAccountPage": CreateAccountPage(self, self.user),
            "LoginPage": LoginPage(self, self.user),
            "CredentialsPage": CredentialsPage(self, self.credential),
            "SafeCommunicationPage": SafeCommunicationPage(self),
            "IncidentResponsePage": IncidentResponsePage(self),
            "TwoFactorPage": TwoFactorPage(self, self.user),
            "ViewCredentialsPage": ViewCredentialsPage(self, self.credential),
        }

    def show_page(self, page_name):
        """Manages page navigation by hiding all pages and showing the selected one"""
        for page in self.pages.values():
            page.grid_remove()
        self.pages[page_name].grid()


# Application entry point
if __name__ == "__main__":
    app = App()
    app.show_page("LandingPage")  # Show initial landing page
    app.mainloop()  # Start the application event loop
