#REMOVE ADMIN ACCESS!!!
#FORMAT THE CRDENTIALS PAGE CORRECTLY
#ADD CONTENT TO SAFE COMMUNCATION AND IR PAGE
#ADD 2FA
#encrypt CREDENTIALS

import tkinter as tk
from tkinter import messagebox
import hashlib
import re
import sqlite3
import os
import random
from cryptography.fernet import Fernet


class User:

    def __init__(self, db):
        self.db = db
        self.two_factor_code = None

    def create_account(self, username, password):
        """Creates a new user account."""
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
        """Generates a random 4-digit code."""
        self.two_factor_code = str(random.randint(1000, 9999))
        return self.two_factor_code

    def evaluate_password(self, password):
        """Evaluates password strength."""
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
        username = self.username_entry_login.get()
        password = self.password_entry_login.get()

        # Hash the password to compare it with the stored hashed password
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        # Verify login credentials from the database
        if self.db.verify_login(username, hashed_password):
            # Generate and store 2FA code
            two_factor_code = self.generate_two_factor_code()
            print(f"Your 2FA code is: {two_factor_code}") 

            # Store the 2FA code in the User object
            self.user.two_factor_code = two_factor_code

            # Show the TwoFactorPage for entering the 2FA code
            self.parent.show_page("TwoFactorPage")
        else:
            messagebox.showerror("Login Failed", "Invalid username or password.")




class Credential:

    def __init__(self, db):
        self.db = db

    def store_gaming_credentials(self, username, twitch, discord, steam):
        """Stores gaming credentials for the user."""
        if not twitch and not discord and not steam:
            messagebox.showerror(
                "Input Error",
                "Please fill in at least one field for gaming credentials.")
            return

        self.db.store_gaming_credentials(username, twitch, discord, steam)
        messagebox.showinfo("Success",
                            "Gaming credentials stored successfully!")


class Database:
    def __init__(self, db_name="CyberEsportsApp.db"):
        self.connection = sqlite3.connect(db_name)
        self.cursor = self.connection.cursor()
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)
        self.create_tables()

    def create_tables(self):
        """Creates the necessary database tables if they don't exist."""
        # Create users table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL
            )
        ''')

        # Create gaming credentials table
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
        return self.cipher.encrypt(data.encode()).decode()

    def decrypt(self, data):
        return self.cipher.decrypt(data.encode()).decode()

    def verify_login(self, username, password):
        """Verifies login credentials."""
        self.cursor.execute(
            "SELECT * FROM users WHERE username = ? AND password_hash = ?",
            (username, password))
        result = self.cursor.fetchone()
        return result is not None

    def store_gaming_credentials(self, username, twitch, discord, steam):
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
        """Checks if username already exists."""
        self.cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
        return self.cursor.fetchone() is not None

    def close(self):
        """Close the database connection."""
        if self.connection:
            self.connection.close()

    def store_credentials(self, username, password):
        """Stores user credentials."""
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        self.cursor.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, hashed_password))
        self.connection.commit()




class Page(tk.Frame):

    def __init__(self, parent, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.parent = parent
        self.grid(row=0, column=0, sticky="nsew")
        
        # Configure grid weights to center content
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        
        # Create main container frame
        self.container = tk.Frame(self)
        self.container.grid(row=0, column=0, sticky="nsew")
        
        # Configure container grid
        self.container.grid_rowconfigure(0, weight=1)
        self.container.grid_columnconfigure(0, weight=1)


class LandingPage(Page):

    def __init__(self, parent, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.landing_label = tk.Label(self,
                                      text="Welcome to Cyber Esports App",
                                      font=("Arial", 16))
        self.landing_label.grid(row=0, column=0, pady=20)

        self.create_account_button = tk.Button(
            self,
            text="Create Account",
            command=lambda: self.parent.show_page("CreateAccountPage"))
        self.create_account_button.grid(row=1, column=0, pady=10)

        self.login_button_landing = tk.Button(
            self,
            text="Login",
            command=lambda: self.parent.show_page("LoginPage"))
        self.login_button_landing.grid(row=2, column=0, pady=10)

class TwoFactorPage(Page):
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
        entered_code = self.code_entry.get()

        # Check if the entered code matches the generated one
        if entered_code == self.user.two_factor_code:
            messagebox.showinfo("Success", "2FA Verified!")
            self.parent.show_page("CredentialsPage")  # Proceed to credentials page
        else:
            messagebox.showerror("Error", "Invalid 2FA Code")


class CreateAccountPage(Page):

    def __init__(self, parent, user, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.user = user

        current_row = 0
        
        self.create_account_label = tk.Label(self,
                                             text="Create Account",
                                             font=("Arial", 16))
        self.create_account_label.grid(row=current_row, column=0, pady=10)
        current_row += 1

        self.username_label_create = tk.Label(self, text="Username:")
        self.username_label_create.grid(row=current_row, column=0, pady=5)
        current_row += 1
        
        self.username_entry_create = tk.Entry(self)
        self.username_entry_create.grid(row=current_row, column=0, pady=5)
        current_row += 1

        self.password_label_create = tk.Label(self, text="Password:")
        self.password_label_create.grid(row=current_row, column=0, pady=5)
        current_row += 1
        
        self.password_entry_create = tk.Entry(self, show="*")
        self.password_entry_create.grid(row=current_row, column=0, pady=5)
        current_row += 1

        # Password strength instructions
        self.password_instructions = tk.Label(
            self,
            text=("Password Strength Requirements:\n"
                  "1. At least 8 characters long (Strong if 13+)\n"
                  "2. At least 1 uppercase and 1 lowercase letter\n"
                  "3. At least 1 number and 1 symbol"),
        )
        self.password_instructions.grid(row=current_row, column=0, pady=5)
        current_row += 1

        # Password Strength Label
        self.password_strength_label_create = tk.Label(self, text="")
        self.password_strength_label_create.grid(row=current_row, column=0, pady=5)
        current_row += 1

        # Bind password entry to strength evaluation
        self.password_entry_create.bind("<KeyRelease>",
                                        self.update_password_strength_create)

        self.create_account_button_final = tk.Button(
            self, text="Create Account", command=self.create_account)
        self.create_account_button_final.grid(row=current_row, column=0, pady=20)
        current_row += 1

        self.back_to_landing_button = tk.Button(
            self,
            text="Back",
            command=lambda: self.parent.show_page("LandingPage"))
        self.back_to_landing_button.grid(row=current_row, column=0, pady=10)

    def update_password_strength_create(self, event=None):
        """Updates password strength feedback during account creation."""
        password = self.password_entry_create.get()
        password_strength = self.user.evaluate_password(password)

        if password_strength:
            self.password_strength_label_create.config(
                text="Password Strength: Strong", fg="green")
        else:
            self.password_strength_label_create.config(
                text="Password Strength: Invalid", fg="red")

    def create_account(self):
        """Handles account creation."""
        username = self.username_entry_create.get()
        password = self.password_entry_create.get()

        if self.user.create_account(username, password):
            self.parent.show_page(
                "CredentialsPage")  # Automatically log in after creation


class LoginPage(Page):

    def __init__(self, parent, user, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.user = user

        current_row = 0
        
        self.login_label = tk.Label(self, text="Login", font=("Arial", 16))
        self.login_label.grid(row=current_row, column=0, pady=10)
        current_row += 1

        self.username_label_login = tk.Label(self, text="Username:")
        self.username_label_login.grid(row=current_row, column=0, pady=5)
        current_row += 1
        
        self.username_entry_login = tk.Entry(self)
        self.username_entry_login.grid(row=current_row, column=0, pady=5)
        current_row += 1

        self.password_label_login = tk.Label(self, text="Password:")
        self.password_label_login.grid(row=current_row, column=0, pady=5)
        current_row += 1
        
        self.password_entry_login = tk.Entry(self, show="*")
        self.password_entry_login.grid(row=current_row, column=0, pady=5)
        current_row += 1

        self.login_button_final = tk.Button(self,
                                            text="Login",
                                            command=self.login)
        self.login_button_final.grid(row=current_row, column=0, pady=20)
        current_row += 1

        self.back_to_landing_button_login = tk.Button(
            self,
            text="Back",
            command=lambda: self.parent.show_page("LandingPage"))
        self.back_to_landing_button_login.grid(row=current_row, column=0, pady=10)

    def login(self):
        username = self.username_entry_login.get()
        password = self.password_entry_login.get()

        # Hash the password to compare it with the stored hashed password
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        # Verify login credentials from the database
        if self.user.db.verify_login(username, hashed_password):
            # Generate and show 2FA code
            two_factor_code = self.user.generate_two_factor_code()
            messagebox.showinfo("2FA Code", f"Your verification code is: {two_factor_code}")
            self.parent.logged_in_user = username
            self.parent.show_page("TwoFactorPage")
        else:
            messagebox.showerror("Login Failed", "Invalid username or password.")


class CredentialsPage(Page):

    def __init__(self, parent, credential, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.credential = credential

        current_row = 0
        
        self.credentials_label = tk.Label(self,
                                          text="Enter Your Gaming Credentials",
                                          font=("Arial", 16))
        self.credentials_label.grid(row=current_row, column=0, columnspan=2, pady=10)
        current_row += 1

        # Twitch
        self.twitch_label = tk.Label(self, text="Twitch Username:")
        self.twitch_label.grid(row=current_row, column=0, pady=5)
        self.twitch_entry = tk.Entry(self)
        self.twitch_entry.grid(row=current_row, column=1, pady=5)
        current_row += 1
        
        self.twitch_pass_label = tk.Label(self, text="Twitch Password:")
        self.twitch_pass_label.grid(row=current_row, column=0, pady=5)
        self.twitch_pass_entry = tk.Entry(self, show="*")
        self.twitch_pass_entry.grid(row=current_row, column=1, pady=5)
        current_row += 1

        # Discord
        self.discord_label = tk.Label(self, text="Discord Username:")
        self.discord_label.grid(row=current_row, column=0, pady=5)
        self.discord_entry = tk.Entry(self)
        self.discord_entry.grid(row=current_row, column=1, pady=5)
        current_row += 1
        
        self.discord_pass_label = tk.Label(self, text="Discord Password:")
        self.discord_pass_label.grid(row=current_row, column=0, pady=5)
        self.discord_pass_entry = tk.Entry(self, show="*")
        self.discord_pass_entry.grid(row=current_row, column=1, pady=5)
        current_row += 1

        # Steam
        self.steam_label = tk.Label(self, text="Steam Username:")
        self.steam_label.grid(row=current_row, column=0, pady=5)
        self.steam_entry = tk.Entry(self)
        self.steam_entry.grid(row=current_row, column=1, pady=5)
        current_row += 1
        
        self.steam_pass_label = tk.Label(self, text="Steam Password:")
        self.steam_pass_label.grid(row=current_row, column=0, pady=5)
        self.steam_pass_entry = tk.Entry(self, show="*")
        self.steam_pass_entry.grid(row=current_row, column=1, pady=5)
        current_row += 1

        # Store Button
        self.store_button = tk.Button(self,
                                      text="Store Credentials",
                                      command=self.store_gaming_credentials)
        self.store_button.grid(row=current_row, column=0, columnspan=2, pady=20)
        current_row += 1

        # Navigation buttons frame
        self.nav_frame = tk.Frame(self)
        self.nav_frame.grid(row=current_row, column=0, columnspan=2, pady=10)

        self.safe_communication_button = tk.Button(
            self.nav_frame,
            text="Safe Communication Practices",
            command=lambda: self.parent.show_page("SafeCommunicationPage"),
        )
        self.safe_communication_button.grid(row=0, column=0, padx=5)

        self.incident_response_button = tk.Button(
            self.nav_frame,
            text="Incident Response",
            command=lambda: self.parent.show_page("IncidentResponsePage"),
        )
        self.incident_response_button.grid(row=0, column=1, padx=5)

        # Logout Button
        self.logout_button = tk.Button(
            self.nav_frame,
            text="Logout",
            command=lambda: self.parent.show_page("LandingPage"))
        self.logout_button.grid(row=0, column=2, padx=5)

    def store_gaming_credentials(self):
        """Handles storing gaming credentials."""
        twitch = self.twitch_entry.get()
        discord = self.discord_entry.get()
        steam = self.steam_entry.get()
        self.credential.store_gaming_credentials(self.parent.logged_in_user,
                                                 twitch, discord, steam)


class SafeCommunicationPage(Page):

    def __init__(self, parent, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        
        current_row = 0
        
        self.safe_communication_label = tk.Label(
            self, text="Safe Communication Practices", font=("Arial", 16))
        self.safe_communication_label.grid(row=current_row, column=0, pady=10)
        current_row += 1

        # Back button to credentials page
        self.back_to_credentials_button_safe = tk.Button(
            self,
            text="Back to Credentials",
            command=lambda: self.parent.show_page("CredentialsPage"),
        )
        self.back_to_credentials_button_safe.grid(row=current_row, column=0, pady=10)


class IncidentResponsePage(Page):

    def __init__(self, parent, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.incident_response_label = tk.Label(
            self,
            text="Incident Response and Recovery Plans",
            font=("Arial", 16),
        )
        self.incident_response_label.pack(pady=10)

        # Back button to credentials page
        self.back_to_credentials_button_incident = tk.Button(
            self,
            text="Back to Credentials",
            command=lambda: self.parent.show_page("CredentialsPage"),
        )
        self.back_to_credentials_button_incident.pack(pady=10)


class App(tk.Tk):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.title("Cyber Esports App")
        self.geometry("400x600")
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        self.logged_in_user = None

        # Initialise database
        self.db = Database()
        self.user = User(self.db)
        self.credential = Credential(self.db)

        # Create frames for each page
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
    # Hide all pages
        for page in self.pages.values():
            page.grid_remove()
    # Show the selected page
        self.pages[page_name].grid()


if __name__ == "__main__":
    app = App()
    app.show_page("LandingPage")  # Show the initial landing page
    app.mainloop()  # Start the main event loop
