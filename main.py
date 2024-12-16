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


class User:

    def __init__(self, db):
        self.db = db

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

    def login(self, username, password):
        """Logs in an existing user."""
        if username == "admin" and password == "admin":
            return "admin"

        if self.db.verify_login(username, password):
            self.two_factor_code = self.generate_two_factor_code()
            return username
        else:
            messagebox.showerror("Login Failed", "Invalid username or password")
            return None


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
        self.create_tables()

    def create_tables(self):
        """Creates the database tables if they don't exist."""
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                              username TEXT PRIMARY KEY,
                              password_hash TEXT)''')
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS gaming_credentials (
                              username TEXT,
                              twitch TEXT,
                              discord TEXT,
                              steam TEXT,
                              FOREIGN KEY (username) REFERENCES users(username))'''
                            )
        self.connection.commit()

    def is_duplicate(self, username):
        """Checks for duplicate username."""
        self.cursor.execute("SELECT username FROM users WHERE username = ?",
                            (username, ))
        duplicate = self.cursor.fetchone()
        return duplicate is not None

    def verify_login(self, username, password):
        """Verifies login credentials."""
        self.cursor.execute(
            "SELECT * FROM users WHERE username = ? AND password_hash = ?",
            (username, hashed_password))  # Use the hashed password for comparison
        result = self.cursor.fetchone()
        return result is not None

    def store_credentials(self, username, password):
        """Stores user credentials (hashed password)."""
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        self.cursor.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, hashed_password))
        self.connection.commit()
    def store_gaming_credentials(self, username, twitch, discord, steam):
        """Stores gaming credentials in the database."""
        if twitch:
            twitch = hashlib.sha256(twitch.encode()).hexdigest()
        if discord:
            discord = hashlib.sha256(discord.encode()).hexdigest()
        if steam:
            steam = hashlib.sha256(steam.encode()).hexdigest()

        self.cursor.execute(
            '''INSERT INTO gaming_credentials (username, twitch, discord, steam) 
                          VALUES (?, ?, ?, ?)''',
            (username, twitch, discord, steam))
        self.connection.commit()



    def close(self):
        """Closes the database connection."""
        self.connection.close()


class Page(tk.Frame):

    def __init__(self, parent, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.parent = parent
        self.grid(row=0, column=0, sticky="nsew")


class LandingPage(Page):

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


class CreateAccountPage(Page):

    def __init__(self, parent, user, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.user = user

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

        # Password strength instructions
        self.password_instructions = tk.Label(
            self,
            text=("Password Strength Requirements:\n"
                  "1. At least 8 characters long (Strong if 13+)\n"
                  "2. At least 1 uppercase and 1 lowercase letter\n"
                  "3. At least 1 number and 1 symbol"),
        )
        self.password_instructions.pack(pady=5)

        # Password Strength Label
        self.password_strength_label_create = tk.Label(self, text="")
        self.password_strength_label_create.pack(pady=5)

        # Bind password entry to strength evaluation
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
        """Handles user login."""
        username = self.username_entry_login.get()
        password = self.password_entry_login.get()

        logged_in_user = self.user.login(username, password)
        if logged_in_user:
            if logged_in_user == "admin":
                self.parent.show_page("CredentialsPage")
            else:
                code = self.user.generate_two_factor_code()
                messagebox.showinfo("2FA Code", f"Your 2FA code is: {code}")
                self.parent.show_page("TwoFactorPage")


class CredentialsPage(Page):

    def __init__(self, parent, credential, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.credential = credential

        self.credentials_label = tk.Label(self,
                                          text="Enter Your Gaming Credentials",
                                          font=("Arial", 16))
        self.credentials_label.pack(pady=10)

        # Twitch
        self.twitch_label = tk.Label(self, text="Twitch Username:")
        self.twitch_label.pack(pady=5)
        self.twitch_entry = tk.Entry(self)
        self.twitch_entry.pack(pady=5)
        self.twitch_label = tk.Label(self, text="Twitch Password:")
        self.twitch_label.pack(pady=5)
        self.twitch_entry = tk.Entry(self, show="*")
        self.twitch_entry.pack(pady=5)

        # Discord
        self.discord_label = tk.Label(self, text="Discord Username:")
        self.discord_label.pack(pady=5)
        self.discord_entry = tk.Entry(self)
        self.discord_entry.pack(pady=5)
        self.discord_label = tk.Label(self, text="Discord Password:")
        self.discord_label.pack(pady=5)
        self.discord_entry = tk.Entry(self, show="*")
        self.discord_entry.pack(pady=5)

        # Steam
        self.steam_label = tk.Label(self, text="Steam Username:")
        self.steam_label.pack(pady=5)
        self.steam_entry = tk.Entry(self)
        self.steam_entry.pack(pady=5)
        self.steam_label = tk.Label(self, text="Steam Password:")
        self.steam_label.pack(pady=5)
        self.steam_entry = tk.Entry(self, show="*")
        self.steam_entry.pack(pady=5)

        # Store Button
        self.store_button = tk.Button(self,
                                      text="Store Credentials",
                                      command=self.store_gaming_credentials)
        self.store_button.pack(pady=20)

        # Navigation buttons to other pages
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

        # Logout Button
        self.logout_button = tk.Button(
            self.nav_frame,
            text="Logout",
            command=lambda: self.parent.show_page("LandingPage"))
        self.logout_button.pack(side="left", padx=5)

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
        self.safe_communication_label = tk.Label(
            self, text="Safe Communication Practices", font=("Arial", 16))
        self.safe_communication_label.pack(pady=10)

        # Back button to credentials page
        self.back_to_credentials_button_safe = tk.Button(
            self,
            text="Back to Credentials",
            command=lambda: self.parent.show_page("CredentialsPage"),
        )
        self.back_to_credentials_button_safe.pack(pady=10)


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

        # Initialize database
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

        # Show the first page
        self.show_page("LandingPage")

    def show_page(self, page_name):
        """Shows the specified page."""
        for frame in self.pages.values():
            frame.grid_remove()

        self.pages[page_name].grid()
        self.pages[page_name].tkraise()


# Database setup function
def create_database():
    connection = sqlite3.connect("CyberEsportsApp.db")
    cursor = connection.cursor()
    # Create tables if they don't exist
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                      username TEXT PRIMARY KEY,
                      password_hash TEXT)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS gaming_credentials (
                      username TEXT,
                      twitch TEXT,
                      discord TEXT,
                      steam TEXT,
                      FOREIGN KEY (username) REFERENCES users(username))''')
    connection.commit()
    connection.close()


# Call the function at the start of your application
create_database()


# Function to evaluate password strength
def evaluate_password(password):
    if len(password) < 8:
        return "Invalid"

    length = len(password)
    upper_case = len(re.findall(r'[A-Z]', password))
    lower_case = len(re.findall(r'[a-z]', password))
    numbers = len(re.findall(r'[0-9]', password))
    symbols = len(re.findall(r'[!@#$%^&*(),.?":{}|<>]', password))

    if length >= 13 and upper_case >= 1 and lower_case >= 1 and numbers >= 1 and symbols >= 1:
        return "Strong"
    elif length >= 8 and upper_case >= 1 and lower_case >= 1 and numbers >= 1 and symbols >= 1:
        return "Weak"
    else:
        return "Invalid"


# Function to check for duplicate username
def is_duplicate(username):
    connection = sqlite3.connect("CyberEsportsApp.db")
    cursor = connection.cursor()
    cursor.execute("SELECT username FROM users WHERE username = ?",
                   (username, ))
    duplicate = cursor.fetchone()
    connection.close()
    return duplicate is not None


# Function to verify login credentials
def verify_login(username, password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    connection = sqlite3.connect("CyberEsportsApp.db")
    cursor = connection.cursor()
    cursor.execute(
        "SELECT * FROM users WHERE username = ? AND password_hash = ?",
        (username, hashed_password))
    result = cursor.fetchone()
    connection.close()
    return result is not None

class TwoFactorPage(Page):
    def __init__(self, parent, user, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.user = user

        self.two_factor_label = tk.Label(self, text="Two-Factor Authentication", font=("Arial", 16))
        self.two_factor_label.pack(pady=10)

        self.instruction_label = tk.Label(self, text="Enter the 4-digit code sent to you:")
        self.instruction_label.pack(pady=5)

        self.code_entry = tk.Entry(self)
        self.code_entry.pack(pady=5)

        self.verify_button = tk.Button(self, text="Verify", command=self.verify_code)
        self.verify_button.pack(pady=20)

    def verify_code(self):
        entered_code = self.code_entry.get()
        if entered_code == self.user.two_factor_code:
            self.parent.show_page("CredentialsPage")
        else:
            messagebox.showerror("Verification Failed", "Invalid code. Please try again.")



# Function to securely store user credentials (hashed password) in SQLite
def store_credentials(username, password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    connection = sqlite3.connect("CyberEsportsApp.db")
    cursor = connection.cursor()
    cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                   (username, hashed_password))
    connection.commit()
    connection.close()


# Function to create account and log in automatically
def create_account():
    global logged_in_user
    username = username_entry_create.get()
    password = password_entry_create.get()

    # Check for duplicate username
    if is_duplicate(username):
        messagebox.showerror("Account Creation Failed",
                             "Username already in use.")
        return

    # Check if password strength is valid
    password_strength = evaluate_password(password)
    if password_strength == "Invalid":
        messagebox.showerror(
            "Account Creation Failed",
            "Your password is invalid. Please follow the instructions to create a stronger password."
        )
        return

    store_credentials(username, password)
    logged_in_user = username
    show_credentials_page()  # Automatically log in after account creation


# Function to log in
def login():
    global logged_in_user
    username = username_entry_login.get()
    password = password_entry_login.get()

    # Check for admin bypass
    if username == "admin" and password == "admin":
        logged_in_user = username
        # You can redirect to an admin page here
        show_credentials_page()  # Create this function to show the admin page
        return

    if verify_login(username, password):
        logged_in_user = username
        show_credentials_page()  # Redirect to credentials page
    else:
        messagebox.showerror("Login Failed", "Invalid username or password")


# Function to store gaming credentials (Twitch, Discord, Steam) in SQLite
def store_gaming_credentials():
    if not logged_in_user:
        messagebox.showerror("Error", "No user is currently logged in.")
        return

    twitch = twitch_entry.get()
    discord = discord_entry.get()
    steam = steam_entry.get()

    # Check if all fields are empty
    if not twitch and not discord and not steam:
        messagebox.showerror(
            "Input Error",
            "Please fill in at least one field for gaming credentials.")
        return

    connection = sqlite3.connect("CyberEsportsApp.db")
    cursor = connection.cursor()
    cursor.execute(
        '''INSERT INTO gaming_credentials (username, twitch, discord, steam) 
                      VALUES (?, ?, ?, ?)''',
        (logged_in_user, twitch, discord, steam))
    connection.commit()
    connection.close()

    messagebox.showinfo("Success", "Gaming credentials stored successfully!")


# Function to show password strength feedback during account creation
def update_password_strength_create(event=None):
    password = password_entry_create.get()
    password_strength = evaluate_password(password)

    if password_strength == "Strong":
        password_strength_label_create.config(text="Password Strength: Strong",
                                              fg="green")
    elif password_strength == "Weak":
        password_strength_label_create.config(text="Password Strength: Weak",
                                              fg="orange")
    else:
        password_strength_label_create.config(
            text="Password Strength: Invalid", fg="red")


# Function to switch to the landing page
def show_landing_page():
    landing_frame.tkraise()


# Function to switch to the create account page
def show_create_account_page():
    create_account_frame.tkraise()


# Function to switch to the login page
def show_login_page():
    login_frame.tkraise()


# Function to switch to the credentials page
def show_credentials_page():
    credentials_frame.tkraise()


# Function to switch to safe communication practices page
def show_safe_communication_page():
    safe_communication_frame.tkraise()


# Function to switch to incident response page
def show_incident_response_page():
    incident_response_frame.tkraise()


# Function to log out
def logout():
    global logged_in_user
    logged_in_user = None
    show_landing_page()  # Go back to the landing page


# Main app window
root = tk.Tk()
root.title("Cyber Esports App")
root.geometry("400x600")

# Frames for each page
landing_frame = tk.Frame(root)
create_account_frame = tk.Frame(root)
login_frame = tk.Frame(root)
credentials_frame = tk.Frame(root)
safe_communication_frame = tk.Frame(root)
incident_response_frame = tk.Frame(root)

for frame in (landing_frame, create_account_frame, login_frame,
              credentials_frame, safe_communication_frame,
              incident_response_frame):
    frame.grid(row=0, column=0, sticky="nsew")

# Landing Page
landing_label = tk.Label(landing_frame,
                         text="Welcome to Cyber Esports App",
                         font=("Arial", 16))
landing_label.pack(pady=20)

create_account_button = tk.Button(landing_frame,
                                  text="Create Account",
                                  command=show_create_account_page)
create_account_button.pack(pady=10)

login_button_landing = tk.Button(landing_frame,
                                 text="Login",
                                 command=show_login_page)
login_button_landing.pack(pady=10)

# Create Account Page
create_account_label = tk.Label(create_account_frame,
                                text="Create Account",
                                font=("Arial", 16))
create_account_label.pack(pady=10)

username_label_create = tk.Label(create_account_frame, text="Username:")
username_label_create.pack(pady=5)
username_entry_create = tk.Entry(create_account_frame)
username_entry_create.pack(pady=5)

password_label_create = tk.Label(create_account_frame, text="Password:")
password_label_create.pack(pady=5)
password_entry_create = tk.Entry(create_account_frame, show="*")
password_entry_create.pack(pady=5)

# Password strength instructions
password_instructions = tk.Label(
    create_account_frame,
    text=("Password Strength Requirements:\n"
          "1. At least 8 characters long (Strong if 13+)\n"
          "2. At least 1 uppercase and 1 lowercase letter\n"
          "3. At least 1 number and 1 symbol"))
password_instructions.pack(pady=5)

# Password Strength Label
password_strength_label_create = tk.Label(create_account_frame, text="")
password_strength_label_create.pack(pady=5)

# Bind password entry to strength evaluation
password_entry_create.bind("<KeyRelease>", update_password_strength_create)

create_account_button_final = tk.Button(create_account_frame,
                                        text="Create Account",
                                        command=create_account)
create_account_button_final.pack(pady=20)

back_to_landing_button = tk.Button(create_account_frame,
                                   text="Back",
                                   command=show_landing_page)
back_to_landing_button.pack(pady=10)

# Login Page
login_label = tk.Label(login_frame, text="Login", font=("Arial", 16))
login_label.pack(pady=10)

username_label_login = tk.Label(login_frame, text="Username:")
username_label_login.pack(pady=5)
username_entry_login = tk.Entry(login_frame)
username_entry_login.pack(pady=5)

password_label_login = tk.Label(login_frame, text="Password:")
password_label_login.pack(pady=5)
password_entry_login = tk.Entry(login_frame, show="*")
password_entry_login.pack(pady=5)

login_button_final = tk.Button(login_frame, text="Login", command=login)
login_button_final.pack(pady=20)

back_to_landing_button_login = tk.Button(login_frame,
                                         text="Back",
                                         command=show_landing_page)
back_to_landing_button_login.pack(pady=10)

# Credentials Page
credentials_label = tk.Label(credentials_frame,
                             text="Enter Your Gaming Credentials",
                             font=("Arial", 16))
credentials_label.pack(pady=10)

# Twitch
twitch_label = tk.Label(credentials_frame, text="Twitch Username:")
twitch_label.pack(pady=5)
twitch_entry = tk.Entry(credentials_frame)
twitch_entry.pack(pady=5)
twitch_label = tk.Label(credentials_frame, text="Twitch Password:")
twitch_label.pack(pady=5)
twitch_entry = tk.Entry(credentials_frame, show="*")
twitch_entry.pack(pady=5)

# Discord
discord_label = tk.Label(credentials_frame, text="Discord Username:")
discord_label.pack(pady=5)
discord_entry = tk.Entry(credentials_frame)
discord_entry.pack(pady=5)
discord_label = tk.Label(credentials_frame, text="Discord Password:")
discord_label.pack(pady=5)
discord_entry = tk.Entry(credentials_frame, show="*")
discord_entry.pack(pady=5)

# Steam
steam_label = tk.Label(credentials_frame, text="Steam Username:")
steam_label.pack(pady=5)
steam_entry = tk.Entry(credentials_frame)
steam_entry.pack(pady=5)
steam_label = tk.Label(credentials_frame, text="Steam Password:")
steam_label.pack(pady=5)
steam_entry = tk.Entry(credentials_frame, show="*")
steam_entry.pack(pady=5)

# Store Button
store_button = tk.Button(credentials_frame,
                         text="Store Credentials",
                         command=store_gaming_credentials)
store_button.pack(pady=20)

# Navigation buttons to other pages
nav_frame = tk.Frame(credentials_frame)
nav_frame.pack(pady=10)

safe_communication_button = tk.Button(nav_frame,
                                      text="Safe Communication Practices",
                                      command=show_safe_communication_page)
safe_communication_button.pack(side="left", padx=5)

incident_response_button = tk.Button(nav_frame,
                                     text="Incident Response",
                                     command=show_incident_response_page)
incident_response_button.pack(side="left", padx=5)

# Logout Button
logout_button = tk.Button(nav_frame, text="Logout", command=logout)
logout_button.pack(side="left", padx=5)

# Safe Communication Practices Page
safe_communication_label = tk.Label(safe_communication_frame,
                                    text="Safe Communication Practices",
                                    font=("Arial", 16))
safe_communication_label.pack(pady=10)

# Back button to credentials page
back_to_credentials_button_safe = tk.Button(safe_communication_frame,
                                            text="Back to Credentials",
                                            command=show_credentials_page)
back_to_credentials_button_safe.pack(pady=10)

# Incident Response Page
incident_response_label = tk.Label(incident_response_frame,
                                   text="Incident Response and Recovery Plans",
                                   font=("Arial", 16))
incident_response_label.pack(pady=10)

# Back button to credentials page
back_to_credentials_button_incident = tk.Button(incident_response_frame,
                                                text="Back to Credentials",
                                                command=show_credentials_page)
back_to_credentials_button_incident.pack(pady=10)

# Start with the landing page
show_landing_page()

# Run the main event loop
root.mainloop()
