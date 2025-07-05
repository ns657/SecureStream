import streamlit as st
import os
import json
import hashlib
import base64
import re
import random
import string
import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from hashlib import pbkdf2_hmac

# Constants for PBKDF2
SALT_FILE = "salt_data.txt"
VAULT_FILE = "password_vault.json"
ITERATIONS = 100_000  # Adjust for security-performance tradeoff

# Function to generate or load salt
def generate_or_load_salt():
    # Check if a salt file exists; if not, create one
    if os.path.exists(SALT_FILE):
        with open(SALT_FILE, "rb") as file:
            return file.read()
    # Generate a new salt and save it to a file
    salt = secrets.token_bytes(16)  
    with open(SALT_FILE, "wb") as file:
        file.write(salt)
    return salt

# Function to derive encryption key using PBKDF2
def derive_encryption_key(master_password):
    # Get the salt and derive the key
    salt = generate_or_load_salt()
    return pbkdf2_hmac('sha256', master_password.encode(), salt, ITERATIONS, dklen=32)

# Function to store and verify master password
def store_and_verify_master_password(master_password):
    # Hash the master password for secure storage
    hashed_password = hashlib.sha256(master_password.encode()).hexdigest()
    with open("master_password.txt", "w") as file:
        file.write(hashed_password)

def verify_master_password(input_password):
    # If no master password is stored, set the input as the master password
    if not os.path.exists("master_password.txt"):
        store_and_verify_master_password(input_password)
        return True
    # Compare the input password with the stored hash
    with open("master_password.txt", "r") as file:
        stored_hash = file.read().strip()
    return stored_hash == hashlib.sha256(input_password.encode()).hexdigest()

# Function to load and save vault
def load_password_vault():
    # Load existing vault data if available
    if os.path.exists(VAULT_FILE):
        with open(VAULT_FILE, "r") as file:
            return json.load(file)
    return {}

def save_password_vault(vault):
    # Save the vault data securely
    with open(VAULT_FILE, "w") as file:
        json.dump(vault, file, indent=4)

# Encryption and decryption functions
def encrypt_password_data(password, key):
    # Initialize AES cipher with a random IV
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    # Encrypt the password and combine it with the IV
    encrypted_password = cipher.encrypt(pad(password.encode(), AES.block_size))
    return base64.b64encode(iv + encrypted_password).decode()

def decrypt_password_data(encrypted_password, key):
    # Separate the IV from the encrypted password
    encrypted_password = base64.b64decode(encrypted_password)
    iv = encrypted_password[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # Decrypt and unpad the password
    return unpad(cipher.decrypt(encrypted_password[AES.block_size:]), AES.block_size).decode()

# Password strength checker
def evaluate_password_strength(password):
    # Check password length and composition
    if len(password) < 8:
        return "Weak"
    if not re.search(r"[A-Z]", password) or not re.search(r"[0-9]", password) or not re.search(r"[!@#$%^&*]", password):
        return "Medium"
    return "Strong"

# Generate strong password
def generate_strong_password():
    # Define the character set for strong passwords
    characters = string.ascii_letters + string.digits + "!@#$%^&*"
    while True:
        password = "".join(random.choice(characters) for _ in range(12))
        if evaluate_password_strength(password) == "Strong":
            return password

# Streamlit UI
st.title("🔒 Secure Password Manager")

# Initialize session state variables
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
    st.session_state.key = None
    st.session_state.vault = {}

# Master Password Authentication
if not st.session_state.authenticated:
    master_password = st.text_input("Enter Master Password:", type="password", key="master_password_input")

    if master_password:
        if verify_master_password(master_password):
            st.session_state.authenticated = True
            st.session_state.key = derive_encryption_key(master_password)
            st.session_state.vault = load_password_vault()
            st.success("✅ Authentication successful!")
            del st.session_state["master_password_input"]
            st.rerun()
        else:
            st.error("⚠ Incorrect master password! Please try again.")

# If authenticated, show options
if st.session_state.authenticated:
    option = st.selectbox("Choose an action:", ["Store Password", "Retrieve Password"])
    vault = st.session_state.vault
    key = st.session_state.key

    if option == "Store Password":
        site = st.text_input("Enter site name:")

        if "generated_password" not in st.session_state:
            st.session_state.generated_password = ""

        password = st.text_input("Enter password:", type="password", value=st.session_state.generated_password, key="password_input")

        if st.button("Generate a Strong Password"):
            st.session_state.generated_password = generate_strong_password()
            st.rerun()

        if st.session_state.generated_password:
            st.text_input("Generated Password:", st.session_state.generated_password, disabled=True)

        if st.button("Check Strength"):
            strength = evaluate_password_strength(password)
            if strength == "Weak":
                st.error("❌ Weak password! Please use a stronger one.")
            elif strength == "Medium":
                st.warning("⚠ Medium strength. Try adding uppercase, numbers, and symbols.")
            else:
                st.success("✅ Strong password!")

        if st.button("Save Password"):
            strength = evaluate_password_strength(password)
            if strength == "Weak":
                st.error("❌ Password is too weak. Please choose a stronger one!")
            else:
                vault[site] = encrypt_password_data(password, key)
                save_password_vault(vault)
                st.success("✅ Password stored securely!")

    elif option == "Retrieve Password":
        retrieve_auth = st.text_input("Re-enter Master Password:", type="password", key="retrieve_auth_input")

        if retrieve_auth:
            if verify_master_password(retrieve_auth):
                site = st.text_input("Enter site name:")
                if st.button("Retrieve Password"):
                    if site in vault:
                        try:
                            decrypted_password = decrypt_password_data(vault[site], key)
                            st.success(f"🔑 Password for {site}:")
                            st.text_input("Copy Password:", decrypted_password, disabled=True)
                        except:
                            st.error("⚠ Decryption failed! Ensure the correct master password is used.")
                    else:
                        st.error("⚠ No password stored for this site.")
            else:
                st.error("⚠ Incorrect master password for retrieval!")