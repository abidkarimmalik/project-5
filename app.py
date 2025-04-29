import streamlit as st
from cryptography.fernet import Fernet
import hashlib
import base64

# Initialize session state variables
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'current_user' not in st.session_state:
    st.session_state.current_user = None

# Constants
MAX_FAILED_ATTEMPTS = 3

def hash_passkey(passkey: str) -> str:
    """Hash the passkey using SHA-256."""
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(data: str, passkey: str) -> str:
    """Encrypt data using Fernet encryption."""
    # Generate a key from the passkey
    key = base64.urlsafe_b64encode(hashlib.sha256(passkey.encode()).digest())
    f = Fernet(key)
    return f.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data: str, passkey: str) -> str:
    """Decrypt data using Fernet decryption."""
    try:
        key = base64.urlsafe_b64encode(hashlib.sha256(passkey.encode()).digest())
        f = Fernet(key)
        return f.decrypt(encrypted_data.encode()).decode()
    except Exception:
        return None

def login_page():
    """Display the login page."""
    st.title("🔒 Secure Data System - Login")
    st.write("Please login to access the secure data system")
    
    username = st.text_input("Username")
    passkey = st.text_input("Passkey", type="password")
    
    if st.button("Login"):
        if username and passkey:
            hashed_passkey = hash_passkey(passkey)
            if username in st.session_state.stored_data:
                if st.session_state.stored_data[username]["passkey"] == hashed_passkey:
                    st.session_state.logged_in = True
                    st.session_state.current_user = username
                    st.session_state.failed_attempts = 0
                    st.rerun()
                else:
                    st.session_state.failed_attempts += 1
                    st.error(f"Invalid credentials! Attempts remaining: {MAX_FAILED_ATTEMPTS - st.session_state.failed_attempts}")
            else:
                st.error("User not found!")
        else:
            st.warning("Please enter both username and passkey")

def store_data_page():
    """Display the store data page."""
    st.title("📝 Store New Data")
    
    data_label = st.text_input("Data Label")
    data_content = st.text_area("Data Content")
    passkey = st.text_input("Passkey", type="password")
    
    if st.button("Store Data"):
        if data_label and data_content and passkey:
            if st.session_state.current_user not in st.session_state.stored_data:
                st.session_state.stored_data[st.session_state.current_user] = {
                    "passkey": hash_passkey(passkey),
                    "data": {}
                }
            
            encrypted_content = encrypt_data(data_content, passkey)
            st.session_state.stored_data[st.session_state.current_user]["data"][data_label] = encrypted_content
            st.success(f"Data stored successfully under label: {data_label}")
        else:
            st.warning("Please fill in all fields")

def retrieve_data_page():
    """Display the retrieve data page."""
    st.title("🔍 Retrieve Data")
    
    if st.session_state.current_user in st.session_state.stored_data:
        user_data = st.session_state.stored_data[st.session_state.current_user]["data"]
        
        if user_data:
            selected_label = st.selectbox("Select data to retrieve", list(user_data.keys()))
            passkey = st.text_input("Enter passkey", type="password")
            
            if st.button("Retrieve"):
                if passkey:
                    encrypted_data = user_data[selected_label]
                    decrypted_data = decrypt_data(encrypted_data, passkey)
                    
                    if decrypted_data:
                        st.text_area("Decrypted Data", decrypted_data, height=100)
                    else:
                        st.session_state.failed_attempts += 1
                        st.error(f"Invalid passkey! Attempts remaining: {MAX_FAILED_ATTEMPTS - st.session_state.failed_attempts}")
                else:
                    st.warning("Please enter your passkey")
        else:
            st.info("No data stored yet. Please store some data first.")
    else:
        st.info("No data available for this user.")

def main():
    # Check for failed attempts
    if st.session_state.failed_attempts >= MAX_FAILED_ATTEMPTS:
        st.session_state.logged_in = False
        st.session_state.current_user = None
        st.session_state.failed_attempts = 0
        st.error("Too many failed attempts. Please login again.")
        login_page()
        return
    
    if not st.session_state.logged_in:
        login_page()
    else:
        # Navigation
        st.sidebar.title("Navigation")
        page = st.sidebar.radio("Go to", ["Store Data", "Retrieve Data"])
        
        # Logout button
        if st.sidebar.button("Logout"):
            st.session_state.logged_in = False
            st.session_state.current_user = None
            st.rerun()
        
        if page == "Store Data":
            store_data_page()
        else:
            retrieve_data_page()

if __name__ == "__main__":
    main() 