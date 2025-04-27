import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# --- Fixed key (important for deployment) ---
KEY = b'M5Uv6U0c1z9MLbht3UpOTvAx9xBdxFzOPh2_YFD6T1A='  # Fixed base64 key
cipher = Fernet(KEY)

stored_data = {}
failed_attempts = 0

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text, passkey):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    global failed_attempts
    hashed_passkey = hash_passkey(passkey)

    for value in stored_data.values():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed_passkey:
            failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()

    failed_attempts += 1
    return None

# --- Streamlit UI starts here ---
st.set_page_config(page_title="Secure Vault", page_icon="🔐")

st.title("🔐 Secure Vault: Encrypt & Retrieve Your Secrets")

menu = ["🏠 Dashboard", "📝 Encrypt Data", "🔍 Decrypt Data", "🔑 Login"]
choice = st.sidebar.selectbox("📂 Navigate", menu)

if choice == "🏠 Dashboard":
    st.subheader("🧊 Welcome to Your Personal Vault")
    st.write("✨ Encrypt your text and protect it with a passkey. Retrieve it only with the correct key.")

elif choice == "📝 Encrypt Data":
    st.subheader("🧾 Encrypt New Secret")
    user_data = st.text_area("🗒️ Enter Text You Want to Secure:")
    passkey = st.text_input("🔐 Choose a Secret Passkey:", type="password")

    if st.button("📦 Encrypt & Store"):
        if user_data and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data, passkey)
            stored_data[encrypted_text] = {"encrypted_text": encrypted_text, "passkey": hashed_passkey}
            st.success("✅ Your secret has been stored safely!")
            st.code(encrypted_text, language="text")
        else:
            st.error("⚠️ Please fill in both fields!")

elif choice == "🔍 Decrypt Data":
    st.subheader("🔓 Access Your Secret")
    encrypted_text = st.text_area("🔒 Paste the Encrypted Text:")
    passkey = st.text_input("🗝️ Enter Your Passkey:", type="password")

    if st.button("🔑 Decrypt"):
        if encrypted_text and passkey:
            decrypted_text = decrypt_data(encrypted_text, passkey)

            if decrypted_text:
                st.success("🟢 Decryption Successful!")
                st.code(decrypted_text, language="text")
            else:
                st.error(f"❌ Incorrect passkey! Attempts left: {3 - failed_attempts}")
                if failed_attempts >= 3:
                    st.warning("🚫 Too many failed attempts! Redirecting to login page.")
                    st.rerun()
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "🔑 Login":
    st.subheader("🔐 Admin Reauthorization")
    login_pass = st.text_input("🔏 Enter Master Password:", type="password")

    if st.button("🔓 Login"):
        if login_pass == "mal090":
            failed_attempts = 0
            st.success("✅ Login successful! Returning to decryption...")
            st.rerun()
        else:
            st.error("❌ Wrong master password!")
