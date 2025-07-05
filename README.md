# 🔐 SecureStream: A Streamlit-Based Password Manager

SecureStream is a lightweight, interactive password manager built using [Streamlit](https://streamlit.io/) and strong encryption practices. It enables users to securely store, generate, and retrieve passwords, all within a simple browser-based interface.

## ✨ Features
- 🔑 Master password authentication
- 🧂 Salted key derivation using PBKDF2-HMAC-SHA256
- 🔒 AES encryption for password storage (CBC mode)
- 📁 Secure local storage using JSON vault
- 🧠 Password strength evaluation (weak, medium, strong)
- 🔧 One-click strong password generator
- ✅ User-friendly UI powered by Streamlit

## 🛠️ Tech Stack
- Python
- Streamlit
- Cryptography (PyCryptodome)
- JSON for secure vault
- PBKDF2 + AES (CBC) for encryption

## 🚀 Getting Started

```bash
pip install streamlit pycryptodome
streamlit run pwd_streamlit.py
