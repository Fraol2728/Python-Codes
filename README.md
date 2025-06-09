# 🔐 Secure File Encryptor

A Python-based command-line tool for securely encrypting and decrypting files with password protection and hidden key management.

---

## 🚀 Features

- 🔐 **Encrypt/Decrypt Any File** with AES (via `cryptography.fernet`)
- 🔑 **Password-Protected Encryption**
- 📁 **Recursive Encryption**: Encrypts all files in current and subdirectories
- 👁️ **Hidden Secure Folder**: Keys and password stored in `.secure_data/` (hidden)
- 🔒 **Key Auto-Management**: Automatically generates, stores, and loads encryption key
- ❌ **Failsafe**: Password and key files are deleted after decryption to prevent reuse
- ✅ **Cross-Platform Support** (Windows, macOS, Linux)
- 🪟 **Windows Hidden Folder Compatibility**
- 🧾 **Encryption Logging**: Actions are logged to `encryption_log.txt`
- ⏱️ **Animated UX**: Loading dots and status feedback

---

## 📦 Requirements

- Python 3.6+
- [cryptography](https://pypi.org/project/cryptography/)
- [colorama](https://pypi.org/project/colorama/)

Install dependencies:
```bash
pip install cryptography colorama
