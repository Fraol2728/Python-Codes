import os
import sys
import time
from cryptography.fernet import Fernet, InvalidToken
from colorama import Fore, Style
from getpass import getpass

# Hidden secure directory setup
SECURE_DIR = ".secure_data"
os.makedirs(SECURE_DIR, exist_ok=True)
if os.name == 'nt':  # Windows: hide folder
    os.system(f'attrib +h {SECURE_DIR}')

# File paths
key_path = os.path.join(SECURE_DIR, "thekey.txt")
pass_path = os.path.join(SECURE_DIR, "enc_pass.bin")

# Banner
print(Fore.RED + """ 
 _____       _ _   _____                _ 
| ____|_   _(_) | |  ___| __ __ _  ___ | |
|  _| \ \ / / | | | |_ | '__/ _` |/ _ \| |
| |___ \ V /| | | |  _|| | | (_| | (_) | |
|_____| \_/ |_|_| |_|  |_|  \__,_|\___/|_|
""" + Style.RESET_ALL)

print(Fore.GREEN + "\n=======What you want to do ?=======\n" + Style.RESET_ALL)
print("1, Encrypt your data")
print("2, Decryption your data")

# Recursive file search
def find_files_recursively(exclude_files, ext_filter=None):
    files = []
    for root, _, filenames in os.walk("."):
        for filename in filenames:
            full_path = os.path.join(root, filename)
            rel_path = os.path.relpath(full_path)
            if filename in exclude_files or rel_path.startswith(SECURE_DIR) or (ext_filter and not filename.endswith(ext_filter)):
                continue
            files.append(rel_path)
    return files

# Menu input
while True:
    options = input("\n Chose a Number only 1 or 2:   ")
    if options in ("1", "2"):
        break
    print(Fore.RED + "Please chose each one" + Style.RESET_ALL)

# ENCRYPTION
if options == "1":
    exclude_files = {"enc.py", "dec.py", "encryption_log.txt"}
    
    # Password creation (hidden)
    while True:
        password = getpass("Create a new password (min 4 chars): ")
        cpassword = getpass("Confirm password: ")
        if password != cpassword:
            print("❌ Passwords do not match. Try again.")
        elif len(password) < 4:
            print("❌ Password too short. Try again.")
        else:
            break

    print("\n⏳ Creating password", end="", flush=True)
    for _ in range(3): time.sleep(0.5); print(".", end="", flush=True)
    time.sleep(0.5)
    sys.stdout.write("\r" + " " * 50 + "\r")
    print("✅ Password created successfully!\n")

    # Load or create key
    if os.path.exists(key_path):
        with open(key_path, "r") as f: key = f.read().strip().encode()
        print("🔑 Loaded existing key.")
    else:
        key = Fernet.generate_key()
        with open(key_path, "w") as f: f.write(key.decode())
        print("🔑 Generated and saved new key.")

    fernet = Fernet(key)

    # Encrypt password
    with open(pass_path, "wb") as f:
        f.write(fernet.encrypt(password.encode()))
    print("🔒 Password encrypted and saved.\n")

    # Find files
    files_to_encrypt = find_files_recursively(exclude_files)

    print("\n🔍 Files to encrypt:")
    for file in files_to_encrypt: print(f" - {file}")
    input("\nPress Enter to start encryption...")

    start_time = time.time()

    for file in files_to_encrypt:
        with open(file, "rb") as f: data = f.read()
        encrypted = fernet.encrypt(data)
        with open(file + ".encrypted", "wb") as f: f.write(encrypted)
        os.remove(file)
        print(f"✅ Encrypted {file} -> {file}.encrypted")
        with open("encryption_log.txt", "a") as log:
            log.write(f"Encrypted: {file} -> {file}.encrypted\n")

    print("\n⏳ Finalizing encryption", end="", flush=True)
    for _ in range(3): time.sleep(0.5); print(".", end="", flush=True)
    sys.stdout.write("\r" + " " * 50 + "\r")
    print(f"✅ All files encrypted successfully!\n⏱️ Completed in {round(time.time() - start_time, 2)} seconds.")

# DECRYPTION
else:
    files_to_decrypt = find_files_recursively(set(), ext_filter=".encrypted")

    if not os.path.exists(key_path) or not os.path.exists(pass_path):
        print("❌ Missing key or password file. Cannot decrypt.")
        sys.exit(1)

    with open(key_path, "r") as f: key = f.read().strip().encode()
    with open(pass_path, "rb") as f: encrypted_password = f.read()

    fernet = Fernet(key)

    try:
        stored_password = fernet.decrypt(encrypted_password).decode()
    except InvalidToken:
        print("❌ Invalid key or corrupted password file.")
        sys.exit(1)

    attempts = 3
    while attempts > 0:
        user_pass = getpass("Enter password to decrypt files: ")
        print("\n⏳ Checking your password", end="", flush=True)
        for _ in range(3): time.sleep(0.5); print(".", end="", flush=True)
        sys.stdout.write("\r" + " " * 50 + "\r")
        if user_pass == stored_password:
            print("✅ Password correct!\n")
            break
        else:
            attempts -= 1
            print(f"❌ Incorrect password. {attempts} attempts left.")
    else:
        print("❌ Too many failed attempts. Exiting.")
        sys.exit(1)

    print("\n🔍 Files to decrypt:")
    for file in files_to_decrypt: print(f" - {file}")
    input("\nPress Enter to start decryption...")

    start_time = time.time()

    for file in files_to_decrypt:
        with open(file, "rb") as f: data = f.read()
        try:
            decrypted = fernet.decrypt(data)
        except InvalidToken:
            print(f"❌ Invalid token for file {file}. Skipping.")
            continue
        original = file.rsplit(".encrypted", 1)[0]
        with open(original, "wb") as f: f.write(decrypted)
        os.remove(file)
        print(f"✅ Decrypted {file} -> {original}")
        with open("encryption_log.txt", "a") as log:
            log.write(f"Decrypted: {file} -> {original}\n")

    print("\n⏳ Finalizing decryption", end="", flush=True)
    for _ in range(3): time.sleep(0.5); print(".", end="", flush=True)
    sys.stdout.write("\r" + " " * 50 + "\r")

    try:
        os.remove(key_path)
        os.remove(pass_path)
    except Exception as e:
        print(f"❌ Failed to delete secure files: {e}")

    print(f"\n✅ All files decrypted successfully!\n⏱️ Completed in {round(time.time() - start_time, 2)} seconds.")
