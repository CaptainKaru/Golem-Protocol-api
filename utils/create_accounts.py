import re
import json
import getpass
from datetime import datetime
from uuid import uuid5, NAMESPACE_OID

import bcrypt

USERNAME = re.compile(r"^([a-z]+[a-z\d.]*){1,30}$")
PASSWORD = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[!-~]{8,16}$")

def encode_pw(pw):
 return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

def ask_password():
    while True:
        pw = getpass.getpass(" Enter password (8-16 chars): ").strip()
        if PASSWORD.fullmatch(pw):
            return pw

def load_accounts():
    with open("../data/mock-account-tbl.json") as file:
        return json.load(file)

def update_accounts(accounts):
    with open("../data/mock-account-tbl.json", "w", encoding="utf-8") as file:
        json.dump(accounts, file, indent=4)

def main():
    print("\nAccount Generator v1")
    print("\n[GUIDE]\n Hit <ENTER> after an empty username to end program.")
    print(" User level: 0 - Std user, 1 - Moderator, 2 - Admin, 3 - Super Admin")
    print(" Username: lowercase, starts with a-z then (alphanumeric and period).")
    print(" Password: contains at least 1 lowercase, " \
    "1 uppercase, 1 digit, and 1 special character (@$!%*?&)")
    print(" Use the same username to overwrite account.")

    accounts = load_accounts()
    while True:
        print("\n[New Account]")

        uname = input(" Username (1-15 chars): ")
        if not uname:
            break

        assert USERNAME.fullmatch(uname), "Invalid username."

        hashed = encode_pw(ask_password())
        user_level = input(" User level: ")[:1]
        full_name = input(" Full Name: ").strip()

        assert user_level in "0123", "Invalid user level."
        assert full_name, "Invalid name."

        account = {}
        account["id"] = str(uuid5(NAMESPACE_OID, uname))
        account["fullName"] = full_name
        account["hash"] = hashed
        account["userLevel"] = int(user_level)
        account["createdAt"] = int(datetime.now().timestamp())
        accounts[uname] = account
        update_accounts(accounts)

if __name__ == "__main__":
 main()