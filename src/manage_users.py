import argparse
import getpass
import json
import os

try:
    from .app import AUTH_USERS_FILE, hash_password, load_user_accounts
except ImportError:
    from app import AUTH_USERS_FILE, hash_password, load_user_accounts


def main():
    parser = argparse.ArgumentParser(description="Provision an activity-app account")
    parser.add_argument("username")
    parser.add_argument("email")
    parser.add_argument("--role", choices=("student", "admin"), required=True)
    arguments = parser.parse_args()

    accounts = load_user_accounts()
    if any(
        account.get("username", "").casefold() == arguments.username.casefold()
        or account.get("email", "").casefold() == arguments.email.casefold()
        for account in accounts
    ):
        parser.error("That username or email is already registered")

    password = getpass.getpass("Password (minimum 12 characters): ")
    confirmation = getpass.getpass("Confirm password: ")
    if len(password) < 12:
        parser.error("Passwords must be at least 12 characters")
    if password != confirmation:
        parser.error("Passwords do not match")

    accounts.append(
        {
            "username": arguments.username,
            "email": arguments.email,
            "role": arguments.role,
            "password_hash": hash_password(password),
        }
    )
    AUTH_USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    temporary_file = AUTH_USERS_FILE.with_name(AUTH_USERS_FILE.name + ".tmp")
    with temporary_file.open("w", encoding="utf-8") as account_file:
        json.dump(accounts, account_file, indent=2)
        account_file.write("\n")
    os.chmod(temporary_file, 0o600)
    temporary_file.replace(AUTH_USERS_FILE)
    print(f"Created {arguments.role} account for {arguments.username}")


if __name__ == "__main__":
    main()
