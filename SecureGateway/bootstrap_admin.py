"""
bootstrap_admin.py -- One-time admin account creation
=========================================================
Self-service registration (REGISTER:<user>:<pass>) only ever creates
regular, read-only-by-default users. There is deliberately no way to
create an admin account over the wire, so the very first admin has to
be provisioned locally before aegis_firewall.py is started.

Run this once, on the same machine and in the same working directory
where aegis_firewall.py will run (they share aegis_auth.db):

    python bootstrap_admin.py

You can run it again later to add additional admin accounts.
"""

import getpass
import sys

import auth_db


def main():
    auth_db.init_db()
    print("=" * 60)
    print("  SecureGateway -- Admin Account Bootstrap")
    print("=" * 60)

    username = input("New admin username: ").strip()
    if not username:
        print("[!] Username cannot be empty.")
        sys.exit(1)

    password = getpass.getpass("New admin password: ")
    confirm = getpass.getpass("Confirm password: ")
    if not password:
        print("[!] Password cannot be empty.")
        sys.exit(1)
    if password != confirm:
        print("[!] Passwords did not match.")
        sys.exit(1)

    result = auth_db.register_admin(username, password)
    if result.ok:
        print(f"[+] {result.reason} You can now log in via admin_console.py.")
    else:
        print(f"[!] {result.reason}")
        sys.exit(1)


if __name__ == "__main__":
    main()
