"""
admin_console.py -- SecureGateway Admin Control Terminal
==========================================================
Now requires an admin login (see bootstrap_admin.py to create the
first admin account) before any admin command is accepted -- the old
version trusted anyone who could reach 127.0.0.1:8080 and prefix a
message with "ADMIN:". Uses the same persistent, framed connection
as client.py (see protocol.py).
"""

import getpass
import socket

from protocol import send_line_sync, recv_framed_sync

HOST = "127.0.0.1"
PORT = 8080


def connect():
    s = socket.socket()
    s.settimeout(10)
    s.connect((HOST, PORT))
    return s


def request(sock, message: str) -> str:
    try:
        send_line_sync(sock, message)
        resp = recv_framed_sync(sock)
        return resp if resp is not None else "[CONSOLE ERROR] Connection closed by server."
    except Exception as e:
        return f"[CONSOLE ERROR] {e}"


def admin_login(sock) -> bool:
    print("=" * 60)
    print("   AEGIS AI FIREWALL v3: SECURE ADMIN CONTROL TERMINAL")
    print("=" * 60)
    print("Connected to Firewall at 127.0.0.1:8080\n")

    for attempt in range(3):
        username = input("Admin username: ").strip()
        password = getpass.getpass("Admin password: ")
        resp = request(sock, f"ADMIN_LOGIN:{username}:{password}")
        print(resp)
        if resp.startswith("[ADMIN-AUTH] Login successful"):
            return True
        if "Locked" in resp or "locked" in resp:
            return False
    print("[!] Too many failed attempts. Exiting.")
    return False


def run_admin_console():
    try:
        sock = connect()
    except Exception as e:
        print(f"[!] Could not connect to firewall: {e}")
        return

    if not admin_login(sock):
        sock.close()
        return

    print("\nAvailable Admin Commands:")
    print("  - dossier                 : View immutable Merkle tree audit logs")
    print("  - status                  : View active internal user strikes & system health")
    print("  - revive <user>           : Clear AI-risk/permission strikes for a terminated user")
    print("  - retrain                 : Force Police Bot to retrain Spy models on attack history")
    print("  - grant <user> <r|w|x|d>  : Grant a permission (highest tier: d = destructive SQL)")
    print("  - revoke <user> <r|w|x|d> : Revoke a permission")
    print("  - perms <user>            : Show a user's current RWXD permissions")
    print("  - unlock <user> [user|admin] : Clear a login lockout (default: user)")
    print("  - listusers               : List all registered users and their permissions")
    print("  - exit                    : Close admin console\n")

    while True:
        try:
            cmd = input("Admin-Terminal> ").strip()
            if not cmd:
                continue
            if cmd.lower() == "exit":
                print("[*] Exiting Admin Console.")
                break

            resp = request(sock, f"ADMIN:{cmd}")
            print("\n[Server Response]")
            print(resp)
            print("-" * 60)

        except (KeyboardInterrupt, EOFError):
            print("\n[*] Exiting Admin Console.")
            break
        except Exception as e:
            print(f"[!] Connection Error: {e}")
            break

    try:
        sock.close()
    except Exception:
        pass


if __name__ == "__main__":
    run_admin_console()
