"""
client.py -- SecureGateway External/Internal Traffic Test Harness
====================================================================
Two distinct ways of talking to the firewall live side by side here:

  1. The MAIN SESSION -- a single persistent, framed connection (see
     protocol.py) used for everything that goes through real
     authentication: REGISTER, LOGIN, CMD:<command>, LOGOUT. This is
     what a real client of SecureGateway looks like.

  2. RAW ATTACKER SOCKETS -- short-lived, unframed, one-shot sockets
     used only by the attacker-simulation tests. Real attackers don't
     speak our framing protocol, so these deliberately bypass it,
     exactly like the original test harness did.

Run this AFTER server.py and aegis_firewall.py are both running:
    Terminal 1:  python server.py
    Terminal 2:  python aegis_firewall.py
    Terminal 3:  python client.py
    (optional)   python admin_console.py   <- to inspect dossier/status/
                                               grant/revoke/unlock from the
                                               admin side while running
                                               tests here
"""

import socket
import threading
import time
import os

from protocol import send_line_sync, recv_framed_sync

HOST = "127.0.0.1"
PORT = 8080


# ----------------------------------------------------------------------
# MAIN SESSION -- one persistent, authenticated connection
# ----------------------------------------------------------------------
class Session:
    def __init__(self):
        self.sock = None
        self.username = None

    def connect(self):
        if self.sock:
            return
        self.sock = socket.socket()
        self.sock.settimeout(10)
        self.sock.connect((HOST, PORT))

    def request(self, message: str) -> str:
        self.connect()
        try:
            send_line_sync(self.sock, message)
            resp = recv_framed_sync(self.sock)
            return resp if resp is not None else "[CLIENT ERROR] Connection closed by server."
        except Exception as e:
            return f"[CLIENT ERROR] {e}"

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None
            self.username = None


session = Session()


def do_register():
    print("\n--- Register a new account ---")
    user = input("Choose a username: ").strip()
    pwd = input("Choose a password: ").strip()
    print(session.request(f"REGISTER:{user}:{pwd}"))
    print("(New accounts start with READ-only access. Ask an admin for more.)")


def do_login():
    print("\n--- Log in ---")
    user = input("Username: ").strip()
    pwd = input("Password: ").strip()
    resp = session.request(f"LOGIN:{user}:{pwd}")
    print(resp)
    if resp.startswith("[AUTH] Login successful"):
        session.username = user


def do_logout():
    print(session.request("LOGOUT"))
    session.username = None


def require_login():
    if not session.username:
        print("[!] You need to log in first (option 1 or 2 in the menu).")
        return False
    return True


# ----------------------------------------------------------------------
# AUTHENTICATED TEST CASES (go through the main session, CMD:<command>)
# ----------------------------------------------------------------------

def test_benign_command():
    if not require_login():
        return
    print("\n--- TEST: Benign Command (requires X / execute) ---")
    cmd = input("Command [e.g. python main.py]: ").strip() or "python main.py"
    print(session.request(f"CMD:{cmd}"))


def test_sql_read():
    if not require_login():
        return
    print("\n--- TEST: Read-only SQL on Backend BRICS DB (requires R) ---")
    print("Available tables: gdp_data, brics_debt_trade")
    cmd = input("SQL [e.g. select * from gdp_data]: ").strip() or "select * from gdp_data"
    print(session.request(f"CMD:{cmd}"))


def test_sql_write():
    if not require_login():
        return
    print("\n--- TEST: Write SQL (requires W) ---")
    cmd = input("SQL [e.g. insert into gdp_data values (...)]: ").strip() or "update gdp_data set gdp=0"
    print(session.request(f"CMD:{cmd}"))


def test_sql_destructive():
    if not require_login():
        return
    print("\n--- TEST: Destructive SQL (requires D -- highest privilege) ---")
    cmd = input("Destructive SQL [drop table gdp_data]: ").strip() or "drop table gdp_data"
    print(session.request(f"CMD:{cmd}"))


def test_out_of_privilege():
    if not require_login():
        return
    print("\n--- TEST: Deliberately Out-of-Privilege Action ---")
    print("Try a command your account shouldn't be allowed to run yet.")
    cmd = input("Command: ").strip() or "drop table gdp_data"
    print(session.request(f"CMD:{cmd}"))


def test_internal_escalation():
    if not require_login():
        return
    print("\n--- TEST: Internal Threat Escalation (Green -> Orange -> Red) ---")
    print("[1] Baseline benign command...")
    print(session.request("CMD:ls -la"))

    for i, cmd in enumerate(["cat /etc/passwd", "drop database production"], start=2):
        print(f"\n[{i}] Sending risky command: '{cmd}'")
        print(session.request(f"CMD:{cmd}"))

    print("\n[3] Retrying after termination (should now be blocked outright)...")
    print(session.request("CMD:ls -la"))

    print("\n[Tip] Open admin_console.py -> 'status' or 'dossier' to see the recorded strikes.")


def test_terminated_user_retry():
    if not require_login():
        return
    print("\n--- TEST: Retry as an already-terminated user ---")
    print(session.request("CMD:ls -la"))


# ----------------------------------------------------------------------
# UNAUTHENTICATED / RAW-SOCKET TEST CASES (attackers don't log in)
# ----------------------------------------------------------------------

def _raw_send_and_receive(payload: bytes, read_seconds=None, bufsize=4096, timeout=6):
    """Opens its own throwaway raw socket -- does NOT use the framed
    protocol, since real attackers won't either."""
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((HOST, PORT))
        s.sendall(payload)

        if read_seconds:
            end_time = time.time() + read_seconds
            chunks = []
            while time.time() < end_time:
                try:
                    data = s.recv(bufsize)
                    if not data:
                        break
                    chunks.append(data)
                except socket.timeout:
                    break
            resp = b"".join(chunks)
        else:
            resp = s.recv(bufsize)

        s.close()
        return resp.decode('utf-8', errors='ignore')
    except Exception as e:
        return f"[CLIENT ERROR] {e}"


def test_data_bombing_single_attacker():
    import sys
    # print("\n--- TEST: Single External Attacker / Data Bombardment ---")
    # print("Connecting as attacker, sending malicious payload, sampling stream for 3s...")
    # resp = _raw_send_and_receive(b"ATTACK: rm -rf /root\n", read_seconds=3)
    # print(resp[:2000])
    # print(f"... [{len(resp)} bytes received total during sample window]")
    print("\n--- TEST: Single External Attacker / Data Bombardment ---")
    print("Connecting as attacker, sending malicious payload, streaming response for 3s...")
    
    s = socket.socket()
    s.connect((HOST, PORT))
    s.setblocking(False) 
    payload = b"ATTACK: rm -rf /root\n"
    s.sendall(payload) 
    
    print("--- STREAM START ---")
    
    total_bytes = 0
    start_time = time.time()
    timeout = 3
    
    while time.time() - start_time < timeout:
        try:
            chunk = s.recv(2048)
            
            if not chunk:
                break
                
            total_bytes += len(chunk)
            print(chunk.decode('utf-8', errors='ignore'),end='')
            sys.stdout.flush()
            
        except BlockingIOError:
            time.sleep(0.01)
            continue
        except Exception as e:
            print(f"\n[Error during stream: {e}]")
            break

    print("\n--- STREAM END ---")
    print(f"... [{total_bytes} bytes received total during sample window]")



def test_entanglement_multi_attacker():
    print("\n--- TEST: Entanglement (Multiple Simultaneous Attackers) ---")
    payloads = [b"ATTACK: rm -rf /root\n", b"ATTACK: drop table users\n"]
    results = {}

    def worker(idx, payload):
        results[idx] = _raw_send_and_receive(payload, read_seconds=3)

    threads = [threading.Thread(target=worker, args=(i, p)) for i, p in enumerate(payloads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    for i, r in results.items():
        print(f"\n[Attacker {i + 1} stream sample -- look for CROSS-FEED FROM SWARM]")
        print(r[:800])


def test_radar_swarm():
    print("\n--- TEST: Radar / Turtle-Shell High-Volume Swarm Burst ---")
    n_threads = int(input("Number of concurrent bursts [5]: ").strip() or 5)
    per_thread = int(input("Requests per burst [20]: ").strip() or 20)

    def burst():
        for _ in range(per_thread):
            try:
                s = socket.socket()
                s.settimeout(2)
                s.connect((HOST, PORT))
                s.sendall(b"GET / HTTP/1.1\r\n\r\n")
                s.close()
            except Exception:
                pass

    threads = [threading.Thread(target=burst) for _ in range(n_threads)]
    start = time.time()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.time() - start
    print(f"Fired {n_threads * per_thread} rapid connections in {elapsed:.2f}s.")
    print("Check the firewall's own console for swarm detection + entanglement logs.")


def test_mixed_traffic():
    print("\n--- TEST: Mixed Legitimate + Illegitimate Traffic (identify & separate) ---")

    def legit(i):
        r = _raw_send_and_receive(f"GET /visitor{i} HTTP/1.1\r\n\r\n".encode())
        print(f"[web visitor {i}] {r.strip()[:150]}")

    def attacker(i):
        r = _raw_send_and_receive(f"ATTACK: rm -rf /dir{i}\n".encode(), read_seconds=1)
        print(f"[attacker{i}] streamed {len(r)} bytes back (entangled)")

    threads = []
    for i in range(5):
        threads.append(threading.Thread(target=legit, args=(i,)))
        threads.append(threading.Thread(target=attacker, args=(i,)))
    for t in threads:
        t.start()
    for t in threads:
        t.join()


MENU = """
=================== SECUREGATEWAY CLIENT TEST HARNESS ====================
 Account:
 1. Register a new account
 2. Log in
 3. Log out
 -----------------------------------------------------------------------
 Authenticated tests (require login, enforced by RWXD + AI risk model):
 4. Benign command (execute)
 5. Read-only SQL query
 6. Write SQL (insert/update)
 7. Destructive SQL (highest privilege)
 8. Deliberately try an out-of-privilege action
 9. Internal threat escalation (Green -> Orange -> Red)
10. Retry as an already-terminated user
 -----------------------------------------------------------------------
 Unauthenticated / attacker simulations (raw sockets, no login):
11. Single external attacker - data bombardment
12. Entanglement - multiple simultaneous attackers
13. Radar - high-volume swarm burst (Turtle Shell)
14. Mixed traffic - legitimate + illegitimate concurrently
 0. Exit
============================================================================
"""

ACTIONS = {
    "1": do_register,
    "2": do_login,
    "3": do_logout,
    "4": test_benign_command,
    "5": test_sql_read,
    "6": test_sql_write,
    "7": test_sql_destructive,
    "8": test_out_of_privilege,
    "9": test_internal_escalation,
    "10": test_terminated_user_retry,
    "11": test_data_bombing_single_attacker,
    "12": test_entanglement_multi_attacker,
    "13": test_radar_swarm,
    "14": test_mixed_traffic,
}


def main():
    os.system('cls' if os.name == 'nt' else 'clear')
    while True:
        status = f"logged in as '{session.username}'" if session.username else "not logged in"
        print(MENU)
        print(f"[{status}]")
        choice = input("Select test> ").strip()
        if choice == "0":
            print("[*] Exiting client test harness.")
            session.close()
            break
        action = ACTIONS.get(choice)
        if action:
            try:
                action()
            except Exception as e:
                print(f"[!] Test raised an error: {e}")
        else:
            print("[!] Invalid choice.")


if __name__ == "__main__":
    main()
