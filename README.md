# WAF Network Security Simulator -- Prototype 1 (increment 2)

A PySide6 control and visualization layer over the existing SecureGateway
CLI backend. The backend programs run **unmodified** as managed
subprocesses (the only backend changes are `server.py`'s DB-engine switch and
the new `mock_mysql.py`). See `SRS_WAF_Simulator_Prototype1.docx`.

## What increment 2 adds

| Area | What you get |
|---|---|
| **Network Topology** | Client -> Firewall -> Server -> MySQL diagram. Colours are real: process state for Client/Firewall/Server, and the server's own startup lines for the MySQL node (Mock DB / Connected / Unreachable). Status colours only, no traffic animation. |
| **Dossier Viewer** | Live view of `aegis_dossier.json` with a filter box. It independently recomputes every entry hash and the Merkle root, and shows **VERIFIED** or **TAMPERING DETECTED** (with the ids of altered entries). Read-only. |
| **Status bar** | Per-process state + MySQL state + Admin-derived counts (registered / warned / terminated / locked users, allowed / blocked events). |
| **Password masking** | When a prompt mentions "password", the input box masks typing and the terminal echo shows `********`. The password never enters the terminal document, so it can't appear in an export. This replaces the plain-text trade-off from increment 1. |
| **Log tools** | Red/amber/green line colouring (display only), per-terminal *Export Log...*, *File > Export All Logs*, *Edit > Clear Logs*. |
| **Menus** | New Simulation, Restart Network, Documentation (F1), View Dossier, Refresh Admin Status (+ 10 s auto-refresh). |
| **Fixes** | Stopping a process yourself now shows *Offline* (it used to show *Crashed*); Stop no longer freezes the window; a stale kill timer can't kill a restarted process. |

### How the Admin counts work
Per your decision, counts are parsed from the Admin console's own `status`
and `listusers` output, so they need an open, logged-in Admin session. Use
**Security > Refresh Admin Status** (or tick auto-refresh). The GUI echoes
each command it sends into the Admin Terminal as `> status   (sent by GUI)`,
so nothing is ever sent silently.

## Folder layout

```
waf_simulator/
├── main.py                          Main window
├── requirements.txt
├── controllers/                     QProcess wrappers
├── gui/
│   ├── widgets/  terminal_widget.py  topology_widget.py  dossier_viewer.py
│   └── dialogs/  working_dir_dialog.py  server_config_dialog.py
├── gui_helpers/admin_console_launcher.py   getpass -> input shim (admin_console.py untouched)
├── utils/  config_manager.py  admin_status.py  dossier_reader.py
└── server_patch/  server.py  mock_mysql.py  <- the ONLY files to copy into your project
```

## Setup

1. Copy `server_patch/server.py` and `server_patch/mock_mysql.py` into your
   SecureGateway project folder (back up your old `server.py`). Running
   `python server.py` with no arguments still behaves as before.
2. Run once, in a normal terminal in that folder: `python bootstrap_admin.py`.
3. Then:

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

4. **Edit > Working Directory**: choose your project folder.

## Typical session
1. **Start Firewall**, then **Start Server** (config dialog opens; Mock DB is the safe default).
2. Wait for the Firewall node to turn green, then **Connect Client** / **Open Admin Terminal**.
3. Register and log in on the Client; log in on the Admin; `grant <user> x`, etc.
4. Watch the Dossier Viewer verify each new entry; use Refresh Admin Status for counts.

## Verified so far
A headless end-to-end run (32 checks, all passing): colour rules;
topology states and link colours; MySQL node = sandbox; masked password entry
for both Client and Admin through the GUI input boxes (and absent from the
document and exports); admin `status`/`listusers` parsing; GUI-sent commands
echoed; dossier load + **VERIFIED**; user-initiated stop = Offline;
deliberate dossier edit -> **TAMPERING DETECTED**; Restart Network back to
Ready; no orphaned processes. Parsers were also fuzzed with 200 random chunk
splits, and the dossier verifier was checked against your real 54-entry
`aegis_dossier.json` (intact) and against edited/deleted-entry copies (both caught).

**Not yet verified:** behaviour on Windows (developed and tested headless on
Linux; the code avoids Python 3.12-only syntax, checked against the 3.9
grammar), Real MySQL mode, several simultaneous clients.

## Known limitations
- The Client Configuration dialog (firewall IP/port) is still deferred: `client.py` fixes 127.0.0.1:8080 in its own source.
- Client/Admin menus are driven by typing into the input box, not by GUI buttons.
- Admin counts require an Admin session (by design, see above).
- On Windows, *Stop* uses a hard kill (console programs ignore the polite request); the backend keeps no state that needs a clean shutdown.
