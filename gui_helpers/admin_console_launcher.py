"""
admin_console_launcher.py -- lets the UNMODIFIED admin_console.py run
correctly as a GUI-managed subprocess.

Why this exists
----------------
admin_console.py's admin_login() calls getpass.getpass() for the admin
password. getpass deliberately bypasses redirected stdin/stdout and reads/
writes directly against the process's controlling console/tty -- exactly
the right behavior for a human typing at a real terminal, so a redirect
or log file can never capture a password. But when admin_console.py is
launched by this GUI as a subprocess with its stdin/stdout piped (not
attached to a real terminal), getpass still finds and grabs whatever
console/tty the *parent* GUI process happens to be attached to -- e.g.
the terminal window "python main.py" was started from -- so the admin
password prompt and the operator's keystrokes appear there instead of in
the GUI's Admin Terminal panel. That is the exact bug this shim fixes.

Rather than editing admin_console.py itself, this launcher monkey-patches
getpass.getpass to fall back to a plain input() call -- the same
mechanism client.py's own login already uses for its password (see
client.py's do_login: `pwd = input("Password: ").strip()`), so this just
brings admin login in line with an approach already used elsewhere in
this project -- and then runs the real, completely unmodified
admin_console.run_admin_console().

Trade-off: the admin password is visible as plain text while typing in
the Admin Terminal's input box, same as the Client Terminal already is
for user passwords. This is a localhost simulator/demo tool, not a
hardened production console, so that trade-off is acceptable here; it is
NOT applied to bootstrap_admin.py (which is intended to be run once, by
hand, in a real terminal, before the GUI is used at all).

Usage: launched by AdminController with cwd set to the shared working
directory (so the real admin_console.py / protocol.py there can be
imported), exactly the same way the GUI launches every other backend
process.
"""

import getpass
import os
import sys

# admin_console.py lives in the shared working directory (this process's
# cwd, set by the GUI when it starts this launcher) -- not next to this
# launcher file -- so it needs to be added to sys.path explicitly.
sys.path.insert(0, os.getcwd())

# Must happen before admin_console.admin_login() is ever CALLED (not
# before it's imported -- module-level `import getpass` in admin_console.py
# binds the same shared module object either way, so patching its
# `getpass` attribute here is visible to admin_console.py regardless of
# import order).
getpass.getpass = lambda prompt="Password: ", stream=None: input(prompt)

import admin_console  # noqa: E402  (unmodified file from the working directory)

if __name__ == "__main__":
    admin_console.run_admin_console()
