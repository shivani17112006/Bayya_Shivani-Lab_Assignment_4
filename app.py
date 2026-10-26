"""
Web Server Security Assignment — IT-30001
Category: OS Command Injection
Variant:  In-band (command output returned directly in the response)

/vulnerable -> intentionally insecure implementation (for the exploit demo)
/secure     -> the same feature, fixed

Run only on your own machine / isolated VM. Do NOT deploy this publicly.
"""

import re
import subprocess

from flask import Flask, render_template, request

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


# ---------------------------------------------------------------------------
# VULNERABLE implementation
# ---------------------------------------------------------------------------
@app.route("/vulnerable", methods=["GET", "POST"])
def cmd_vulnerable():
    """
    (a) VULNERABLE CODE PATH
    The user-supplied host is concatenated directly into a shell command
    string, and shell=True hands that string to the system shell. Any shell
    metacharacter the user includes (;  &&  |  `` ` `` etc.) is interpreted
    by the shell, not treated as part of the hostname.

    (b) WORKING EXPLOIT
    Enter as host:
        127.0.0.1; whoami
        127.0.0.1 && dir        (Windows)   /   127.0.0.1 && cat /etc/passwd  (Linux)
        127.0.0.1 | hostname
    The ping still runs, but so does the injected command — and its output
    is returned in-band, in the same response.

    (c) ROOT CAUSE
    Untrusted input reaches a shell interpreter (shell=True) without any
    validation or encoding, so the shell's own syntax (command separators)
    is exposed to the attacker.
    """
    output, command_shown = None, None
    if request.method == "POST":
        host = request.form.get("host", "")

        # --- VULNERABLE: shell=True + raw string concatenation ---
        command = f"ping -n 1 {host}" if _is_windows() else f"ping -c 1 {host}"
        command_shown = command
        try:
            result = subprocess.run(
                command, shell=True, capture_output=True, timeout=5, text=True
            )
            output = (result.stdout or "") + (result.stderr or "")
        except Exception as e:  # noqa: BLE001 (demo only)
            output = str(e)

    return render_template(
        "cmd_vulnerable.html", output=output, command_shown=command_shown
    )


# ---------------------------------------------------------------------------
# SECURE implementation (mitigation implemented)
# ---------------------------------------------------------------------------
HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")  # allow-list: hostnames / IPv4 only


@app.route("/secure", methods=["GET", "POST"])
def cmd_secure():
    """
    (d) MITIGATION IMPLEMENTED
    Two layers:
      1. No shell is invoked at all: subprocess.run([...], shell=False)
         passes the command as an argument vector, so shell metacharacters
         have no special meaning — they're just literal characters in one
         argument.
      2. Allow-list input validation: the host is also checked against a
         strict regex (letters, digits, dots, hyphens only) before use, as
         defence in depth.
    The exact same payload that worked against /vulnerable is rejected here
    before any process is even started.
    """
    output, error = None, None
    if request.method == "POST":
        host = request.form.get("host", "").strip()
        if not HOST_RE.match(host):
            error = "Invalid host — only letters, digits, dots and hyphens are allowed."
        else:
            try:
                # --- SECURE: argument vector, shell=False, validated input ---
                args = ["ping", "-n", "1", host] if _is_windows() else ["ping", "-c", "1", host]
                result = subprocess.run(
                    args, shell=False, capture_output=True, timeout=5, text=True
                )
                output = (result.stdout or "") + (result.stderr or "")
            except Exception as e:  # noqa: BLE001 (demo only)
                output = str(e)

    return render_template("cmd_secure.html", output=output, error=error)


def _is_windows() -> bool:
    import platform
    return platform.system().lower() == "windows"


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
