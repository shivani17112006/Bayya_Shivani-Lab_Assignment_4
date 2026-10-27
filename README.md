# OS Command Injection — In-band (Assignment Deliverable)

**IT-30001 Cyber Security — Web Server Security Assignment**

Category: **OS Command Injection**
Variant: **In-band** (the injected command's output is returned directly in
the HTTP response)

A small Flask "ping" utility implemented twice:
- `/vulnerable` — intentionally insecure, for the exploit demonstration
- `/secure` — the same feature, with the mitigation implemented

> **Authorised testing only.** Run this on `127.0.0.1` / your own machine.
> Do not point it at shared or hosted infrastructure.

---

## (a) Vulnerable implementation

File: `app.py`, function `cmd_vulnerable()`. The host field is concatenated
directly into a shell command string:

```python
command = f"ping -c 1 {host}"
result = subprocess.run(command, shell=True, capture_output=True, text=True)
```

`shell=True` hands this whole string to the system shell, so any shell
metacharacter in `host` (`;`, `&&`, `|`, backticks) is interpreted by the
shell instead of being treated as part of a hostname.

## (b) Working exploit

With the app running, go to `/vulnerable` and enter as **host**:

- Linux/macOS: `127.0.0.1; whoami`  or  `127.0.0.1 && cat /etc/passwd`
- Windows: `127.0.0.1 && whoami`  or  `127.0.0.1 && dir`

The ping still runs, but the injected command (`whoami`, `cat`, `dir`, ...)
also executes, and its output is appended to the response — **in-band**,
in the same page. The page also prints the exact shell string that was
run, which is useful evidence for your screenshot/video.

## (c) Root cause

Untrusted user input reaches a shell interpreter (`shell=True`) without any
validation or escaping. Shell command separators in the input change the
meaning of the command instead of being treated as literal text.

## (d) Mitigation implemented

File: `app.py`, function `cmd_secure()`. Two combined controls:

1. **No shell is invoked.** The command is run as an argument vector:
   ```python
   subprocess.run(["ping", "-c", "1", host], shell=False, ...)
   ```
   With `shell=False` and a list of arguments, there is no shell parsing
   step at all — `host` is passed as a single literal argument to `ping`,
   so `;`, `&&`, `|` etc. have no special meaning.
2. **Allow-list input validation**, as defence in depth:
   ```python
   HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
   ```
   Anything containing a space, semicolon, ampersand, pipe, or backtick is
   rejected before a process is ever started.

Submit the **exact same payload** (`127.0.0.1; whoami`) to `/secure` —
it is rejected immediately with "Invalid host", and a plain host like
`127.0.0.1` still works normally. Screenshot this rejection as your
evidence of the fix.

## (e) Other mitigations — theory only (for the viva)

You only need to *explain* these, not implement them:

- **Avoid the shell entirely** (what we implemented) — calling the binary
  directly with a fixed argument list removes the shell's parsing/joining
  behaviour from the picture completely.
- **Allow-list validation on structure/format** — independently of how the
  command is executed, restricting input to an expected pattern (valid
  IPv4/hostname characters, bounded length) blocks malformed input before
  it is ever used.
- **Least privilege** — running the service process under an account with
  minimal OS permissions (no access to sensitive files, no elevated rights)
  limits the damage even if an injection were to succeed elsewhere.

---

## Setup — VS Code (Windows)

1. Create the `cmd-injection-assignment` Project.
2. Open a terminal: **Terminal → New Terminal**. Make sure it's
   **PowerShell** (shown top-right of the terminal panel).
3. Confirm Python is installed:
   ```powershell
   python --version
   ```
   If that fails, install Python from **python.org/downloads**, ticking
   **"Add python.exe to PATH"** during install, then reopen the terminal.
4. Create and activate a virtual environment:
   ```powershell
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   ```
   If activation is blocked by execution policy, run once:
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```
   then retry the `Activate.ps1` line. Your prompt should now start with
   `(venv)`.
5. Install dependencies and run the app:
   ```powershell
   pip install -r requirements.txt
   python app.py
   ```
6. Open **http://127.0.0.1:5000** in your browser.
7. Demo the exploit at `/vulnerable`, then the fix at `/secure`, using the
   payloads in section (b) above. Take screenshots of both for your
   submission.
8. Stop the server with `Ctrl+C` in the terminal when done.

### macOS / Linux equivalent (steps 4–5)
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

---

## Deliverables checklist

- [ ] Push this whole folder to a **public GitHub repository**.
- [ ] Complete the ownership table below in this README.
- [ ] Record your video: show the vulnerable code, run the exploit, show
      the secure route blocking the same payload, then summarise the
      "other mitigations" theory from section (e) in ~20–30 seconds.
- [ ] Be ready to explain all of the above individually at the viva.

## Table 3 — Ownership declaration

| Member name | Roll number | Category | Variant implemented |
|---|---|---|---|
| Mogal Saith Sumayya | IIB2024032 | SQL Injection | Authentication bypass |
| Bayya Shivani | IIT2024275 | OS Command Injection | In-band |
| Rakhi Chauhan | IIT2024269 | Cross-Site Scripting (XSS) | Stored XSS |

---

## Project structure

```
cmd-injection-assignment/
├── app.py                  # Flask routes: /vulnerable and /secure
├── requirements.txt
├── README.md
├── static/
│   └── style.css
└── templates/
    ├── base.html
    ├── index.html
    ├── cmd_vulnerable.html
    └── cmd_secure.html
```
