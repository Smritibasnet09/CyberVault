"""
╔══════════════════════════════════════════════════════════════════════════════╗
║         OFFENSIVE SECURITY WITH PYTHON — 10 PROJECT-BASED EXERCISES         ║
║                    For Educational Purposes Only                             ║
║   ⚠️  All exercises must ONLY be performed in your own lab/test environment  ║
╚══════════════════════════════════════════════════════════════════════════════╝

COURSE OVERVIEW:
─────────────────
These 10 hands-on exercises introduce students to offensive security concepts
using Python. Each exercise builds on real-world attack techniques and teaches
you how attackers think — so you can defend better.

PREREQUISITES:
  - Python 3.8+
  - Basic Python knowledge (functions, loops, file I/O, sockets)
  - Libraries: socket, os, subprocess, requests, scapy (install as needed)
  - A local lab environment (e.g., VirtualBox/VMware with Kali Linux + targets)

ETHICS & LEGAL WARNING:
  ⚠️  NEVER run these tools on systems you do not own or have written permission
      to test. Unauthorized access is illegal under cybercrime laws worldwide,
      including Nepal's Electronic Transaction Act (ETA) 2063.
"""

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# EXERCISE 1: PORT SCANNER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
TOPIC: Network Reconnaissance / Information Gathering

BACKGROUND:
  Port scanning is the first step in almost every penetration test. Before
  attacking a target, hackers identify which services are running and on which
  ports. A "port" is a numbered endpoint (0–65535) on a network interface.
  Common ports: 21 (FTP), 22 (SSH), 80 (HTTP), 443 (HTTPS), 3306 (MySQL).

  Tools like Nmap do this professionally. In this exercise, you will build
  a simplified version from scratch using Python's `socket` module.

LEARNING OBJECTIVES:
  1. Understand TCP connections and the socket handshake.
  2. Learn how to identify open vs closed ports programmatically.
  3. Use threading to speed up scanning.
  4. Understand why attackers value this information.

CONCEPTS TO STUDY FIRST:
  - TCP 3-way handshake (SYN → SYN-ACK → ACK)
  - Python socket module: socket(), connect_ex(), settimeout()
  - Python threading module: Thread, daemon threads
  - What is a "banner" (service identification string)?

TASK DESCRIPTION:
  Build a multi-threaded TCP port scanner that:
    a) Accepts a target IP address as input.
    b) Scans ports in a given range (e.g., 1–1024).
    c) Reports which ports are OPEN.
    d) Optionally attempts to grab the service banner.
    e) Uses threads to scan multiple ports concurrently.

STEP-BY-STEP INSTRUCTIONS:
  Step 1 — Import required modules: socket, threading, datetime.
  Step 2 — Write a function `scan_port(ip, port)` that:
            • Creates a TCP socket
            • Sets a timeout of 0.5 seconds
            • Uses connect_ex() — returns 0 if port is open
            • Attempts to grab a banner using recv(1024)
            • Prints result and closes socket
  Step 3 — Write a function `run_scanner(target, start_port, end_port)` that:
            • Resolves hostname to IP (socket.gethostbyname)
            • Creates and starts a Thread for each port
            • Joins all threads (waits for completion)
  Step 4 — Add a `__main__` block that takes user input for target/port range.
  Step 5 — Test on localhost (127.0.0.1) or your lab VM.

EXPECTED OUTPUT EXAMPLE:
  Scanning 192.168.1.1 from port 1 to 1024...
  [+] Port 22 OPEN  | Banner: SSH-2.0-OpenSSH_8.2
  [+] Port 80 OPEN  | Banner: HTTP/1.1 200 OK
  Scan completed in 3.42 seconds.

CHALLENGE (BONUS):
  - Add a `-sV` style version detection using the banner.
  - Support UDP scanning.
  - Output results to a CSV file.
"""



import socket
import threading
import datetime
import time


# Function to scan a single port
def scan_port(ip, port, results, lock):

    try:
        # Create TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Set timeout
        sock.settimeout(0.5)

        # Try connecting to the port
        result = sock.connect_ex((ip, port))

        # If port is open
        if result == 0:

            banner = ""

            try:
                # Send request to server
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")

                # Receive banner
                banner = sock.recv(1024).decode(
                    "utf-8",
                    errors="ignore"
                ).strip()

                # If banner empty
                if not banner:
                    banner = "No Banner"

            except:
                banner = "No Banner"

            # Thread-safe printing
            with lock:

                results.append((port, banner))

                print(f"[+] Port {port} OPEN | {banner[:50]}")

        # Close socket
        sock.close()

    except:
        pass


# Main scanner function
def run_scanner(target, start_port, end_port):

    try:
        # Convert hostname to IP
        ip = socket.gethostbyname(target)

    except socket.gaierror:

        print("[-] Could not resolve hostname.")
        return

    print("\n" + "=" * 60)

    print(f"Scanning Target: {ip}")

    print(f"Port Range: {start_port} - {end_port}")

    print(f"Started: {datetime.datetime.now()}")

    print("=" * 60)

    # Store open ports
    results = []

    # Create lock
    lock = threading.Lock()

    # Store threads
    threads = []

    # Start timer
    start_time = time.time()

    # Loop through ports
    for port in range(start_port, end_port + 1):

        # Create thread
        thread = threading.Thread(
            target=scan_port,
            args=(ip, port, results, lock),
            daemon=True
        )

        # Add thread to list
        threads.append(thread)

        # Start thread
        thread.start()

    # Wait for all threads
    for thread in threads:
        thread.join()

    # End timer
    end_time = time.time()

    print("\n" + "-" * 60)

    print(f"Open Ports Found: {len(results)}")

    print(f"Scan completed in {end_time - start_time:.2f} seconds")

    print("-" * 60)


# Main program
if __name__ == "__main__":

    print("=== PYTHON PORT SCANNER ===")

    target = input("Enter target IP or hostname: ")

    start_port = int(input("Enter start port: "))

    end_port = int(input("Enter end port: "))

    run_scanner(target, start_port, end_port)
