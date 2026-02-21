# 🛡️ Sanitize-It | Zero-Trust Log & Code Purifier

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.x](https://img.shields.io/badge/python-3.x-blue.svg)](https://www.python.org/)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)]()
[![Status: Active](https://img.shields.io/badge/Status-Active-success.svg)]()

**Sanitize-It** is a brutal, client-side, offline-only Python application designed to aggressively scrub sensitive data (PII, Credentials, IPs, API Keys) from your server logs, source code, and text files before you share them on GitHub, Reddit, or StackOverflow.

---

## 🚨 The Problem
You have a bug in your production server. You want to post the 10,000-line server log on a public forum to ask for help. But that log is littered with real IPv4 addresses, AWS Access Keys, user emails, and database passwords. 
Manual redaction takes hours and is highly error-prone. Online "Log Scrubbers" require you to upload your sensitive data to *their* servers.

## 💡 The Solution
**Sanitize-It** runs 100% locally on your machine. It utilizes a massive database of enterprise-grade Regular Expressions to identify and replace sensitive tokens in milliseconds. It features both a beautifully threaded **GUI** for normal users and a powerful **CLI** for SysAdmins.

---

## ✨ Killer Features

* **Hybrid Architecture (GUI & CLI):** Launch it without arguments for a stunning Dark-Mode Desktop App, or pass `-i` to run it as a silent background pipeline script.
* **Consistent Hashing:** If the attacking IP `192.168.1.50` appears 500 times in your log, it isn't just replaced with `[REDACTED]`. It is replaced with `[REDACTED_IPV4_1]` every single time. This preserves the logical flow of your logs so developers can still debug the architecture without seeing the real IP.
* **Zero Dependencies:** No `pip install` required. Built entirely on the Python 3 Standard Library (uses built-in `re`, `threading`, and `tkinter`).
* **Multithreaded Engine:** The GUI will never freeze. Heavy regex operations are offloaded to background threads with safe queue-polling.
* **Built-in Diff Engine:** (CLI Mode) See exactly what lines were changed directly in your terminal using the `--diff` flag.

---

## 🚀 Installation

Because Sanitize-It has zero external dependencies, installation takes 3 seconds.

```bash
# 1. Clone the repository
git clone [https://github.com/Wasserpuncher/Sanitize-It.git](https://github.com/Wasserpuncher/Sanitize-It.git)
```

## 🖥️ Usage: Graphical User Interface (GUI)


# 2. Navigate into the directory
cd Sanitize-It

# 3. Run it
python sanitize_it.py

