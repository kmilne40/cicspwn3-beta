# CICSPWN3 Technical Documentation

This document provides a **technical overview** of the CICSPWN3 application, summarises **all changes** made in recent updates, explains the **purpose** of each Python module, and includes a **detailed user manual** describing how to install and use the tool for testing CICS systems.

---

## Table of Contents
1. [Introduction](#introduction)
2. [Overview of Changes](#overview-of-changes)
3. [Module Descriptions](#module-descriptions)
   - [tn3270lib.py](#tn3270libpy)
   - [tn3270_session.py](#tn3270_sessionpy)
   - [cics_utilities.py](#cics_utilitiespy)
   - [cics_scanner.py](#cics_scannerpy)
   - [cics_exploits.py](#cics_exploitspy)
   - [cics_menu.py](#cics_menupy)
   - [main.py](#mainpy)
4. [Technical Manual](#technical-manual)
   - [Installation & Setup](#installation--setup)
   - [Running the Program](#running-the-program)
     - [Interactive Mode](#interactive-mode)
     - [Command-Line Mode](#command-line-mode)
   - [List of Transactions & Exploits](#list-of-transactions--exploits)
   - [Brute Force Logic](#brute-force-logic)
   - [CEDA Security Bypass Logic](#ceda-security-bypass-logic)
5. [Support & Legal Disclaimer](#support--legal-disclaimer)

---

## Introduction

**CICSPWN3** is a toolkit for **enumerating** and **exploiting** IBM CICS regions over a TN3270 connection. It provides a variety of features:  
- **APPLID discovery**  
- **Basic enumeration** (e.g. CESN, CECI checks)  
- **Default credential checks**  
- **Transaction exploits** (command injection, arbitrary commands)  
- **Brute-force login**  
- **CEDA-based security bypass**  

All functionality is accessible either via **interactive** mode or through **command-line** flags.

---

## Overview of Changes

1. **Transition from Raw Telnet to TN3270**  
   Previously, the application used plain Telnet (`telnetlib`) to communicate. This was replaced with **`tn3270lib.py`** and a wrapper in **`tn3270_session.py`** so the tool can handle **TN3270** negotiations correctly (EBCDIC data, 3270 screen flows, etc.).

2. **Strict CP037 EBCDIC Decoding**  
   The code now attempts to decode all inbound mainframe data using CP037 EBCDIC, rather than multiple fallback encodings.

3. **Removal of Placeholders**  
   - **Brute Force**: Real multithreaded logic with `ThreadPoolExecutor`.  
   - **Security Bypass**: A demonstration approach using **CEDA** to illustrate how one might disable or weaken security checks.

4. **Modular Structure**  
   - Each major function (scanning, exploitation, sessions, etc.) is in its own module:  
     - `cics_scanner.py` handles scanning/enumeration.  
     - `cics_exploits.py` handles multiple exploit methods.  
     - `cics_menu.py` offers an interactive UI.

5. **Expanded Transactions**  
   The tool checks for or attempts to exploit these transactions: **CECI**, **CESN**, **CEDA**, **CEMT**, **CESF**, plus others like **CEBR**, **CECD**, etc.

6. **Complete Command-Line Interface (CLI)**  
   **`main.py`** now includes command-line arguments for scanning, enumeration, default creds, bypass, brute force, etc., ensuring no more placeholders.

---

## Module Descriptions

### tn3270lib.py
**Purpose**:  
- A library that manages **TN3270** sessions, negotiations, screen data handling, and EBCDIC character conversions.  

**Key Points**:  
- Provides the `TN3270` class with methods like `initiate()`, `send_cursor()`, `send_enter()`, and `get_all_data()`.  
- Handles telnet negotiation and 3270-specific commands (IAC, EOR, etc.).  

### tn3270_session.py
**Purpose**:  
- A **lightweight wrapper** around `tn3270lib.TN3270` to emulate the old “send & read” session interface used by the rest of the application.  

**Key Points**:  
- Contains `TN3270Session`, which has:
  - `open_session()` – initiates a TN3270 connection.  
  - `close_session()` – closes the connection.  
  - `send_vtam_command()` – types the command at the cursor and presses Enter.  
  - `read_screen()` – collects raw bytes from the mainframe for subsequent decoding.  

### cics_utilities.py
**Purpose**:  
- Helper functions:
  - `is_valid_host()`
  - `is_valid_port()`
  - `decode_mainframe_output()` (strict CP037 decode)

**Key Points**:  
- The `decode_mainframe_output()` now **only** attempts CP037, returning replacement characters for unsupported bytes.  

### cics_scanner.py
**Purpose**:  
- **Scans** for a valid APPLID (via “L <applid>”)  
- **Enumerates** basic transactions (e.g., checks CESN & CECI screens).  

**Key Points**:  
- `check_applid_validity()` tries “L <applid>” then hunts for words like “CICS” or “DFH”.  
- `run_basic_enum()` attempts small transaction commands (CESN, CECI) to gather info.  

### cics_exploits.py
**Purpose**:  
- **Implements** the exploit logic.  
- Features:  
  - `exploit_default_credentials()`  
  - `brute_force_login()`  
  - `exploit_transaction_command()`  
  - `exploit_arbitrary_commands()`  
  - `security_bypass_exploit()` (uses **CEDA** to attempt misconfig-based security changes)  

**Key Points**:  
- **CEDA Bypass**: Illustrates how an attacker might remove security from a transaction with `SET TRAN XYZ SECURITY(NO)`, if not properly restricted.  
- **Brute Force**: Uses multiple threads to systematically try user/password pairs.  

### cics_menu.py
**Purpose**:  
- Offers an **interactive menu** for enumerations, exploits, and session configuration changes.  

**Key Points**:  
- `run_interactive(...)` presents menu items for:  
  1. APPLID check  
  2. Basic enumeration  
  3. Default credentials exploit  
  4. Transaction-based exploit  
  5. Arbitrary commands  
  6. Security bypass  
  7. Brute force  
  8. Scan for CICS markers  
  9. Change APPLID  
  10. Change port  
  11. Exit  

### main.py
**Purpose**:  
- Acts as the **entry point** for the entire tool.  
- Provides command-line argument parsing, logging setup, and direct calls into `cics_scanner` or `cics_exploits` methods.  

**Key Points**:  
- Two modes: **interactive** (`--interactive`) or **non-interactive** CLI flags (e.g., `--check`, `--exploit-default-creds`, `--bypass`).  
- Validates host/port, then runs the selected commands.  

---

## Technical Manual

Below is a technical manual detailing how to install and use CICSPWN3 for testing CICS systems. 

### Installation & Setup

1. **Python 3.8+** is recommended.  
2. **Clone** or **download** all `.py` files into the same directory:
   - `main.py`
   - `cics_menu.py`
   - `cics_scanner.py`
   - `cics_exploits.py`
   - `cics_utilities.py`
   - `tn3270_session.py`
   - `tn3270lib.py`

3. **Install Dependencies**  
   - Typically no third-party dependencies are strictly needed beyond standard Python libraries.  
   - (Optional) If you want to use concurrency or advanced packages, ensure they are installed (`concurrent.futures` is part of the standard library from Python 3.2 onward).  

4. **Set up** your environment:
   ```bash
   cd path/to/cicspwn3
   python3 main.py -h
   ```
   You should see the command-line help.

### Running the Program

You can operate the tool in **two modes**:

#### Interactive Mode

- Launch the interactive menu with:
  ```bash
  python main.py --target <mainframe> --interactive
  ```
- You’ll see a menu like:
  ```
  [Target: myMainframe, Port: 23, APPLID: CICS, Timeout: 10.0]
  CICS PWN Menu:
  1. Check APPLID Validity
  2. Perform Basic Enumeration
  3. Exploit Default Credentials
  4. Exploit Transaction Command
  5. Exploit Arbitrary Commands
  6. Attempt Security Bypass
  7. Perform Brute Force Attack
  8. Scan for CICS Markers
  9. Change APPLID
  10. Change Port
  11. Exit
  ```
  Enter a number to choose an action.  

#### Command-Line Mode

You can also run specific actions via flags. For example:

1. **Check APPLID**:
   ```bash
   python main.py --target 192.168.1.100 --check
   ```
   The tool will attempt “L CICS” by default (or `--applid` if you supply it), then log whether the region is valid.

2. **Basic Enumeration**:
   ```bash
   python main.py --target mainframe.example.com --enum
   ```
   The tool checks CESN, CECI screens for banner info and logs them.

3. **Default Credentials Exploit**:
   ```bash
   python main.py --target mainframe -p 23 --exploit-default-creds --user TESTUSER --password TESTPASS
   ```

4. **Transaction Command Exploit**:
   ```bash
   python main.py --target mainframe --exploit-transaction \
       --transaction CECI --command "EX TRA('SOMEPRIV')"
   ```

5. **Arbitrary Commands**:
   ```bash
   python main.py --target mainframe --exploit-arbitrary
   ```

6. **Security Bypass**:
   ```bash
   python main.py --target mainframe --bypass
   ```
   Tries a **CEDA**-based approach to remove or alter security restrictions.

7. **Brute Force**:
   ```bash
   python main.py --target mainframe --brute-force --threads 10
   ```
   Attempts multiple user/password combos concurrently.

### List of Transactions & Exploits

The tool references several standard CICS transactions:

- **CESN**: CICS Sign-On  
- **CESF**: CICS Sign-Off  
- **CECI**: CICS Command Interpreter  
- **CEDA**: Resource Definition (Administrator)  
- **CEMT**: Master Terminal transaction  
- **CEBR**, **CECD**, etc.: Additional utilities or subcommands  
- **CIEZ**: **Fictional** “backdoor” used in the example bypass logic  

#### General Exploit Flow

1. **Open** a TN3270 session (`L <APPLID>`).  
2. **Send** transaction name (e.g. `CEDA`) at the screen, press Enter.  
3. **Read** and decode the returned 3270 data (CP037 EBCDIC).  
4. **Look** for success or error markers (e.g., `DFHAC`, `NOT AUTH`, or `CHANGED`).  

### Brute Force Logic

- **`brute_force_login()`** in `cics_exploits.py` uses `ThreadPoolExecutor` to test multiple credentials:
  1. For each `(user, password)` pair, call **`exploit_default_credentials(user, password)`**.  
  2. If any call returns success, the brute force halts or logs success accordingly.  

- This is typically used to discover a valid sign-on combination, either from a known default or a dictionary list.

### CEDA Security Bypass Logic

- The code attempts:
  1. **`CEDA`** transaction.  
  2. If not denied, sends a **SET** or **DEFINE** style command that might **disable** or **downgrade** security (e.g. `SECURITY(NO)`).  
  3. Checks for success indicators like `CHANGED`, `SUCCESS`, or `TASK COMPLETE`.  
- If the region is misconfigured to allow **CEDA** updates without proper authority, this can effectively remove or reduce security controls.

---

## Support & Legal Disclaimer

**Support**:  
- This project is offered as an educational or penetration testing resource.  
- For real-world usage, thoroughly test in a safe environment or with explicit permission.

**Disclaimer**:  
- The authors bear no responsibility for misuse.  
- Use **only** on systems you own or are lawfully permitted to test.  

---

**End of Document**
