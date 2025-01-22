# CICSPWN3 Technical Documentation

---

## Table of Contents

1. [Introduction](#introduction)
2. [What is CICS?](#what-is-cics)
3. [CICS Transactions Overview](#cics-transactions-overview)
   - [CEMT](#cemt)
   - [CEDA](#ceda)
   - [CESN](#cesn)
   - [CESF](#cesf)
   - [CECI](#ceci)
4. [Overview of Changes](#overview-of-changes)
5. [Module Descriptions](#module-descriptions)
   - [tn3270lib.py](#tn3270libpy)
   - [tn3270_session.py](#tn3270_sessionpy)
   - [cics_utilities.py](#cics_utilitiespy)
   - [cics_scanner.py](#cics_scannerpy)
   - [cics_exploits.py](#cics_exploitspy)
   - [cics_menu.py](#cics_menupy)
   - [main.py](#mainpy)
6. [Command Examples & Expected Output](#command-examples--expected-output)
   - [APPLID Check](#applid-check)
   - [Basic Enumeration](#basic-enumeration)
   - [Default Credentials Exploit](#default-credentials-exploit)
   - [Transaction Exploit](#transaction-exploit)
   - [Security Bypass via CEDA](#security-bypass-via-ceda)
7. [Technical Manual](#technical-manual)
   - [Installation & Setup](#installation--setup)
   - [Running the Program](#running-the-program)
     - [Interactive Mode](#interactive-mode)
     - [Command-Line Mode](#command-line-mode)
8. [Support & Legal Disclaimer](#support--legal-disclaimer)

---

## Introduction

**CICSPWN3** is a Python-based framework for interacting with and testing IBM's CICS (Customer Information Control System) regions via TN3270 connections. It supports a variety of enumeration and exploitation techniques, including:

- **Discovering APPLIDs**: Verifying if a CICS region exists at a specified endpoint.
- **Enumerating Resources**: Gathering information on active transactions, user prompts, and system banners.
- **Default Credential Exploitation**: Testing known default username/password pairs.
- **Transaction Exploitation**: Executing privileged commands via transactions like `CEDA` and `CECI`.
- **Brute Force Login**: Systematically testing large credential lists.
- **Security Bypass via CEDA**: Demonstrating potential vulnerabilities in improperly secured CICS regions.

This document outlines the purpose, architecture, and functionality of CICSPWN3 and provides detailed examples of its usage.

---

## What is CICS?

**Customer Information Control System (CICS)** is a transaction processing middleware developed by IBM for use on mainframes. It is highly scalable, supporting thousands of concurrent users and millions of transactions per day. CICS allows businesses to run critical online applications, such as banking systems, retail point-of-sale applications, and insurance claim processing.

CICS provides the following core functions:
- **Transaction Management**: Processes online transactions reliably and securely.
- **Middleware Services**: Acts as an intermediary between applications and system resources.
- **Data Handling**: Connects to databases and ensures data integrity across transactions.

CICS supports several programming languages, including COBOL, Java, and C++, and provides interfaces for modern integration technologies like REST APIs.

---

## CICS Transactions Overview

### CEMT

**CEMT** (CICS Execute Master Terminal) is the primary transaction for **resource management**. It allows administrators to query, start, stop, or modify the status of resources such as:
- Programs
- Files
- Terminals
- Transactions

**Example Use Case**:
```plaintext
CEMT I TRAN
```
This command lists all active transactions.

---

### CEDA

**CEDA** (CICS Execute Definition and Administration) is used for managing resource definitions in the CICS environment. It provides commands to:
- Define new transactions, programs, and files.
- Update existing resource definitions.
- Delete unnecessary or obsolete resources.

**Example Use Case**:
```plaintext
CEDA DEFINE TRANSACTION(MYTRAN) GROUP(MYGRP)
```
This command defines a new transaction called `MYTRAN` in the group `MYGRP`.

---

### CESN

**CESN** (CICS Execute Sign-On) is used by users to authenticate themselves to the CICS system. Successful sign-on assigns the user a profile, which determines their access levels and permissions.

**Example Use Case**:
```plaintext
CESN USERID(USER1) PASSWORD(PASS1)
```
Upon successful authentication, the user can access restricted transactions.

---

### CESF

**CESF** (CICS Execute Sign-Off) is used to terminate a user's session. This ensures that any resources allocated to the user are released and their session state is cleared.

**Example Use Case**:
```plaintext
CESF
```
The user is logged off, and no further commands can be issued until they sign back in.

---

### CECI

**CECI** (CICS Execute Command Interpreter) is a powerful transaction for debugging and testing. It allows users to interactively issue CICS commands and observe the results.

**Example Use Case**:
```plaintext
CECI INQUIRE FILE(MYFILE)
```
This command retrieves information about the `MYFILE` resource.

---

## Overview of Changes

1. Transitioned from **plain Telnet** to **TN3270** for protocol-level communication, enabling proper handling of EBCDIC data streams.
2. Implemented **strict CP037 decoding** for TN3270 data, ensuring correct translation of screen content.
3. Enhanced the **interactive menu** and CLI options for comprehensive CICS enumeration and exploitation.
4. Replaced placeholder logic for **brute force** and **security bypass** with functional implementations.
5. Expanded the **list of transactions** to include CEDA, CEMT, CESN, CESF, and more.
6. Improved **logging and debug output** to provide users with detailed feedback during operations.

---

## Module Descriptions

### tn3270lib.py

**Purpose**:  
A low-level library for managing TN3270 sessions, including negotiation, EBCDIC data handling, and screen interactions.

**Key Methods**:
- `initiate()`: Establishes a TN3270 connection and begins negotiation.
- `send_cursor()`: Sends data to the screen from the current cursor position.
- `recv_data()`: Reads data from the TN3270 session.

---

### tn3270_session.py

**Purpose**:  
A wrapper for `tn3270lib.py`, providing simplified methods for sending commands and reading responses.

**Key Methods**:
- `open_session()`: Opens a TN3270 session.
- `close_session()`: Closes the session.
- `send_vtam_command()`: Sends a command and presses Enter.

---

### cics_utilities.py

**Purpose**:  
Contains helper functions for validation and data decoding.

**Key Functions**:
- `is_valid_host()`: Validates a hostname or IP.
- `decode_mainframe_output()`: Decodes EBCDIC data using CP037 encoding.

---

### cics_scanner.py

**Purpose**:  
Handles the discovery and enumeration of CICS regions and resources.

**Key Methods**:
- `check_applid_validity()`: Tests if the specified APPLID exists.
- `run_basic_enum()`: Performs basic transaction enumeration (e.g., CESN, CECI).

---

### cics_exploits.py

**Purpose**:  
Implements CICS exploitation techniques, including brute force, default credentials, and transaction manipulation.

**Key Methods**:
- `exploit_default_credentials()`: Attempts to log in with default credentials.
- `brute_force_login()`: Performs multi-threaded brute force attempts.
- `security_bypass_exploit()`: Demonstrates a CEDA-based security bypass.

---

### cics_menu.py

**Purpose**:  
Provides an interactive menu for users to select actions.

**Key Features**:
- Supports all major functionality (e.g., enumeration, brute force, bypass).

---

### main.py

**Purpose**:  
Entry point for CICSPWN3. Handles argument parsing, logging, and execution of tasks.

---

## Command Examples & Expected Output

### APPLID Check

**Command**:
```bash
python main.py --target 192.168.1.1 --check
```

**Expected Output**:
```plaintext
2025-01-22 20:00:00 [INFO] Checking validity of APPLID 'CICS' on 192.168.1.1:23
2025-01-22 20:00:02 [INFO] APPLID 'CICS' is valid on 192.168.1.1:23
```

---

### Basic Enumeration

**Command**:
```bash
python main.py --target 192.168.1.1 --enum
```

**Expected Output**:
```plaintext
2025-01-22 20:05:00 [INFO] Running basic CICS enumeration...
2025-01-22 20:05:03 [INFO] CESN: Sign-On screen detected.
2025-01-22 20:05:05 [INFO] CECI: Command Interpreter is available.
```

---

### Default Credentials Exploit

**Command**:
```bash
python main.py --target 192.168.1.1 --exploit-default-creds --user CICS --password CICS
```

**Expected Output**:
```plaintext
2025-01-22 20:10:00 [INFO] Attempting default credentials: CICS/CICS
2025-01-22 20:10:02 [INFO] Successfully exploited default credentials!
```

---

### Security Bypass via CEDA

**Command**:
```bash
python main.py --target 192.168.1.1 --bypass
```

**Expected Output**:
```plaintext
2025-01-22 20:15:00 [INFO] Attempting security bypass via CEDA.
2025-01-22 20:15:02 [INFO] CEDA transaction executed successfully.
2025-01-22 20:15:03 [INFO] Security settings changed successfully.
```

---

## Technical Manual

### Installation & Setup

1. Install Python 3.8+.
2. Clone or download all files into the same directory.
3. Install any required dependencies (if any).

### Running the Program

- Interactive Mode:
  ```bash
  python main.py --interactive --target 192.168.1.1
  ```

- Command-Line Mode:
  ```bash
  python main.py --target 192.168.1.1 --bypass
  ```

---

## Support & Legal Disclaimer

**Use responsibly** on systems you own or have explicit permission to test. The authors are not responsible for misuse.

--- 

This document provides a comprehensive guide for using and understanding CICSPWN3. Let me know if you need further details!