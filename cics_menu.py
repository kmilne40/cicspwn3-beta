import logging
from cics_scanner import CICSScanner
from cics_exploits import CICSExploits
from cics_utilities import is_valid_port

def display_menu() -> None:
    """
    Display the interactive menu options.
    """
    menu = """
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
    """
    print(menu)

def run_interactive(target: str, port: int, applid: str, timeout: float, default_applid: str):
    """
    Interactive menu to dynamically configure and execute functionality.
    """
    while True:
        print(f"[Target: {target}, Port: {port}, APPLID: {applid}, Timeout: {timeout}]")
        display_menu()
        choice = input("Select an option: ").strip()

        if choice == "1":
            scanner = CICSScanner(target, port, timeout, applid)
            valid = scanner.check_applid_validity()
            print(f"APPLID '{applid}' is {'valid' if valid else 'invalid'}.")
        elif choice == "2":
            scanner = CICSScanner(target, port, timeout, applid)
            results = scanner.run_basic_enum()
            print("Enumeration Results:")
            for key, value in results.items():
                print(f"{key}: {value}")
        elif choice == "3":
            user = input("Enter user ID: ").strip()
            password = input("Enter password: ").strip()
            exploit = CICSExploits(target, port, timeout, applid)
            success = exploit.exploit_default_credentials(user or "CICS", password or "CICS")
            print("Default Credentials Exploit:", "Success" if success else "Failed")
        elif choice == "4":
            transaction = input("Enter transaction name: ").strip()
            command = input("Enter transaction command: ").strip()
            exploit = CICSExploits(target, port, timeout, applid)
            success = exploit.exploit_transaction_command(transaction, command)
            print("Transaction Exploit:", "Success" if success else "Failed")
        elif choice == "5":
            exploit = CICSExploits(target, port, timeout, applid)
            success = exploit.exploit_arbitrary_commands()
            print("Arbitrary Commands Exploit:", "Success" if success else "Failed")
        elif choice == "6":
            exploit = CICSExploits(target, port, timeout, applid)
            success = exploit.security_bypass_exploit()
            print("Security Bypass Exploit:", "Success" if success else "Failed")
        elif choice == "7":
            threads_str = input("Enter number of threads: ").strip()
            try:
                threads = int(threads_str)
                exploit = CICSExploits(target, port, timeout, applid)
                exploit.brute_force_login(threads=threads)
            except ValueError:
                print("Invalid thread count. Skipping brute force.")
        elif choice == "8":
            exploit = CICSExploits(target, port, timeout, applid)
            marker_results = exploit.scan_for_cics_markers()
            print("Marker Scan Results:")
            for txn, result in marker_results.items():
                print(f"{txn}: {result}")
        elif choice == "9":
            new_applid = input("Enter new APPLID: ").strip()
            if new_applid:
                applid = new_applid
                print(f"APPLID changed to: {applid}")
        elif choice == "10":
            new_port = input("Enter new port: ").strip()
            try:
                new_port = int(new_port)
                if is_valid_port(new_port):
                    port = new_port
                    print(f"Port changed to: {port}")
                else:
                    print("Invalid port. Keeping current port.")
            except ValueError:
                print("Invalid input. Keeping current port.")
        elif choice == "11":
            print("Exiting. Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")
