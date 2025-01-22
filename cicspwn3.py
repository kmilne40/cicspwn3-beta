import logging
import sys
from argparse import ArgumentParser

from cics_scanner import CICSScanner
from cics_exploits import CICSExploits
from cics_menu import run_interactive
from cics_utilities import is_valid_host, is_valid_port


def parse_arguments():
    """
    Parse command-line arguments, including restored and extended options.
    """
    parser = ArgumentParser(description="cicspwn - Enhanced Python 3 version for CICS testing")

    # Target and connection parameters
    parser.add_argument("-t", "--target", help="Target host to scan/exploit")
    parser.add_argument("-p", "--port", type=int, default=23, help="Telnet port (default: 23)")
    parser.add_argument("--applid", default="CICS", help="APPLID to use (default: 'CICS')")
    parser.add_argument("--timeout", type=float, default=10.0, help="Connection timeout in seconds")

    # Scanning and enumeration
    parser.add_argument("--check", action="store_true", help="Check if the specified APPLID is valid")
    parser.add_argument("--enum", action="store_true", help="Perform basic enumeration of the target")

    # Exploit options
    parser.add_argument("--exploit-default-creds", action="store_true", help="Attempt default credentials exploit")
    parser.add_argument("--user", default="", help="User ID for default credential exploit")
    parser.add_argument("--password", default="", help="Password for default credential exploit")
    parser.add_argument("--exploit-transaction", action="store_true", help="Attempt transaction command exploit")
    parser.add_argument("--transaction", default="", help="Transaction name (e.g., 'CECI')")
    parser.add_argument("--command", default="", help="Command or parameter for the transaction exploit")
    parser.add_argument("--exploit-arbitrary", action="store_true", help="Attempt arbitrary commands exploit")

    # Security bypass and brute force
    parser.add_argument("--bypass", action="store_true", help="Attempt to bypass security mechanisms")
    parser.add_argument("--brute-force", action="store_true", help="Perform brute-force login attempts")
    parser.add_argument("--threads", type=int, default=5, help="Number of threads to use for brute-forcing")

    # Default settings and interactive mode
    parser.add_argument("--default-applid", default="CICS", help="Set default APPLID (used interactively)")
    parser.add_argument("--interactive", action="store_true", help="Run interactive menu")

    # Logging verbosity
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")

    return parser.parse_args()


def setup_logging(verbose: bool) -> None:
    """
    Configure logging with optional debug verbosity.
    """
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def main():
    """
    Main entry point for the script.
    """
    args = parse_arguments()
    setup_logging(args.verbose)

    # Handle interactive mode
    if args.interactive:
        if not args.target:
            logging.error("Interactive mode requires a target host (--target/-t).")
            sys.exit(1)
        run_interactive(
            target=args.target,
            port=args.port,
            applid=args.applid,
            timeout=args.timeout,
            default_applid=args.default_applid,
        )
        sys.exit(0)

    # Validate required arguments
    if not args.target:
        logging.error("You must specify a --target or -t.")
        sys.exit(1)
    if not is_valid_host(args.target):
        logging.error(f"Invalid host specified: {args.target}")
        sys.exit(1)
    if not is_valid_port(args.port):
        logging.error(f"Invalid port specified: {args.port}")
        sys.exit(1)

    # Instantiate scanner and exploits
    scanner = CICSScanner(args.target, args.port, args.timeout, args.applid)
    exploits = CICSExploits(args.target, args.port, args.timeout, args.applid)

    # Perform actions based on command-line flags
    if args.check:
        valid = scanner.check_applid_validity()
        logging.info(f"APPLID '{args.applid}' is {'valid' if valid else 'invalid'} on {args.target}:{args.port}")

    if args.enum:
        logging.info("Running basic CICS enumeration...")
        results = scanner.run_basic_enum()
        for key, value in results.items():
            logging.info(f"{key}: {value}")

    if args.exploit_default_creds:
        user = args.user or "CICS"
        password = args.password or "CICS"
        success = exploits.exploit_default_credentials(user, password)
        logging.info(f"Default credentials exploit {'succeeded' if success else 'failed'}.")

    if args.exploit_transaction:
        if not args.transaction:
            logging.error("Transaction name (--transaction) is required for exploit.")
        else:
            success = exploits.exploit_transaction_command(args.transaction, args.command)
            logging.info(f"Transaction exploit {'succeeded' if success else 'failed'}.")

    if args.exploit_arbitrary:
        success = exploits.exploit_arbitrary_commands()
        logging.info(f"Arbitrary commands exploit {'succeeded' if success else 'failed'}.")

    if args.bypass:
        logging.info("Attempting to bypass security... (placeholder)")
        # Add bypass logic here

    if args.brute_force:
        logging.info(f"Starting brute-force login attempts with {args.threads} threads...")
        # Add brute force logic here
        logging.info("Brute force attack completed.")


if __name__ == "__main__":
    main()
