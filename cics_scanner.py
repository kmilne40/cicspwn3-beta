import logging
import time

from tn3270_session import TN3270Session
from cics_utilities import is_valid_host, is_valid_port, decode_mainframe_output

class CICSScanner:
    """
    Provides scanning functionality to detect if CICS is running under a given APPLID,
    enumerates resources, and identifies basic potential vulnerabilities.
    """

    def __init__(self, host: str, port: int = 23, timeout: float = 10.0, applid: str = "CICS"):
        """
        :param host: Target host for scanning
        :param port: TN3270 port
        :param timeout: Connection/read timeout
        :param applid: The CICS region name or APPLID (e.g. "CICSTS56")
        """
        self.host = host
        self.port = port
        self.timeout = timeout
        self.applid = applid
        self.session = TN3270Session(host, port, timeout)

    def check_applid_validity(self) -> bool:
        """
        Attempts to open a session, pass 'L <applid>', and check if the response
        indicates a valid CICS region.
        """
        logging.info(f"Checking validity by sending 'L {self.applid}' to {self.host}:{self.port}")
        try:
            self.session.open_session()

            # 1. Send "L <applid>"
            self.session.send_vtam_command(f"L {self.applid}")
            time.sleep(1.0)

            # Press Enter or blank lines multiple times to advance any screens
            for _ in range(3):
                self.session.send_vtam_command("")
                time.sleep(0.8)

            # 2. Read until no new data arrives
            screen_data = b""
            no_new_data_iterations = 0
            max_iterations = 5

            while no_new_data_iterations < max_iterations:
                chunk = self.session.read_screen()
                if chunk:
                    screen_data += chunk
                    no_new_data_iterations = 0
                else:
                    no_new_data_iterations += 1
                time.sleep(0.5)

            # 3. Decode final screen data
            decoded = decode_mainframe_output(screen_data)
            logging.debug(f"[check_applid_validity] Decoded output:\n{decoded}")

            # 4. Look for any common CICS markers
            valid_markers = ["CICS", "DFH", "SIGN-ON", "CESN", "CECI", "CICSTS"]
            return any(marker in decoded.upper() for marker in valid_markers)

        except Exception as ex:
            logging.error(f"Error sending 'L {self.applid}': {ex}")
            return False
        finally:
            self.session.close_session()

    def run_basic_enum(self) -> dict:
        """
        Runs a basic enumeration of CICS resources or screens.
        """
        results = {}
        try:
            self.session.open_session()

            # Use "L <applid>"
            self.session.send_vtam_command(f"L {self.applid}")
            time.sleep(1.0)

            # Example: check CESN screen
            self.session.send_vtam_command("CESN")
            time.sleep(1.0)
            data_cesn = decode_mainframe_output(self.session.read_screen())
            results["CESN"] = data_cesn

            # Example: check CECI screen
            self.session.send_vtam_command("CECI")
            time.sleep(1.0)
            data_ceci = decode_mainframe_output(self.session.read_screen())
            results["CECI"] = data_ceci

        except Exception as ex:
            logging.error(f"Error in basic enumeration: {ex}")
        finally:
            self.session.close_session()

        return results

    @staticmethod
    def multi_applid_scan(host_list, port=23, applid="CICS", timeout=10.0):
        """
        Scan multiple hosts for the same APPLID. 
        Returns a list of hosts on which the APPLID appears valid.
        """
        valid_hosts = []
        for host in host_list:
            if not is_valid_host(host) or not is_valid_port(port):
                logging.warning(f"Skipping invalid host/port: {host}:{port}")
                continue
            scanner = CICSScanner(host, port, timeout, applid)
            if scanner.check_applid_validity():
                logging.info(f"{host}:{port} responded positively to 'L {applid}'")
                valid_hosts.append(host)
        return valid_hosts
