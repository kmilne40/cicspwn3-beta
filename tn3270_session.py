import logging
import time

# Import the TN3270 class from your tn3270lib
from tn3270lib import TN3270

class TN3270Session:
    """
    Emulates a 3270 session to a mainframe using tn3270lib for proper TN3270 negotiation.
    Offers methods similar to a raw Telnet session but is 3270-aware.
    """

    def __init__(self, host: str, port: int = 23, timeout: float = 10.0):
        """
        :param host: Mainframe IP/hostname
        :param port: 23 (plaintext) or possibly 992 (TLS/SSL)
        :param timeout: Connection/read timeout in seconds
        """
        self.host = host
        self.port = port
        self.timeout = timeout
        self.tn = None  # Will store an instance of TN3270 once connected

    def open_session(self) -> None:
        """
        Open a 3270 connection using tn3270lib.
        """
        logging.debug(f"Opening TN3270 session to {self.host}:{self.port}")
        self.tn = TN3270()
        # Adjust debug level if you want more logs from tn3270lib
        self.tn.set_debuglevel(0)

        connected = self.tn.initiate(self.host, self.port, self.timeout)
        if not connected:
            raise ConnectionError(f"Unable to connect via TN3270 to {self.host}:{self.port}")

        logging.info("TN3270 session established successfully.")

    def close_session(self) -> None:
        """
        Close the 3270 connection if open.
        """
        if self.tn:
            logging.debug("Closing TN3270 session.")
            self.tn.disconnect()
            self.tn = None

    def send_vtam_command(self, command: str) -> None:
        """
        In TN3270 land, we typically place text at the cursor and send an AID (Enter).
        We'll do a simple 'type command + press Enter' approach.
        """
        if not self.tn:
            raise ConnectionError("TN3270 session is not open.")

        logging.debug(f"Sending 3270 command: {command}")
        # 'send_cursor' types the text at the current cursor position in EBCDIC
        self.tn.send_cursor(command)
        # Then we press Enter to submit
        self.tn.send_enter()

        # Brief pause so the mainframe can process the input
        time.sleep(0.5)

    def read_screen(self) -> bytes:
        """
        Read data from the 3270 session. We'll call get_all_data to ensure
        we capture everything. We'll return raw bytes, which the caller can decode.
        """
        if not self.tn:
            raise ConnectionError("TN3270 session is not open.")

        self.tn.get_all_data()  # retrieve all waiting data
        # tn.raw_tn is a list of data blocks read after each EOR (end-of-record)
        raw_bytes = b"".join(self.tn.raw_screen_buffer())
        # Clear out raw_tn to avoid duplications next time
        self.tn.raw_tn = []

        return raw_bytes
