import telnetlib
import time
import logging

class TelnetHandler:
    """
    Manages a Telnet connection for the CICS enumerations and interactions.
    Provides basic reading and writing functionality.
    """

    def __init__(self, host: str, port: int = 23, timeout: float = 10.0):
        """
        Initialise the Telnet handler.

        :param host: Target hostname/IP
        :param port: Telnet port (default 23)
        :param timeout: Connection/read timeout
        """
        self.host = host
        self.port = port
        self.timeout = timeout
        self.tn = None

    def connect(self) -> None:
        """
        Establish a Telnet connection to the specified host and port.
        """
        logging.debug(f"Connecting to {self.host}:{self.port} via Telnet...")
        self.tn = telnetlib.Telnet(self.host, self.port, self.timeout)
        logging.info("Telnet connection established.")

    def close(self) -> None:
        """
        Close the Telnet connection if open.
        """
        if self.tn:
            logging.debug("Closing Telnet connection.")
            self.tn.close()
            self.tn = None

    def send_data(self, data: bytes, carriage_return: bool = True) -> None:
        """
        Write data over Telnet as bytes. Optionally append \r\n.
        """
        if not self.tn:
            raise ConnectionError("Telnet connection is not open.")
        logging.debug(f"Sending data: {data}")
        to_send = data + (b"\r\n" if carriage_return else b"")
        self.tn.write(to_send)
        time.sleep(0.2)  # Slight pause for the mainframe to respond

    def read_until(self, expected: bytes, timeout: float = None) -> bytes:
        """
        Read data from Telnet until the 'expected' marker appears or a timeout occurs.
        """
        if not self.tn:
            raise ConnectionError("Telnet connection is not open.")
        if timeout is None:
            timeout = self.timeout
        output = self.tn.read_until(expected, timeout)
        logging.debug(f"Read until {expected!r}, received {output!r}")
        return output

    def read_eager(self) -> bytes:
        """
        Read any data available right now without blocking.
        """
        if not self.tn:
            raise ConnectionError("Telnet connection is not open.")
        try:
            data = self.tn.read_very_eager()
            logging.debug(f"Read eager data: {data!r}")
            return data
        except EOFError:
            logging.debug("EOF encountered on Telnet read.")
            return b""

    def interact(self) -> None:
        """
        Give the user an interactive Telnet session (for debugging or manual exploitation).
        """
        if not self.tn:
            raise ConnectionError("Telnet connection is not open.")
        logging.info("Dropping into Telnet interactive mode. Press Ctrl+] to exit.")
        self.tn.interact()
