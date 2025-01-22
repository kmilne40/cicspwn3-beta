import re

def is_valid_host(host: str) -> bool:
    """
    Validate if the given string could be an IP address or resolvable hostname.
    """
    ip_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    match = re.match(ip_pattern, host)
    if match:
        segments = host.split(".")
        return all(0 <= int(seg) <= 255 for seg in segments)
    return bool(host)  # If not an IP, we assume it's a valid hostname

def is_valid_port(port: int) -> bool:
    """
    Return True if the port is in the valid TCP range (1-65535).
    """
    return 1 <= port <= 65535

def decode_mainframe_output(data: bytes) -> str:
    """
    Decode mainframe output from EBCDIC CP037 (or fallback).
    If you are certain it's CP037, keep it strictly so (removing fallback).
    Here, we attempt CP037 and replace invalid sequences.
    """
    return data.decode("cp037", errors="replace")
