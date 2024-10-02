#!/usr/bin/python3
import socket
import struct
import time
from datetime import datetime, timedelta

NTP_PORT = 124  # Standard NTP port
NTP_TIMESTAMP_DELTA = 2208988800  # Difference between 1970 and 1900 in seconds
NTP_SERVER = 'au.pool.ntp.org'  # External NTP server

def get_time_from_ntp_server():
    """Gets the current time from an external NTP server."""
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_socket.settimeout(2)  # Timeout for the NTP request

    # NTP request packet (all zeroes)
    request_packet = b'\x1b' + 47 * b'\0'

    try:
        client_socket.sendto(request_packet, (NTP_SERVER, 123))
        response_packet, _ = client_socket.recvfrom(1024)

        # Unpack the response to get the transmit timestamp
        ntp_data = struct.unpack('!12I', response_packet)
        ntp_time = ntp_data[10] # Convert to seconds since epoch

        return ntp_time
    except Exception as e:
        print(f"Failed to get time from NTP server: {e}")
        return time.time()  # Fallback to the local time


def is_dst():
    """Check if the current date is within DST (first Sunday of October to first Sunday of April)."""
    now = datetime.now()

    # Get the first Sunday of April and October for the current year
    first_april = datetime(now.year, 4, 1)
    first_october = datetime(now.year, 10, 1)

    first_sunday_april = first_april + timedelta(days=(6 - first_april.weekday()))
    first_sunday_october = first_october + timedelta(days=(6 - first_october.weekday()))

    # DST is active between the first Sunday of October and the first Sunday of April
    if first_sunday_april <= now < first_sunday_october:
        return False  # Not DST
    return True  # DST


def get_spoofed_ntp_time():
    """Returns the current NTP time with an automatic DST offset if applicable."""
    current_time = get_time_from_ntp_server()  # Get time from external NTP server
    offset_hours = 1 if is_dst() else 0  # Apply +1 hour during DST, no offset otherwise
    spoofed_time = current_time + (offset_hours * 3600)  # Apply the UTC offset
    return spoofed_time

def create_ntp_response(client_data):
    client_packet = struct.unpack('!12I', client_data)
    client_transmit_timestamp_sec = client_packet[10]  # Client's transmit timestamp (seconds)
    client_transmit_timestamp_frac = client_packet[11]  # Client's transmit timestamp (fraction)

    # Get the spoofed NTP time with the offset applied
    spoofed_ntp_time = get_spoofed_ntp_time()

    # Calculate fractional seconds for the spoofed time
    fractional_seconds = int((spoofed_ntp_time % 1) * (2**32))  # This will usually be 0 for an integer

    # Ensure we are working with an integer for spoofed_time
    spoofed_ntp_time_int = int(spoofed_ntp_time)

    # LI = 0 (no warning), Version = 4, Mode = 4 (server)
    LI_VN_MODE = (0 << 6) | (4 << 3) | 4

    # Create the NTP response packet with proper timestamps
    packet = struct.pack(
        '!B b b b 11I',
        LI_VN_MODE,   # Leap Indicator, Version, Mode
        1,            # Stratum (1 for primary server)
        4,            # Poll interval (signed 8-bit)
        -20,          # Precision (signed 8-bit)
        0,            # Root delay (not used)
        0,            # Root dispersion (not used)
        0x4C4F434C,   # Reference Identifier ("LOCL" for local clock)
        spoofed_ntp_time_int,  # Reference Timestamp (spoofed)
        fractional_seconds,     # Fractional part of reference timestamp
        client_transmit_timestamp_sec,  # Originate Timestamp (seconds, from client)
        client_transmit_timestamp_frac,  # Fractional part of originate timestamp
        spoofed_ntp_time_int,  # Receive Timestamp (spoofed)
        fractional_seconds,      # Fractional part of receive timestamp
        spoofed_ntp_time_int,  # Transmit Timestamp (spoofed)
        fractional_seconds       # Fractional part of transmit timestamp
    )

    return packet

def run_ntp_server():
    """Runs the NTP server, applying the automatic DST offset."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('', NTP_PORT))
    print(f"NTP server started on port {NTP_PORT}")

    while True:
        client_data, client_address = server_socket.recvfrom(1024)
        print(f"Received NTP request from {client_address}")

        # Create the NTP response with the spoofed time
        response_packet = create_ntp_response(client_data)

        # Send the response back to the client
        server_socket.sendto(response_packet, client_address)

if __name__ == '__main__':
    # Start the NTP server
    run_ntp_server()


