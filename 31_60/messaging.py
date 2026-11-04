
import socket
import json
import struct

MAX_PACKET_SIZE = 1_000_000


def send_packet(host, port, packet):
    """Send one JSON packet to a TCP server."""

    data = json.dumps(packet).encode("utf-8")

    if len(data) > MAX_PACKET_SIZE:
        raise ValueError("Packet is too large.")

    # Prefix the packet with its 4-byte length.
    header = struct.pack("!I", len(data))

    with socket.create_connection((host, port), timeout=5) as client:
        client.sendall(header + data)

        # Receive a short acknowledgement.
        response = client.recv(1024)

    return response.decode("utf-8")


def receive_exact(connection, size):
    """Read exactly the requested number of bytes."""

    data = bytearray()

    while len(data) < size:
        chunk = connection.recv(size - len(data))

        if not chunk:
            raise ConnectionError("Connection closed unexpectedly.")

        data.extend(chunk)

    return bytes(data)


def receive_packet(connection):
    """Receive and decode one length-prefixed JSON packet."""

    header = receive_exact(connection, 4)
    packet_size = struct.unpack("!I", header)[0]

    if packet_size == 0 or packet_size > MAX_PACKET_SIZE:
        raise ValueError("Invalid packet size.")

    data = receive_exact(connection, packet_size)

    try:
        packet = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("Invalid JSON packet.")

    if not isinstance(packet, dict):
        raise ValueError("Packet must be a JSON object.")

    return packet


def start_receiver(host, port, handle_packet):
    """Listen for packets and pass each one to a handler."""

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen()

        print(f"Receiver listening on {host}:{port}")

        while True:
            connection, address = server.accept()

            with connection:
                try:
                    packet = receive_packet(connection)

                    # The handler verifies and processes the packet.
                    result = handle_packet(packet)

                    connection.sendall(
                        ("ACCEPTED: " + result).encode("utf-8")
                    )

                    print(f"Accepted packet from {address}")

                except (ValueError, ConnectionError, OSError) as error:
                    message = "REJECTED: " + str(error)

                    try:
                        connection.sendall(message.encode("utf-8"))
                    except OSError:
                        pass

                    print(message)
