
import socket
import threading

from messaging import receive_packet, send_packet


HOST = "127.0.0.1"
PROXY_PORT = 5057
BOB_HOST = "127.0.0.1"
BOB_PORT = 5056


def handle_client(connection, address):
    with connection:
        try:
            packet = receive_packet(connection)

            print(f"\nMallory intercepted a packet from {address}")
            print("Sender:", packet.get("sender"))
            print("Recipient:", packet.get("recipient"))
            print("Message ID:", packet.get("message_id"))

            # Forward the packet unchanged to Bob.
            response = send_packet(BOB_HOST, BOB_PORT, packet)

            print("Mallory forwarded the packet unchanged.")
            connection.sendall(response.encode("utf-8"))

        except (ValueError, ConnectionError, OSError) as error:
            print("Proxy error:", error)

            try:
                connection.sendall(
                    ("PROXY ERROR: " + str(error)).encode("utf-8")
                )
            except OSError:
                pass


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PROXY_PORT))
        server.listen()

        print(f"Mallory proxy listening on {HOST}:{PROXY_PORT}")
        print(f"Forwarding packets to Bob at {BOB_HOST}:{BOB_PORT}")

        while True:
            connection, address = server.accept()

            thread = threading.Thread(
                target=handle_client,
                args=(connection, address),
                daemon=True
            )
            thread.start()


if __name__ == "__main__":
    main()
