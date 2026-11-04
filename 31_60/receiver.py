
from crypto_utils import open_packet


class SecureReceiver:
    def __init__(self, name, aes_key, trusted_keys):
        self.name = name
        self.aes_key = aes_key
        self.trusted_keys = trusted_keys
        self.received_ids = set()

    def handle_packet(self, packet):
        # Check the recipient before processing.
        if packet.get("recipient") != self.name:
            raise ValueError("Incorrect recipient.")

        message_id = packet.get("message_id")

        if not isinstance(message_id, str) or not message_id:
            raise ValueError("Invalid message ID.")

        # Reject a message that has already been accepted.
        if message_id in self.received_ids:
            raise ValueError("Replay detected.")

        # Verify the signature and decrypt the message.
        plaintext = open_packet(
            packet,
            self.name,
            self.aes_key,
            self.trusted_keys
        )

        # Record the ID only after successful verification and decryption.
        self.received_ids.add(message_id)

        return plaintext
