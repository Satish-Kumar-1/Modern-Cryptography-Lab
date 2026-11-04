"""Interactive controlled security experiments, using the actual project crypto functions."""
import copy
import json
import uuid
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from crypto_utils import (create_keys, create_packet, verify_packet, decrypt_packet,
                          decode, encode, make_aad)
from receiver import SecureReceiver

KEY, PRIVATE, TRUSTED = create_keys()
BOB = SecureReceiver('Bob', KEY, TRUSTED)


def new_packet():
    message = input('Alice plaintext [Hello Bob]: ').strip() or 'Hello Bob'
    return create_packet('Alice', 'Bob', message, KEY, PRIVATE)


def changed(before, after):
    return [name for name in sorted(set(before) | set(after)) if before.get(name) != after.get(name)]


def show_changes(before, after):
    keys = changed(before, after)
    print('\nChanged fields:', ', '.join(keys) if keys else '(none)')
    for name in keys:
        print('  FIELD:', name)
        print('  BEFORE:', repr(before.get(name)))
        print('  AFTER: ', repr(after.get(name)))


def deliver(packet):
    print('Receiver: Bob | actual SecureReceiver.handle_packet()')
    try:
        msg = BOB.handle_packet(packet)
        print('RESULT: ACCEPTED | plaintext:', msg)
        return True
    except (ValueError, KeyError, TypeError) as exc:
        print('RESULT: REJECTED | reason:', exc)
        return False


def edit_menu(packet):
    print('Choose field to edit: 1 manually type ciphertext, 2 signature bit, 3 recipient, 4 sender, 5 message ID, 6 nonce bit, 7 raw JSON editor, 8 no change, 9 automatic ciphertext bit flip')
    choice = input('Edit: ').strip()
    if choice == '1':
        original_ciphertext = packet['ciphertext']
        print('\nORIGINAL CIPHERTEXT (Base64):')
        print(original_ciphertext)
        print('Type or paste the FULL modified Base64 ciphertext below.')
        print('Tip: change one character, keeping the rest of the text unchanged.')
        replacement = input('MODIFIED CIPHERTEXT: ').strip()
        if not replacement:
            print('No ciphertext entered; attack cancelled.')
            return False
        try:
            decoded = decode(replacement)
            if not decoded:
                raise ValueError('Empty ciphertext')
        except (ValueError, TypeError) as exc:
            print('INVALID BASE64 CIPHERTEXT:', exc)
            return False
        packet['ciphertext'] = replacement
    elif choice in ('2', '6', '9'):
        field = {'2':'signature', '6':'nonce', '9':'ciphertext'}[choice]
        data = bytearray(decode(packet[field]))
        data[0] ^= 1
        packet[field] = encode(bytes(data))
    elif choice == '3':
        packet['recipient'] = input('New recipient [Mallory]: ').strip() or 'Mallory'
    elif choice == '4':
        packet['sender'] = input('New sender [Mallory]: ').strip() or 'Mallory'
    elif choice == '5':
        packet['message_id'] = input('New message ID [random]: ').strip() or str(uuid.uuid4())
    elif choice == '7':
        print('Paste a complete JSON object on ONE line:')
        try:
            obj = json.loads(input('JSON: '))
            if not isinstance(obj, dict):
                raise ValueError('JSON root must be an object')
            packet.clear()
            packet.update(obj)
        except (json.JSONDecodeError, ValueError) as exc:
            print('JSON FORMAT ERROR:', exc, '| no cryptographic check performed')
            return False
    return True


def manual_attack():
    original = new_packet()
    print('\nINTERCEPTED ORIGINAL PACKET (not yet delivered):')
    print(json.dumps(original, indent=2))
    edited = copy.deepcopy(original)
    if not edit_menu(edited):
        return
    show_changes(original, edited)
    print('\nFORWARDING TO BOB:')
    deliver(edited)
    print('NOTE: A modified signed field usually fails Ed25519 before AES-GCM is reached.')


def aes_gcm_attack():
    original = new_packet()
    changed_packet = copy.deepcopy(original)
    ciphertext = bytearray(decode(changed_packet['ciphertext']))
    ciphertext[0] ^= 1
    changed_packet['ciphertext'] = encode(bytes(ciphertext))
    show_changes(original, changed_packet)
    print('ISOLATED AES-GCM TEST: signature verification is deliberately skipped.')
    print('This is a controlled cryptographic test, not a claim that Mallory has Alice\'s signing key.')
    try:
        AESGCM(KEY).decrypt(decode(changed_packet['nonce']), decode(changed_packet['ciphertext']), make_aad(changed_packet))
    except InvalidTag:
        print('RESULT: REJECTED | AES-GCM raised InvalidTag (authentication failure)')
    else:
        print('RESULT: UNEXPECTED ACCEPTANCE | inspect implementation')


def impersonation():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from crypto_utils import signed_data
    original = new_packet()
    forged = copy.deepcopy(original)
    attacker_key = Ed25519PrivateKey.generate()
    forged['signature'] = encode(attacker_key.sign(signed_data(forged)))
    show_changes(original, forged)
    print('Mallory signs with an UNTRUSTED key while claiming to be Alice.')
    deliver(forged)


def replay():
    packet = new_packet()
    print('\nFIRST DELIVERY (valid):')
    deliver(packet)
    print('\nSECOND DELIVERY (identical packet):')
    deliver(packet)
    print('The packet is unchanged. The second delivery should fail due to its repeated message ID.')


def replay_comparison():
    packet = new_packet()
    print('CONTROL: a receiver without replay tracking')
    for i in (1, 2):
        try:
            verify_packet(packet, TRUSTED)
            msg = decrypt_packet(packet, 'Bob', KEY)
            print(f'Delivery {i}: ACCEPTED | {msg}')
        except (ValueError, KeyError, TypeError) as exc:
            print(f'Delivery {i}: REJECTED | {exc}')
    print('Two acceptances demonstrate that signatures and AES-GCM alone do not stop replay.')


def nonce_test():
    count = 1000
    nonces = [create_packet('Alice', 'Bob', 'nonce sample', KEY, PRIVATE)['nonce'] for _ in range(count)]
    print(f'Generated: {count} | Unique: {len(set(nonces))} | Nonce length: 12 bytes')
    print('Random nonces reduce collision risk; this sample does NOT prove future uniqueness.')
    print('Reusing an AES-GCM nonce with the same key can compromise confidentiality and authentication.')


def main():
    options = {'1': ('Manual packet tampering (type edited ciphertext/signature/metadata)', manual_attack),
               '2': ('Isolated AES-GCM tampering', aes_gcm_attack),
               '3': ('Sender impersonation', impersonation),
               '4': ('Replay defence', replay),
               '5': ('Replay without defence (comparison)', replay_comparison),
               '6': ('Nonce management', nonce_test)}
    while True:
        print('\n===== SECURE MESSAGING — TERMINAL ATTACK LAB =====')
        for k, (name, _) in options.items():
            print(f'{k}. {name}')
        print('0. Exit')
        selection = input('Choose experiment: ').strip()
        if selection == '0':
            break
        if selection not in options:
            print('Invalid selection.')
            continue
        print('\nEXPERIMENT:', options[selection][0])
        try:
            options[selection][1]()
        except (ValueError, TypeError, KeyError, IndexError) as exc:
            print('TEST INPUT ERROR:', exc)

if __name__ == '__main__':
    main()
