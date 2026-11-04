"""Minimal two-user messaging GUI: local simulation using shared crypto helpers."""
import json
import tkinter as tk
from tkinter import ttk
from crypto_utils import create_keys, create_packet, verify_packet
from receiver import SecureReceiver

key, private_keys, trusted_keys = create_keys()
receivers = {n: SecureReceiver(n, key, trusted_keys) for n in ('Alice', 'Bob')}
root = tk.Tk()
root.title('Secure Messaging — Alice and Bob')
root.geometry('800x640')
root.minsize(670, 530)
frame = ttk.Frame(root, padding=18)
frame.pack(fill='both', expand=True)
ttk.Label(frame, text='Secure Messaging', font=('Segoe UI', 18, 'bold')).pack(anchor='w')
ttk.Label(frame, text='AES-256-GCM + Ed25519 | Local Alice/Bob simulation').pack(anchor='w', pady=(0, 12))
row = ttk.Frame(frame)
row.pack(fill='x')
ttk.Label(row, text='Sender:').pack(side='left')
sender = tk.StringVar(value='Alice')
ttk.Combobox(row, values=('Alice', 'Bob'), textvariable=sender, state='readonly', width=12).pack(side='left', padx=8)
ttk.Label(row, text='Recipient selected automatically').pack(side='left')
ttk.Label(frame, text='Plaintext:').pack(anchor='w', pady=(12, 3))
entry = tk.Text(frame, height=3, wrap='word')
entry.pack(fill='x')
entry.insert('1.0', 'Hello Bob! This is a secure message.')
status = tk.StringVar(value='Ready.')
ttk.Label(frame, textvariable=status, font=('Segoe UI', 10, 'bold'), wraplength=740).pack(anchor='w', pady=(10, 8))
ttk.Label(frame, text='Transmitted packet (Base64 ciphertext includes the 16-byte GCM tag):').pack(anchor='w')
packet_view = tk.Text(frame, height=12, font=('Consolas', 9), wrap='word')
packet_view.pack(fill='both', expand=True, pady=(3, 8))
ttk.Label(frame, text='Receiver verification and plaintext:').pack(anchor='w')
result_view = tk.Text(frame, height=5, font=('Consolas', 10), wrap='word')
result_view.pack(fill='x', pady=(3, 8))
for w in (packet_view, result_view):
    w.configure(state='disabled')

def show(w, value):
    w.configure(state='normal')
    w.delete('1.0', 'end')
    w.insert('1.0', value)
    w.configure(state='disabled')

def send():
    who = sender.get()
    target = 'Bob' if who == 'Alice' else 'Alice'
    message = entry.get('1.0', 'end-1c').strip()
    try:
        packet = create_packet(who, target, message, key, private_keys)
        verified = verify_packet(packet, trusted_keys)
        received = receivers[target].handle_packet(packet)
    except (ValueError, TypeError, KeyError) as error:
        status.set('REJECTED — ' + str(error))
        show(result_view, 'No message delivered.\nReason: ' + str(error))
        return
    show(packet_view, json.dumps(packet, indent=2))
    show(result_view, f'From: {who}\nTo: {target}\nEd25519 signature: VALID\nAES-GCM: AUTHENTICATED\nRecovered plaintext: {received}')
    status.set(f'ACCEPTED — {who} → {target}')

ttk.Button(frame, text='Encrypt, Sign and Send', command=send).pack(anchor='w')
ttk.Label(frame, text='Security experiments: open a separate terminal and run python attack_lab.py').pack(anchor='w', pady=(10, 0))
if __name__ == '__main__':
    root.mainloop()
