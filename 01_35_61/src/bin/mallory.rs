use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use ed25519_dalek::{Signer, SigningKey};
use getrandom::{SysRng, rand_core::UnwrapErr};
use colour::*;

// Same payload format the honest clients sign over: "chat-v1" + seq + message.
fn signed_payload(seq: u64, msg: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(7 + 8 + msg.len());
    v.extend_from_slice(b"chat-v1");
    v.extend_from_slice(&seq.to_be_bytes());
    v.extend_from_slice(msg);
    v
}

// Read one framed message: 4-byte length, 8-byte seq, message, 64-byte signature.
fn read_frame(s: &mut TcpStream) -> Option<(u64, Vec<u8>, [u8; 64])> {
    let mut len_buf = [0u8; 4];
    s.read_exact(&mut len_buf).ok()?;
    let msg_len = u32::from_be_bytes(len_buf) as usize;

    let mut seq_buf = [0u8; 8];
    s.read_exact(&mut seq_buf).ok()?;
    let seq = u64::from_be_bytes(seq_buf);

    let mut msg = vec![0u8; msg_len];
    s.read_exact(&mut msg).ok()?;

    let mut sig = [0u8; 64];
    s.read_exact(&mut sig).ok()?;
    Some((seq, msg, sig))
}

fn write_frame(s: &mut TcpStream, seq: u64, msg: &[u8], sig: &[u8]) {
    let len = (msg.len() as u32).to_be_bytes();
    let _ = s.write_all(&len);
    let _ = s.write_all(&seq.to_be_bytes());
    let _ = s.write_all(msg);
    let _ = s.write_all(sig);
}

fn main() {
    // Mode: sniff | tamper | impersonate | substitute | replay
    let mode = std::env::args().nth(1).unwrap_or_else(|| "sniff".to_string());

    // Mallory's own key pair, used for the impersonate and substitute attacks.
    let mut csprng = UnwrapErr(SysRng);
    let m_secret = SigningKey::generate(&mut csprng);
    let m_public = m_secret.verifying_key();

    let listener = TcpListener::bind("127.0.0.1:9090").unwrap();
    yellow!("Mallory on 127.0.0.1:9090  mode: {}\n", mode);
    yellow!("Run Alice with:  cargo run --bin alice -- 127.0.0.1:9090\n\n");

    let (mut alice, _) = listener.accept().unwrap();
    let mut bob = TcpStream::connect("127.0.0.1:8080").unwrap();

    // --- Relay the handshake ---
    // 1. "Connected" banner from Bob to Alice.
    let mut conn = [0u8; 9];
    bob.read_exact(&mut conn).unwrap();
    alice.write_all(&conn).unwrap();

    // 2. Alice's public key, forwarded to Bob (or swapped in substitute mode).
    let mut alice_key = [0u8; 32];
    alice.read_exact(&mut alice_key).unwrap();
    if mode == "substitute" {
        red!("[substitute] Replacing Alice's public key with Mallory's key toward Bob\n");
        let hex: String = m_public.as_bytes().iter().map(|b| format!("{:02x}", b)).collect();
        yellow!("[substitute] Bob will now see peer fingerprint ...{}\n", &hex[hex.len() - 4..]);
        bob.write_all(m_public.as_bytes()).unwrap();
    } else {
        bob.write_all(&alice_key).unwrap();
    }

    // 3. Bob's public key, forwarded to Alice unchanged.
    let mut bob_key = [0u8; 32];
    bob.read_exact(&mut bob_key).unwrap();
    alice.write_all(&bob_key).unwrap();

    // --- Relay the message streams ---
    let mut alice_rd = alice.try_clone().unwrap();
    let mut bob_wr = bob.try_clone().unwrap();
    let mut bob_rd = bob;
    let mut alice_wr = alice;

    let mode_ab = mode.clone();
    // Alice -> Bob: the direction Mallory attacks.
    let a2b = thread::spawn(move || {
        let forged = b"(forged) Pay 500 to Mallory\n".to_vec();
        loop {
            match read_frame(&mut alice_rd) {
                None => break,
                Some((seq, msg, sig)) => match mode_ab.as_str() {
                    "tamper" => {
                        let mut m = msg.clone();
                        if !m.is_empty() {
                            m[0] ^= 0x20; // flip one bit of one character
                        }
                        red!("[tamper] Changed one byte, kept Alice's original signature\n");
                        write_frame(&mut bob_wr, seq, &m, &sig);
                    }
                    "impersonate" => {
                        // Bob holds Alice's REAL key (handshake was honest), but Mallory
                        // signs with its own key while claiming to be Alice.
                        let s = m_secret.sign(&signed_payload(seq, &forged));
                        red!("[impersonate] Forged a message signed with Mallory's key\n");
                        write_frame(&mut bob_wr, seq, &forged, &s.to_bytes());
                    }
                    "substitute" => {
                        // Bob holds Mallory's key, so Mallory's signature verifies.
                        let s = m_secret.sign(&signed_payload(seq, &forged));
                        red!("[substitute] Sending a forged message that Bob accepts as 'Alice'\n");
                        write_frame(&mut bob_wr, seq, &forged, &s.to_bytes());
                    }
                    "replay" => {
                        write_frame(&mut bob_wr, seq, &msg, &sig);
                        red!("[replay] Re-sending the captured message a second time\n");
                        write_frame(&mut bob_wr, seq, &msg, &sig);
                    }
                    _ => {
                        // sniff: forward unchanged, print the plaintext.
                        cyan!("[sniff] Alice -> Bob: ");
                        print!("{}", String::from_utf8_lossy(&msg));
                        write_frame(&mut bob_wr, seq, &msg, &sig);
                    }
                },
            }
        }
    });

    let mode_ba = mode.clone();
    // Bob -> Alice: always forwarded unchanged (only read for the sniff view).
    let b2a = thread::spawn(move || loop {
        match read_frame(&mut bob_rd) {
            None => break,
            Some((seq, msg, sig)) => {
                if mode_ba == "sniff" {
                    green!("[sniff] Bob -> Alice: ");
                    print!("{}", String::from_utf8_lossy(&msg));
                }
                write_frame(&mut alice_wr, seq, &msg, &sig);
            }
        }
    });

    let _ = a2b.join();
    let _ = b2a.join();
}
