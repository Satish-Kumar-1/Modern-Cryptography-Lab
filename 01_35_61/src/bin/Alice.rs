use std::io::{Write, stdout, stdin, Read};
use std::net::TcpStream;
use std::thread;
use ed25519_dalek::{ Signer, SigningKey, Signature, VerifyingKey, Verifier};
use getrandom::{SysRng, rand_core::{UnwrapErr}};
use colour::*;

fn signed_payload(seq: u64, msg: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(7 + 8 + msg.len());
    v.extend_from_slice(b"chat-v1");
    v.extend_from_slice(&seq.to_be_bytes());
    v.extend_from_slice(msg);
    v
}

fn handle_server(stream:TcpStream , secret_key: SigningKey,sender_public_key: VerifyingKey){
	let mut write_stream:TcpStream=stream.try_clone().unwrap();
	let mut read_stream=stream;

	//reading thread
	thread::spawn(move || {
		let mut expected_seq: u64 = 0;
		loop{
			let mut len_buf = [0u8; 4];
            if read_stream.read_exact(&mut len_buf).is_err() {
				red!("Connection disconnected");
	            std::process::exit(0);
            }

            let msg_len = u32::from_be_bytes(len_buf) as usize;
            if msg_len > 10 * 1024 * 1024 {
				red!("Message too large");
                break;
           }

            let mut seq_buf = [0u8; 8];
            if read_stream.read_exact(&mut seq_buf).is_err() {
                red!("Failed to read seq");
                break;
            }
            let seq = u64::from_be_bytes(seq_buf);

            let mut msg_buf = vec![0u8; msg_len];
            if read_stream.read_exact(&mut msg_buf).is_err() {
				red!("Failed to read message");
                break;
            }

            let mut signature_buf = [0u8; 64];
            if read_stream.read_exact(&mut signature_buf).is_err() {
				red!("Failed to read signature");
                break;
           }
			let signature = Signature::from_bytes(&signature_buf);

            if sender_public_key.verify(&signed_payload(seq, &msg_buf), &signature).is_err() {
				red!("Invalid signature!\n");
				continue;
			}
            if seq != expected_seq {
                red!("Replay/reorder/dropped message detected! Closing.\n");
                std::process::exit(1);
            }
            expected_seq += 1;

			blue!("Bob [verified]: ");
			print!("{}", String::from_utf8_lossy(&msg_buf));

		}
	});

	//writing thread
	let mut message=String::new();
	let mut send_seq: u64 = 0;
	loop{
		stdout().flush().unwrap();
		if stdin().read_line(&mut message).unwrap_or(0) == 0 {
			break;}
		if !message.trim().is_empty(){
			print!("\x1B[1A\x1B[2K\r");
			stdout().flush().unwrap();
			green!("Alice:");
			print!(" {}",message);
			let message_bytes= message.as_bytes();
			let signature=secret_key.sign(&signed_payload(send_seq, message_bytes));
			let len=(message_bytes.len() as u32).to_be_bytes();
			write_stream.write_all(&len).unwrap();
			write_stream.write_all(&send_seq.to_be_bytes()).unwrap();
			write_stream.write_all(message_bytes).unwrap();
			write_stream.write_all(&signature.to_bytes()).unwrap();
			send_seq += 1;
		}
	    message.clear();
	}
}

fn main(){
	let addr=std::env::args().nth(1).unwrap_or("127.0.0.1:8080".to_string());
	let mut stream:TcpStream;
	loop{
		let temp=TcpStream::connect(&addr);
		if temp.is_ok(){
			stream=temp.unwrap();
			break;
		}
	}
	
	let mut buffer=[0u8;9];
	stream.read_exact(&mut buffer).unwrap();
	if &buffer == b"Connected" {
		yellow!("Connected Successfully!");
		println!();
	} else {
		red!("Unexpected server response");
		return;
	}

    let mut csprng=UnwrapErr(SysRng);
    let secret_key=SigningKey::generate(&mut csprng);
	let public_key=secret_key.verifying_key();

	stream.write_all(public_key.as_bytes()).unwrap();

	let mut sender_key_bytes = [0u8; 32];
	stream.read_exact(&mut sender_key_bytes).unwrap();
	let sender_public_key = VerifyingKey::from_bytes(&sender_key_bytes).unwrap();

	confirm_key(&public_key, &sender_public_key);
			
	handle_server(stream, secret_key, sender_public_key);
    
}

 
fn confirm_key(own: &VerifyingKey, peer: &VerifyingKey) {
    let hex = |k: &VerifyingKey| {
        let h: String = k.as_bytes().iter().map(|b| format!("{:02x}", b)).collect();
        format!("...{}", &h[h.len() - 4..])
    };
    println!("Own key : {}\nPeer key: {}", hex(own), hex(peer));
    print!("Peer key matches value verified out-of-band? (y/N): ");
    stdout().flush().unwrap();
    let mut a = String::new();
    stdin().read_line(&mut a).unwrap();
    if a.trim() != "y" { red!("Key rejected\n"); std::process::exit(1); }
}
