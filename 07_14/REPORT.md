# Brief Experiment Report

## Method

The program uses AES-256-GCM through OpenSSL EVP. Normal encryption obtains a
32-byte key and 12-byte nonce from `RAND_bytes()`. Decryption keeps candidate
plaintext in memory and writes it only if `EVP_DecryptFinal_ex()` verifies the
16-byte tag.

## Experiments

1. **Ciphertext tampering:** One ciphertext bit is flipped. Authentication must
   fail, showing that encrypted data cannot be changed silently.
2. **Tag modification:** One tag bit is flipped. Authentication must fail,
   showing that the tag is required exactly as generated.
3. **Wrong key:** A separately generated 256-bit key is used. Authentication
   must fail, so an incorrect key never produces accepted plaintext.
4. **Nonce reuse:** Two equal-length messages are encrypted using the same key
   and nonce only inside the isolated test. AES-GCM uses counter mode for
   encryption, so the same keystream is repeated and `C1 XOR C2 = P1 XOR P2`.
   This leaks relationships between plaintexts and can expose a known message.
   Reuse also creates algebraic relationships between GCM authentication tags,
   weakening integrity and potentially allowing forged messages. Normal
   encryption never follows this unsafe test procedure.
5. **Correctness:** A message is encrypted with a fresh nonce, authenticated,
   decrypted, and compared byte-for-byte with its original.

## Result

The actual captured output is stored in `TEST_RESULTS.txt`. All five checks must
show PASS before the project is considered validated.
