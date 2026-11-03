import java.math.BigInteger;
  import java.util.Arrays;

  /**
   * Experiment 9: RSA Encryption and Decryption
   * Implements the RSA Public-Key Cryptosystem:
   * 1. Key Generation: n = p * q, phi(n) = (p - 1)(q - 1), d = e^-1 mod phi(n)
   * 2. Encryption: C = M^e mod n
   * 3. Decryption: M = C^d mod n
   */
  public class Exp09RSA {

      public static BigInteger[] encryptText(String message, BigInteger e, BigInteger n) {
          BigInteger[] cipher = new BigInteger[message.length()];
          for (int i = 0; i < message.length(); i++) {
              BigInteger m = BigInteger.valueOf((int) message.charAt(i));
              cipher[i] = m.modPow(e, n);
          }
          return cipher;
      }

      public static String decryptText(BigInteger[] ciphertext, BigInteger d, BigInteger n) {
          StringBuilder sb = new StringBuilder();
          for (BigInteger c : ciphertext) {
              int m = c.modPow(d, n).intValue();
              sb.append((char) m);
          }
          return sb.toString();
      }

      public static void main(String[] args) {
           System.out.println("=== Experiment 9: RSA Encryption and Decryption ===\n");

          // 1. RSA Key Generation
          BigInteger p = BigInteger.valueOf(61);
          BigInteger q = BigInteger.valueOf(53);
          BigInteger n = p.multiply(q);
          BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
          BigInteger e = BigInteger.valueOf(17);
          BigInteger d = e.modInverse(phi);

             System.out.println("[1] RSA Key Generation (p = " + p + ", q = " + q + "):");
          System.out.println("     Modulus (n = p * q)         : " + n);
          System.out.println("     Totient phi(n)              : " + phi);
          System.out.println("     Public Key (e, n)           : (" + e + ", " + n + ")");
          System.out.println("     Private Key (d, n)          : (" + d + ", " + n + ")\n");

           // 2. Numeric Message Encryption & Decryption
           BigInteger msgNum = BigInteger.valueOf(65);
           BigInteger cipherNum = msgNum.modPow(e, n);
           BigInteger decryptedNum = cipherNum.modPow(d, n);

          System.out.println("[2] Numeric RSA Encryption:");
          System.out.println("    Original Integer Message   : " + msgNum);
          System.out.println("    Encrypted Ciphertext       : " + cipherNum);
          System.out.println("    Decrypted Integer Message : " + decryptedNum + "\n");

           // 3. Text Message Encryption & Decryption
           String message = "RSA PUBLIC KEY CRYPTOGRAPHY";
           BigInteger[] cipherBlocks = encryptText(message, e, n);
           String decryptedMessage = decryptText(cipherBlocks, d, n);

          System.out.println("[3] Text Message RSA Encryption:");
          System.out.println("    Plaintext Message          : " + message);
          System.out.println("    Ciphertext Blocks          : " + Arrays.toString(cipherBlocks));
          System.out.println("    Decrypted Message          : " + decryptedMessage);
      } }
