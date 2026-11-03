import java.nio.charset.StandardCharsets;
  import java.security.SecureRandom;

  /**
   * Experiment 3: One-Time Pad (OTP)
   * Implements:
   * 1. Bitwise XOR One-Time Pad using SecureRandom
   * 2. Alphabetic Modulo-26 One-Time Pad (Vernam Cipher)
   */
  public class Exp03OneTimePad {

      public static byte[] generateKey(int length) {
          byte[] key = new byte[length];
          new SecureRandom().nextBytes(key);
          return key;
      }

      public static byte[] otpXor(byte[] data, byte[] key) {
          if (data.length != key.length) {
              throw new IllegalArgumentException("Key length must equal message length.");
          }
          byte[] out = new byte[data.length];
          for (int i = 0; i < data.length; i++) {
              out[i] = (byte) (data[i] ^ key[i]);
          }
          return out;
      }

      public static String toHex(byte[] bytes) {
          StringBuilder sb = new StringBuilder();
          for (byte b : bytes) {
              sb.append(String.format("%02x", b));
          }
          return sb.toString();
      }

      public static String otpAlphaEncrypt(String plaintext, String key) {
          StringBuilder sb = new StringBuilder();
          for (int i = 0; i < plaintext.length(); i++) {
              int p = plaintext.charAt(i) - 'A';
              int k = key.charAt(i) - 'A';
              sb.append((char) (((p + k) % 26) + 'A'));
          }
          return sb.toString();
      }

      public static String otpAlphaDecrypt(String ciphertext, String key) {
           StringBuilder sb = new StringBuilder();
           for (int i = 0; i < ciphertext.length(); i++) {
               int c = ciphertext.charAt(i) - 'A';
               int k = key.charAt(i) - 'A';
               sb.append((char) (((c - k + 26) % 26) + 'A'));
           }
           return sb.toString();
      }

      public static void main(String[] args) {
          System.out.println("=== Experiment 3: One-Time Pad (OTP) ===\n");

           // 1. Bitwise XOR One-Time Pad
           String message = "CONFIDENTIAL LAUNCH CODE 9481";
           byte[] msgBytes = message.getBytes(StandardCharsets.UTF_8);
           byte[] keyBytes = generateKey(msgBytes.length);
           byte[] cipherBytes = otpXor(msgBytes, keyBytes);
           byte[] decryptedBytes = otpXor(cipherBytes, keyBytes);

          System.out.println("[1] Bitwise XOR One-Time Pad:");
          System.out.println("    Plaintext        : " + message);
          System.out.println("    Random Key (Hex) : " + toHex(keyBytes));
          System.out.println("    Ciphertext (Hex) : " + toHex(cipherBytes));
          System.out.println("    Decrypted Text   : " + new String(decryptedBytes, StandardCharsets.UTF_8) + "\n");

           // 2. Alphabetic Modulo-26 One-Time Pad
           String alphaPt = "HELLO";
           String alphaKey = "XMCKL";
           String alphaCt = otpAlphaEncrypt(alphaPt, alphaKey);
           String alphaDec = otpAlphaDecrypt(alphaCt, alphaKey);

           System.out.println("[2] Alphabetic Modulo-26 One-Time Pad:");
           System.out.println("    Plaintext   : " + alphaPt);
           System.out.println("    One-Time Key: " + alphaKey);
           System.out.println("    Ciphertext : " + alphaCt);
           System.out.println("    Decrypted   : " + alphaDec);
      } }
