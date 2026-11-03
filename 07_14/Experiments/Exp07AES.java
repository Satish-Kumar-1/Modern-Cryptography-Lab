import java.nio.charset.StandardCharsets;
  import java.util.Base64;
  import javax.crypto.Cipher;
  import javax.crypto.spec.SecretKeySpec;

  /**
   * Experiment 7: Advanced Encryption Standard (AES-128)
   * Demonstrates:
   * 1. Official FIPS-197 Appendix B 128-bit test vector verification
   * 2. Arbitrary text encryption/decryption using AES/ECB/PKCS5Padding
   */
  public class Exp07AES {

      public static byte[] hexToBytes(String hex) {
          byte[] data = new byte[hex.length() / 2];
          for (int i = 0; i < hex.length(); i += 2) {
              data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                       + Character.digit(hex.charAt(i + 1), 16));
          }
          return data;
      }

      public static String bytesToHex(byte[] bytes) {
          StringBuilder sb = new StringBuilder();
          for (byte b : bytes) {
              sb.append(String.format("%02x", b));
          }
          return sb.toString();
      }

      public static void main(String[] args) throws Exception {
          System.out.println("=== Experiment 7: Advanced Encryption Standard (AES-128) ===\n");

           // 1. Official FIPS-197 128-bit Test Vector
           String ptHex = "3243f6a8885a308d313198a2e0370734";
           String keyHex = "2b7e151628aed2a6abf7158809cf4f3c";
           SecretKeySpec aesKey = new SecretKeySpec(hexToBytes(keyHex), "AES");

           Cipher blockCipher = Cipher.getInstance("AES/ECB/NoPadding");
           blockCipher.init(Cipher.ENCRYPT_MODE, aesKey);
           byte[] ctBytes = blockCipher.doFinal(hexToBytes(ptHex));

           blockCipher.init(Cipher.DECRYPT_MODE, aesKey);
           byte[] decBytes = blockCipher.doFinal(ctBytes);

           System.out.println("[1] FIPS-197 128-bit Block Test Vector:");
           System.out.println("    Plaintext (Hex) : " + ptHex);
             System.out.println("   Key (Hex)        : " + keyHex);
             System.out.println("   Ciphertext (Hex) : " + bytesToHex(ctBytes));
             System.out.println("   Decrypted (Hex) : " + bytesToHex(decBytes) + "\n");

          // 2. Arbitrary Message AES Encryption
          String message = "Advanced Encryption Standard (AES-128) Lab Experiment";
          Cipher textCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
          textCipher.init(Cipher.ENCRYPT_MODE, aesKey);
          byte[] encMsg = textCipher.doFinal(message.getBytes(StandardCharsets.UTF_8));

          textCipher.init(Cipher.DECRYPT_MODE, aesKey);
          String decMsg = new String(textCipher.doFinal(encMsg), StandardCharsets.UTF_8);

          System.out.println("[2] Padded Message AES-128 Encryption:");
          System.out.println("    Plaintext          : " + message);
          System.out.println("    Ciphertext (Base64): " + Base64.getEncoder().encodeToString(encMsg));
          System.out.println("    Decrypted          : " + decMsg);
      } }
