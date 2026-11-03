import java.nio.charset.StandardCharsets;
  import java.util.Base64;
  import javax.crypto.Cipher;
  import javax.crypto.spec.SecretKeySpec;

  /**
   * Experiment 5: Data Encryption Standard (DES)
   * Demonstrates DES encryption and decryption:
   * 1. Exact 64-bit block NIST vector verification (DES/ECB/NoPadding)
   * 2. Arbitrary text encryption using DES/ECB/PKCS5Padding
   */
  public class Exp05DES {

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
              sb.append(String.format("%02X", b));
          }
          return sb.toString();
      }

      public static void main(String[] args) throws Exception {
           System.out.println("=== Experiment 5: Data Encryption Standard (DES) ===\n");

           // 1. Standard 64-bit Block Test Vector
           String ptHex = "0123456789ABCDEF";
           String keyHex = "133457799BBCDFF1";
           SecretKeySpec rawKey = new SecretKeySpec(hexToBytes(keyHex), "DES");

           Cipher blockCipher = Cipher.getInstance("DES/ECB/NoPadding");
           blockCipher.init(Cipher.ENCRYPT_MODE, rawKey);
           byte[] ctBytes = blockCipher.doFinal(hexToBytes(ptHex));

           blockCipher.init(Cipher.DECRYPT_MODE, rawKey);
           byte[] decBytes = blockCipher.doFinal(ctBytes);

           System.out.println("[1] 64-bit Block DES Test Vector:");
           System.out.println("    Plaintext (Hex) : " + ptHex);
             System.out.println("   Key (Hex)        : " + keyHex);
             System.out.println("   Ciphertext (Hex) : " + bytesToHex(ctBytes));
             System.out.println("   Decrypted (Hex) : " + bytesToHex(decBytes) + "\n");

          // 2. Arbitrary String DES Encryption with PKCS5Padding
          String message = "Data Encryption Standard Lab Experiment";
          Cipher textCipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
          textCipher.init(Cipher.ENCRYPT_MODE, rawKey);
          byte[] encryptedMsg = textCipher.doFinal(message.getBytes(StandardCharsets.UTF_8));

          textCipher.init(Cipher.DECRYPT_MODE, rawKey);
          String decryptedMsg = new String(textCipher.doFinal(encryptedMsg), StandardCharsets.UTF_8);

          System.out.println("[2] Padded Message DES Encryption:");
          System.out.println("    Plaintext          : " + message);
          System.out.println("    Ciphertext (Base64): " + Base64.getEncoder().encodeToString(encryptedMsg));
          System.out.println("    Decrypted          : " + decryptedMsg);
      } }
