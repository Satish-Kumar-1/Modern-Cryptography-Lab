import java.nio.charset.StandardCharsets;
  import java.util.Base64;
  import javax.crypto.Cipher;
  import javax.crypto.spec.SecretKeySpec;

  /**
   * Experiment 6: Triple DES (3DES)
   * Demonstrates 168-bit (24-byte) Triple DES (DESede) in EDE mode.
   */
  public class Exp06TripleDES {

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
           System.out.println("=== Experiment 6: Triple DES (3DES - DESede) ===\n");

          // 24-byte (192-bit with parity, 168-bit effective) 3DES key (K1 || K2 || K3)
          String k1Hex = "133457799BBCDFF1";
          String k2Hex = "1122334455667788";
          String k3Hex = "AABBCCDDEEFF0011";
          byte[] key24 = hexToBytes(k1Hex + k2Hex + k3Hex);

           SecretKeySpec tripleDesKey = new SecretKeySpec(key24, "DESede");
           Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");

          String message = "Triple DES EDE Encryption Test!";
          cipher.init(Cipher.ENCRYPT_MODE, tripleDesKey);
          byte[] ciphertext = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));

           cipher.init(Cipher.DECRYPT_MODE, tripleDesKey);
          String decrypted = new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);

          System.out.println("Key 1 (Hex)        : " + k1Hex);
          System.out.println("Key 2 (Hex)        : " + k2Hex);
          System.out.println("Key 3 (Hex)        : " + k3Hex);
          System.out.println("Plaintext          : " + message);
          System.out.println("Ciphertext (Hex)   : " + bytesToHex(ciphertext));
          System.out.println("Ciphertext (Base64): " + Base64.getEncoder().encodeToString(ciphertext));
          System.out.println("Decrypted Text     : " + decrypted);
      } }
