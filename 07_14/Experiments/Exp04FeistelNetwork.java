import java.nio.ByteBuffer;
  import java.nio.charset.StandardCharsets;

  /**
   * Experiment 4: Feistel Network
   * Implements a 16-round 64-bit Feistel Cipher demonstrating:
   * - Splitting a 64-bit block into 32-bit Left (L) and Right (R) halves
   * - Round function F(R, K_i)
   * - Exact structural symmetry between encryption and decryption
   */
  public class Exp04FeistelNetwork {

      public static int[] generateRoundKeys(long masterKey, int rounds) {
          int[] keys = new int[rounds];
          for (int i = 0; i < rounds; i++) {
              int sub = (int) ((masterKey >>> (i % 32)) ^ (0x9E3779B9L * (i + 1)));
              keys[i] = Integer.rotateLeft(sub, (i * 3) % 32);
          }
          return keys;
      }

      public static int roundFunction(int right, int roundKey) {
          int mixed = right ^ roundKey;
          mixed = mixed * 0x85EBCA6B;
          mixed = Integer.rotateLeft(mixed, 13);
          mixed = mixed ^ (mixed >>> 16);
          return mixed;
      }

      public static long feistelEncryptBlock(long block64, int[] roundKeys) {
          int left = (int) (block64 >>> 32);
          int right = (int) block64;

           for (int key : roundKeys) {
               int nextLeft = right;
               int nextRight = left ^ roundFunction(right, key);
               left = nextLeft;
               right = nextRight;
           }

           // Final swap of Left and Right halves
           int temp = left;
           left = right;
           right = temp;

           return ((left & 0xFFFFFFFFL) << 32) | (right & 0xFFFFFFFFL);
      }
      public static long feistelDecryptBlock(long cipher64, int[] roundKeys) {
          int[] reversedKeys = new int[roundKeys.length];
          for (int i = 0; i < roundKeys.length; i++) {
              reversedKeys[i] = roundKeys[roundKeys.length - 1 - i];
          }
          return feistelEncryptBlock(cipher64, reversedKeys);
      }

      public static void main(String[] args) {
          System.out.println("=== Experiment 4: Feistel Network (16-Round 64- bit Block Cipher) ===\n");

           String plaintext = "FEISTEL!";
           long masterKey = 0x133457799BBCDFF1L;
           int[] roundKeys = generateRoundKeys(masterKey, 16);

          long block64 = ByteBuffer.wrap(plaintext.getBytes(StandardCharsets.UTF_8)).getLong();
          long cipher64 = feistelEncryptBlock(block64, roundKeys);
          long decrypted64 = feistelDecryptBlock(cipher64, roundKeys);

          byte[] decBytes = ByteBuffer.allocate(8).putLong(decrypted64).array();
          String decryptedStr = new String(decBytes, StandardCharsets.UTF_8);

           System.out.printf("Plaintext ASCII     : %s%n", plaintext);
           System.out.printf("Plaintext (64-bit) : 0x%016X%n", block64);
           System.out.printf("Master Key (64-bit) : 0x%016X%n", masterKey);
           System.out.printf("Ciphertext (64-bit) : 0x%016X%n", cipher64);
           System.out.printf("Decrypted (64-bit) : 0x%016X%n", decrypted64);
           System.out.printf("Decrypted ASCII     : %s%n", decryptedStr);
      } }
