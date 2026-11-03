/**
   * Experiment 2: Caesar, Vigenere and Hill Ciphers
   * Implements encryption and decryption for:
   * 1. Caesar Cipher
   * 2. Vigenere Cipher
   * 3. Hill Cipher (2x2 Matrix mod 26)
   */
  public class Exp02ClassicalCiphers {

      // --- 1. CAESAR CIPHER ---
      public static String caesarEncrypt(String text, int shift) {
          StringBuilder sb = new StringBuilder();
          shift = ((shift % 26) + 26) % 26;
          for (char ch : text.toCharArray()) {
              if (Character.isLetter(ch)) {
                  char base = Character.isUpperCase(ch) ? 'A' : 'a';
                  sb.append((char) ((ch - base + shift) % 26 + base));
              } else {
                  sb.append(ch);
              }
          }
          return sb.toString();
      }

      public static String caesarDecrypt(String ciphertext, int shift) {
          return caesarEncrypt(ciphertext, -shift);
      }

      // --- 2. VIGENERE CIPHER ---
      public static String vigenereEncrypt(String text, String key) {
          StringBuilder sb = new StringBuilder();
          key = key.toUpperCase();
          int keyIdx = 0;
          for (char ch : text.toCharArray()) {
              if (Character.isLetter(ch)) {
                  char base = Character.isUpperCase(ch) ? 'A' : 'a';
                  int shift = key.charAt(keyIdx % key.length()) - 'A';
                  sb.append((char) ((ch - base + shift) % 26 + base));
                  keyIdx++;
              } else {
                  sb.append(ch);
              }
          }
          return sb.toString();
      }

      public static String vigenereDecrypt(String ciphertext, String key) {
          StringBuilder sb = new StringBuilder();
       key = key.toUpperCase();
       int keyIdx = 0;
       for (char ch : ciphertext.toCharArray()) {
           if (Character.isLetter(ch)) {
               char base = Character.isUpperCase(ch) ? 'A' : 'a';
               int shift = key.charAt(keyIdx % key.length()) - 'A';
               sb.append((char) ((ch - base - shift + 26) % 26 + base));
               keyIdx++;
           } else {
               sb.append(ch);
           }
       }
       return sb.toString();
   }

    // --- 3. HILL CIPHER (2x2 Matrix mod 26) ---
    private static int modInverse26(int a) {
        a = ((a % 26) + 26) % 26;
        for (int x = 1; x < 26; x++) {
            if ((a * x) % 26 == 1) {
                return x;
            }
        }
        throw new IllegalArgumentException("No modular inverse for determinant mod 26");
    }

   public static String hillEncrypt2x2(String plaintext, int[][] key) {
       String clean = plaintext.toUpperCase().replaceAll("[^A-Z]", "");
       if (clean.length() % 2 != 0) {
           clean += "X";
       }
       StringBuilder sb = new StringBuilder();
       for (int i = 0; i < clean.length(); i += 2) {
           int v0 = clean.charAt(i) - 'A';
           int v1 = clean.charAt(i + 1) - 'A';
           int c0 = ((key[0][0] * v0 + key[0][1] * v1) % 26 + 26) % 26;
           int c1 = ((key[1][0] * v0 + key[1][1] * v1) % 26 + 26) % 26;
           sb.append((char) (c0 + 'A')).append((char) (c1 + 'A'));
       }
       return sb.toString();
   }

    public static String hillDecrypt2x2(String ciphertext, int[][] key) {
        int det = ((key[0][0] * key[1][1] - key[0][1] * key[1][0]) % 26 + 26) % 26;
        int detInv = modInverse26(det);
        int[][] invKey = new int[][]{
            {((key[1][1] * detInv) % 26 + 26) % 26, ((-key[0][1] * detInv) % 26 + 26) % 26},
            {((-key[1][0] * detInv) % 26 + 26) % 26, ((key[0][0] * detInv) % 26 + 26) % 26}
        };
        return hillEncrypt2x2(ciphertext, invKey);
    }
      public static void main(String[] args) {
          System.out.println("=== Experiment 2: Caesar, Vigenere and Hill Ciphers ===\n");

          // 1. Caesar Cipher
          String ptCaesar = "NETWORK SECURITY";
          int shift = 3;
          String ctCaesar = caesarEncrypt(ptCaesar, shift);
          System.out.println("[1] Caesar Cipher (Shift = " + shift + "):");
          System.out.println("    Plaintext : " + ptCaesar);
          System.out.println("    Ciphertext : " + ctCaesar);
          System.out.println("    Decrypted : " + caesarDecrypt(ctCaesar, shift) + "\n");

          // 2. Vigenere Cipher
          String ptVig = "ATTACKATDAWN";
          String keyVig = "LEMON";
          String ctVig = vigenereEncrypt(ptVig, keyVig);
          System.out.println("[2] Vigenere Cipher (Key = '" + keyVig + "'):");
          System.out.println("     Plaintext : " + ptVig);
          System.out.println("     Ciphertext : " + ctVig);
          System.out.println("     Decrypted : " + vigenereDecrypt(ctVig, keyVig) + "\n");

             // 3. Hill Cipher
             String ptHill = "HELP";
             int[][] keyHill = {{3, 3}, {2, 5}};
             String ctHill = hillEncrypt2x2(ptHill, keyHill);
             System.out.println("[3] Hill Cipher (2x2 Key Matrix = [[3, 3], [2, 5]]):");
          System.out.println("       Plaintext : " + ptHill);
          System.out.println("       Ciphertext : " + ctHill);
          System.out.println("       Decrypted : " + hillDecrypt2x2(ctHill, keyHill));
      } }
