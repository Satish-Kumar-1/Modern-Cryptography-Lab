import java.math.BigInteger;
  import java.security.SecureRandom;

  /**
   * Experiment 8: Miller-Rabin Primality Test
   * Implements the probabilistic Miller-Rabin Primality Test using BigInteger
   * to support arbitrarily large integers.
   */
  public class Exp08MillerRabin {

      private static final SecureRandom RANDOM = new SecureRandom();

      public static boolean isProbablePrime(BigInteger n, int k) {
          if (n.compareTo(BigInteger.TWO) < 0) {
              return false;
          }
          if (n.equals(BigInteger.TWO) || n.equals(BigInteger.valueOf(3))) {
              return true;
          }
          if (n.mod(BigInteger.TWO).equals(BigInteger.ZERO)) {
              return false;
          }

           // Write n - 1 = 2^r * d with d odd
           BigInteger d = n.subtract(BigInteger.ONE);
           int r = d.getLowestSetBit();
           d = d.shiftRight(r);

          for (int i = 0; i < k; i++) {
              BigInteger a;
              do {
                   a = new BigInteger(n.bitLength(), RANDOM);
              } while (a.compareTo(BigInteger.TWO) < 0 || a.compareTo(n.subtract(BigInteger.TWO)) > 0);

              BigInteger x = a.modPow(d, n);
              if (x.equals(BigInteger.ONE) || x.equals(n.subtract(BigInteger.ONE))) {
                  continue;
              }

                boolean passed = false;
                for (int j = 0; j < r - 1; j++) {
                    x = x.modPow(BigInteger.TWO, n);
                    if (x.equals(n.subtract(BigInteger.ONE))) {
                        passed = true;
                        break;
                    }
               }
               if (!passed) {
                   return false; // Definitely composite
               }
           }
           return true; // Probably prime
      }

      public static void main(String[] args) {
           System.out.println("=== Experiment 8: Miller-Rabin Primality Test ===\n");

          long[] numbers = {17L, 561L, 1000003L, 104729L, 104729L * 1000003L, 2147483647L};
          String[] labels = {
              "Small Prime",
              "Carmichael Number (3 * 11 * 17)",
              "6-Digit Prime",
              "10,000th Prime",
              "Product of Two Primes",
              "Mersenne Prime (2^31 - 1)"
          };

          for (int i = 0; i < numbers.length; i++) {
              BigInteger n = BigInteger.valueOf(numbers[i]);
              boolean prime = isProbablePrime(n, 20);
              String status = prime ? "PROBABLY PRIME" : "COMPOSITE";
              System.out.printf("n = %-15d [%-32s] -> %s%n", numbers[i], labels[i], status);
          }

          BigInteger randomPrime = new BigInteger(64, 20, RANDOM);
          System.out.println("\nGenerated 64-bit Probable Prime: " + randomPrime);
      } }
