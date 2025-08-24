import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Scanner;


/*
* Lina Andrade A00380779
* Danna Lopez A00395625
*/

class DESTest {

   public static void main(String[] args) {
      Scanner scanner = new java.util.Scanner(System.in);

      System.out.println("""
              Remember the order: KEY CYPHER_TEXT CLEAR_TEXT\
              
              1. 0101010101010101 20B9E767B2FB1456 0800000000000000\
              
              2. 0101010101010101 ADD0CC8D6E5DEBA1 0008000000000000\
              
              3. 0101010101010101 9D64555A9A10B852 0000001000000000\
              
              4. 0101010101010101 5E0905517BB59BCF 0000000004000000""");

       System.out.println(" So, the results should be: ");

      String [] tests = {"1", "2", "3", "4"};

      boolean exit = false;

      for (int i = 0; i < tests.length; i++) {

         try {
            byte[] theKey;
            byte[] theMsg;
            byte[] theExp;

             switch (tests[i]) {
                 case "1" -> {
                     theKey = hexToBytes("0101010101010101");  // "Key"

                     theMsg = hexToBytes("0800000000000000");  // "Message"

                     theExp = hexToBytes("20B9E767B2FB1456"); // "Expected"
                 }
                 case "2" -> {
                     theKey = hexToBytes("0101010101010101"); // "8bytekey"

                     theMsg = hexToBytes("0008000000000000"); // "message."

                     theExp = hexToBytes("ADD0CC8D6E5DEBA1");
                 }
                 case "3" -> {

                     theKey = hexToBytes("0101010101010101");  // "Key"

                     theMsg = hexToBytes("0000001000000000");  // "Message"

                     theExp = hexToBytes("9D64555A9A10B852"); // "Expected"
                 }
                 case "4" -> {
                     theKey = hexToBytes("0101010101010101");  // "Key"

                     theMsg = hexToBytes("0000000004000000");  // "Message"

                     theExp = hexToBytes("5E0905517BB59BCF"); // "Expected"
                 }
                 default -> {
                     System.out.println("Usage:");
                     System.out.println("java JceSunDesTest 1/2");
                     return;
                 }
            }

            KeySpec ks = new DESKeySpec(theKey);
            SecretKeyFactory kf = SecretKeyFactory.getInstance("DES");
            SecretKey ky = kf.generateSecret(ks);
            Cipher cf = Cipher.getInstance("DES/ECB/NoPadding");
            cf.init(Cipher.ENCRYPT_MODE,ky);

            byte[] theCph = cf.doFinal(theMsg);
            
            System.out.println("Test case #" + tests[i]);

            System.out.println("Key     : "+bytesToHex(theKey));
            System.out.println("Message : "+bytesToHex(theMsg));
            System.out.println("Cipher text: "+bytesToHex(theCph));
            System.out.println("Expected result: "+bytesToHex(theExp));

            if (bytesToHex(theCph).equals(bytesToHex(theExp))) {
               System.out.println("Encryption OK");
            } else {
               System.out.println("Encryption Failed");
            }
            
            while (!exit) {
               System.out.println("""
                  Choose what to do next:
                  
                  1. Decrypt the cipher text with the same key and verify you get the original clear text
                  
                  2. Encrypt the clear text again using AES algorithm and other test vectors""");

               int option = scanner.nextInt();


               if (option == 1) {
                  cf.init(Cipher.DECRYPT_MODE, ky);
                  byte[] theClear = cf.doFinal(theCph);
                  System.out.println("Key     : " + bytesToHex(theKey));                  
                  System.out.println("Cipher text: " + bytesToHex(theCph));
                  System.out.println("Decrypted text: " + bytesToHex(theClear));
                  System.out.println("Expected result: " + bytesToHex(theMsg));
                  
                  if (bytesToHex(theClear).equals(bytesToHex(theMsg))) {
                     System.out.println("Decryption OK");

                  } else {
                     System.out.println("Decryption Failed");
                  }
                  exit = true;
               } else if (option == 2) {
                  System.out.println("Going to AES test vectors...");
                  exit = true;                  
               }
            }
            
         } catch (Exception e) {
            e.printStackTrace();
            return;
         }
      }



   }
   public static byte[] hexToBytes(String str) {
      if (str==null) {
         return null;
      } else if (str.length() < 2) {
         return null;
      } else {
         int len = str.length() / 2;
         byte[] buffer = new byte[len];
         for (int i=0; i<len; i++) {
             buffer[i] = (byte) Integer.parseInt(
                str.substring(i*2,i*2+2),16);
         }
         return buffer;
      }

   }
   public static String bytesToHex(byte[] data) {
      if (data==null) {
         return null;
      } else {

         StringBuilder str = new StringBuilder();
          for (byte datum : data) {
              if ((datum & 0xFF) < 16) str.append("0").append(Integer.toHexString(datum & 0xFF));
              else str.append(Integer.toHexString(datum & 0xFF));
          }
         return str.toString().toUpperCase();
      }
   }            
}