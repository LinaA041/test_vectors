import java.security.spec.*;
import java.util.Scanner;
import javax.crypto.*;
import javax.crypto.spec.*;


class DESTest {

    public static void main(String[] args) {

        Scanner scanner = new Scanner(System.in);

        System.out.println("Please, select the algorithm to test:" +
                "\n1 - DES" +
                "\n2 - AES");

        int choice = scanner.nextInt();

        if (choice == 1) {

            System.out.println("""
                Remember the order: KEY CYPHER_TEXT CLEAR_TEXT

                1. 0101010101010101 20B9E767B2FB1456 0800000000000000

                2. 0101010101010101 ADD0CC8D6E5DEBA1 0008000000000000

                3. 0101010101010101 9D64555A9A10B852 0000001000000000

                4. 0101010101010101 5E0905517BB59BCF 0000000004000000""");

            System.out.println("\nRunning test vectors...\n");

            String[] tests = {"1", "2", "3", "4"};

            for (String test : tests) {
                runTestCase(test);
                runTestCaseAES(test);
            }

        } else if (choice == 2) {

            System.out.println("""
                Remember the order: KEY CLEAR_TEXT CYPHER_TEXT

                1. 10a58869d74be5a374cf867cfb473859 00000000000000000000000000000000 6d251e6944b051e04eaa6fb4dbf78465
                2. da84367f325d42d601b4326964802e8e 00000000000000000000000000000000 bba071bcb470f8f6586e5d3add18bc66
                3. 47d6742eefcc0465dc96355e851b64d9 00000000000000000000000000000000 0306194f666d183624aa230a8b264ae7
                4. e234cdca2606b81f29408d5f6da21206 00000000000000000000000000000000 fff60a4740086b3b9c56195b98d91a7b""");

            String[] tests = {"1", "2", "3", "4"};

            for (String test : tests) {
                runTestCaseAES(test);
            }

        } else {
            System.out.println("Invalid choice. Please select 1 or 2.");
        }



    }

    private static void runTestCase(String testId) {
        try {
            byte[] theKey;
            byte[] theMsg;
            byte[] theExp;

            switch (testId) {
                case "1" -> {
                    theKey = hexToBytes("0101010101010101");
                    theMsg = hexToBytes("0800000000000000");
                    theExp = hexToBytes("20B9E767B2FB1456");
                }
                case "2" -> {
                    theKey = hexToBytes("0101010101010101");
                    theMsg = hexToBytes("0008000000000000");
                    theExp = hexToBytes("ADD0CC8D6E5DEBA1");
                }
                case "3" -> {
                    theKey = hexToBytes("0101010101010101");
                    theMsg = hexToBytes("0000001000000000");
                    theExp = hexToBytes("9D64555A9A10B852");
                }
                case "4" -> {
                    theKey = hexToBytes("0101010101010101");
                    theMsg = hexToBytes("0000000004000000");
                    theExp = hexToBytes("5E0905517BB59BCF");
                }
                default -> {
                    System.out.println("Unknown test case: " + testId);
                    return;
                }
            }

            KeySpec ks = new DESKeySpec(theKey);
            SecretKeyFactory kf = SecretKeyFactory.getInstance("DES");
            SecretKey ky = kf.generateSecret(ks);
            Cipher cf = Cipher.getInstance("DES/ECB/NoPadding");

            // --- ENCRYPT ---
            cf.init(Cipher.ENCRYPT_MODE, ky);
            byte[] theCph = cf.doFinal(theMsg);

            System.out.println("Test case #" + testId);
            System.out.println("Key     : " + bytesToHex(theKey));
            System.out.println("Message : " + bytesToHex(theMsg));
            System.out.println("Cipher text: " + bytesToHex(theCph));
            System.out.println("Expected cipher: " + bytesToHex(theExp));

            if (bytesToHex(theCph).equals(bytesToHex(theExp))) {
                System.out.println("Encryption OK");
            } else {
                System.out.println("Encryption Failed");
            }

            System.out.println("In this order, the decryption to the test case " + testId + " is:");

            // --- DECRYPT ---
            cf.init(Cipher.DECRYPT_MODE, ky);
            byte[] theClear = cf.doFinal(theCph);

            System.out.println("Decrypted text: " + bytesToHex(theClear));
            System.out.println("Expected clear: " + bytesToHex(theMsg));

            if (bytesToHex(theClear).equals(bytesToHex(theMsg))) {
                System.out.println("Decryption OK");
            } else {
                System.out.println("Decryption Failed");
            }

            System.out.println("------------------------------");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void runTestCaseAES(String testId) {
        try {
            byte[] theKey;
            byte[] theMsg;
            byte[] theExp;
            
            // Key: 128 bits
            switch (testId) {
                case "1" -> {
                    theKey = hexToBytes("10a58869d74be5a374cf867cfb473859");
                    theMsg = hexToBytes("00000000000000000000000000000000");
                    theExp = hexToBytes("6d251e6944b051e04eaa6fb4dbf78465");
                }
                case "2" -> {
                    theKey = hexToBytes("da84367f325d42d601b4326964802e8e");
                    theMsg = hexToBytes("00000000000000000000000000000000");
                    theExp = hexToBytes("bba071bcb470f8f6586e5d3add18bc66");
                }
                case "3" -> {
                    theKey = hexToBytes("47d6742eefcc0465dc96355e851b64d9");
                    theMsg = hexToBytes("00000000000000000000000000000000");
                    theExp = hexToBytes("0306194f666d183624aa230a8b264ae7");
                }
                case "4" -> {
                    theKey = hexToBytes("e234cdca2606b81f29408d5f6da21206");
                    theMsg = hexToBytes("00000000000000000000000000000000");
                    theExp = hexToBytes("fff60a4740086b3b9c56195b98d91a7b");
                }
                default -> {
                    System.out.println("Unknown test case: " + testId);
                    return;
                }
            }

            SecretKey ky = new SecretKeySpec(theKey, "AES");
            Cipher cf = Cipher.getInstance("AES/ECB/NoPadding");

            // --- ENCRYPT ---
            cf.init(Cipher.ENCRYPT_MODE, ky);
            byte[] theCph = cf.doFinal(theMsg);

            System.out.println("Test case #" + testId);
            System.out.println("Key         : " + bytesToHex(theKey));
            System.out.println("Plaintext   : " + bytesToHex(theMsg));
            System.out.println("Cipher text : " + bytesToHex(theCph));
            System.out.println("Expected    : " + bytesToHex(theExp));

            if (bytesToHex(theCph).equalsIgnoreCase(bytesToHex(theExp))) {
                System.out.println("Encryption OK");
            } else {
                System.out.println("Encryption Failed");
            }

            // --- DECRYPT ---
            // cf.init(Cipher.DECRYPT_MODE, ky);
            // byte[] theClear = cf.doFinal(theCph);

            // System.out.println("Decrypted   : " + bytesToHex(theClear));
            // System.out.println("Expected PT : " + bytesToHex(theMsg));

            // if (bytesToHex(theClear).equalsIgnoreCase(bytesToHex(theMsg))) {
            //     System.out.println("Decryption OK");
            // } else {
            //     System.out.println("Decryption Failed");
            // }

            // System.out.println("------------------------------");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static byte[] hexToBytes(String str) {
        if (str == null || str.length() < 2) return null;
        int len = str.length() / 2;
        byte[] buffer = new byte[len];
        for (int i = 0; i < len; i++) {
            buffer[i] = (byte) Integer.parseInt(str.substring(i * 2, i * 2 + 2), 16);
        }
        return buffer;
    }

    public static String bytesToHex(byte[] data) {
        if (data == null) return null;
        StringBuilder str = new StringBuilder();
        for (byte datum : data) {
            if ((datum & 0xFF) < 16) str.append("0");
            str.append(Integer.toHexString(datum & 0xFF));
        }
        return str.toString().toUpperCase();
    }
}
