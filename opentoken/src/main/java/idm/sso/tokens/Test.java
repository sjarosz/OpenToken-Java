package idm.sso.tokens;

public class Test {
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws Exception {
        String encryptedWord;
        // Encryption en = new Encryption();
        // encryptedWord = en.encrypt("TEST-TEST");
        // System.out.println("Encrypted word is : " + encryptedWord);
        // Decryption de = new Decryption();
        // System.out.println("Decrypted word is : " + de.decrypt(encryptedWord));

        // OTKCipher otkc0 = new OTKCipher(0, "Null", "Null", 0, "Null", "Null", 0);
        OTKCipher otkc1 = new OTKCipher(1, "AES/CBC/PKCS5Padding", "AES", 256, "PKCS5", "CBC", 16);
        OTKCipher otkc2 = new OTKCipher(2, "AES/CBC/PKCS5Padding", "AES", 128, "PKCS5", "CBC", 16);
        // OTKCipher otkc3 = new OTKCipher(3, "DESede/CBC/PKCS5Padding", "DESede", 168,
        // "PKCS5", "CBC", 8);

        encryptedWord = otkc1.encrypt("2Federate", "This is a really, really big test");
        System.out.println("ENC:" + encryptedWord);
        System.out.println("DEC:" + otkc1.decrypt("2Federate", encryptedWord));
        System.out.println("======");

        encryptedWord = otkc2.encrypt("2Federate", "This is a really, really big test");
        System.out.println("ENC:" + encryptedWord);
        System.out.println("DEC:" + otkc2.decrypt("2Federate", encryptedWord));
        System.out.println("======");

    }
}