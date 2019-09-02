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

        encryptedWord = CipherSuite.aes256.encrypt("2Federate", "This is a really, really big test");
        System.out.println("ENC:" + encryptedWord);
        System.out.println("DEC:" + CipherSuite.aes256.decrypt("2Federate", encryptedWord));
        System.out.println("======");

        encryptedWord = CipherSuite.aes128.encrypt("2Federate", "This is a really, really big test");
        System.out.println("ENC:" + encryptedWord);
        System.out.println("DEC:" + CipherSuite.aes128.decrypt("2Federate", encryptedWord));
        System.out.println("======");

        OTKStructure tokenStructure = new OTKStructure(
                "T1RLAQKrMohNdaqjSzkinkn1yr5I_tG2LBBY2TM3XYJadvGNH9gtLx5dAACQpP00vfnLe8ev-bW4xNsUu9UzR-B5TGMSh0CbvgIuIs91UWEnU1CrVg_E_q0yToWx7COkfyuOeVLeR3M8S5l7nz_LiLEJYB2efqejdgjeu9N1-vHU8GJMl1-qCFSTurQl-1I5HLuYNi3VyTomWtPiRXpQrvgknK2KwEma14wXk40JqGOwLDcKTqpr5DJZwoN4");
        System.out.println("otk: " + tokenStructure.toString());

        System.out.println(tokenStructure.getHeader());

    }
}