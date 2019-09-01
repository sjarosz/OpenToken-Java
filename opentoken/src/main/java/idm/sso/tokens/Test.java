package idm.sso.tokens;

public class Test {
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws Exception {
        Encryption en = new Encryption();
        String encryptedWord = en.encrypt("Test");
        System.out.println("Encrypted word is : " + encryptedWord);
        Decryption de = new Decryption();
        System.out.println("Decrypted word is : " + de.decrypt(encryptedWord));
    }
}