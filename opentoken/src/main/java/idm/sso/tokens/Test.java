package idm.sso.tokens;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.StringUtils;
import org.apache.commons.*;


public class Test {
    /**
     * @param args the command line arguments
     */


    public static String bytesToHex(byte[] in) {
        final StringBuilder builder = new StringBuilder();
        for(byte b : in) {
            builder.append(String.format("%02x", b));
        }
        return builder.toString();
    } 


    public static void main(String[] args) throws Exception {
        String encryptedWord;
        // Encryption en = new Encryption();
        // encryptedWord = en.encrypt("TEST-TEST");
        // System.out.println("Encrypted word is : " + encryptedWord);
        Decryption de = new Decryption();
        // System.out.println("Decrypted word is : " + de.decrypt(encryptedWord));

    //    encryptedWord = CipherSuite.aes256.encrypt("2Federate", "This is a really, really big test");
     //   System.out.println("ENC:" + encryptedWord);
     //   System.out.println("DEC:" + CipherSuite.aes256.decrypt("2Federate", encryptedWord));
    //    System.out.println("======");

    //    encryptedWord = CipherSuite.aes128.encrypt("2Federate", "This is a really, really big test");
    //    System.out.println("ENC:" + encryptedWord);
    //    System.out.println("DEC:" + CipherSuite.aes128.decrypt("2Federate", encryptedWord));
    //    System.out.println("======");

        // System.out.println("XXX:" + de.decrypt(
        // "pP00vfnLe8ev+bW4xNsUu9UzR+B5TGMSh0CbvgIuIs91UWEnU1CrVg/E/q0yToWx7COkfyuOeVLeR3M8S5l7nz/LiLEJYB2efqejdgjeu9N1+vHU8GJMl1+qCFSTurQl+1I5HLuYNi3VyTomWtPiRXpQrvgknK2KwEma14wXk40JqGOwLDcKTqpr5DJZwoN4"));
        // System.out.println("======");


String input = "T1RLAQKrMohNdaqjSzkinkn1yr5I_tG2LBBY2TM3XYJadvGNH9gtLx5dAACQpP00vfnLe8ev-bW4xNsUu9UzR-B5TGMSh0CbvgIuIs91UWEnU1CrVg_E_q0yToWx7COkfyuOeVLeR3M8S5l7nz_LiLEJYB2efqejdgjeu9N1-vHU8GJMl1-qCFSTurQl-1I5HLuYNi3VyTomWtPiRXpQrvgknK2KwEma14wXk40JqGOwLDcKTqpr5DJZwoN4";



        OTKStructure tokenStructure = new OTKStructure(input);
        System.out.println("otk: " + tokenStructure.toString());

    }
}