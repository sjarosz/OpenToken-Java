package idm.sso.tokens;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.KeySpec;
//import java.util.Base64;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;


/**
 * Set of JavaAPIs and CLI to implement
 * https://tools.ietf.org/id/draft-smith-opentoken-02.html
 * 
 * 2019 - Steven Jarosz Permission is hereby granted, free of charge, to any
 * person obtaining a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to permit
 * persons to whom the Software is furnished to do so, subject to the following
 * conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

public final class OTKCipher {
    /**
     * Simple Cipher object in support of the OpenToken APIs.
     * 
     * @param args The arguments of the program.
     */

    static final int ITERATION_COUNT = 1024;
    static final int BLOCK_SIZE = 16;

    int id;
    String name;
    String cipher;
    int keysize;
    String padding;
    String mode;
    int ivlength;


    public static String bytesToHex(byte[] in) {
        final StringBuilder builder = new StringBuilder();
        for(byte b : in) {
            builder.append(String.format("%02x", b));
        }
        return builder.toString();
    } 


    public OTKCipher(int id, String name, String cipher, int keysize, String padding, String mode, int ivlength) {
        this.id = id;
        this.name = name;
        this.cipher = cipher;
        this.keysize = keysize;
        this.padding = padding;
        this.mode = mode;
        this.ivlength = ivlength;
    }

    public int getID() {
        return this.id;
    }

    public String getName() {
        return this.name;
    }

    public String getCipher() {
        return this.cipher;
    }

    public byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte bytes[] = new byte[BLOCK_SIZE];
        random.nextBytes(bytes);
        return bytes;
    }

    public SecretKeySpec deriveKey(byte[] salt, String password) {

        SecretKeyFactory factory = null;
        SecretKey secretKey = null;
        try {
            factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATION_COUNT, this.keysize);
        try {
            secretKey = factory.generateSecret(spec);
        } catch (InvalidKeySpecException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return new SecretKeySpec(secretKey.getEncoded(), this.cipher);
    }

    public String encrypt(String password, String data) {
        byte[] ivBytes;
        byte[] salt = generateSalt();
        byte[] buffer = null;
        SecretKeySpec secret = deriveKey(salt, password);

        /* you can give whatever you want for password. This is for testing purpose */
        Cipher cipher;
        try {
            cipher = Cipher.getInstance(this.name);

            cipher.init(Cipher.ENCRYPT_MODE, secret);
            AlgorithmParameters params = cipher.getParameters();
            ivBytes = params.getParameterSpec(IvParameterSpec.class).getIV();
            byte[] encryptedTextBytes = cipher.doFinal(data.getBytes("UTF-8"));
            // prepend salt and iv
            buffer = new byte[salt.length + ivBytes.length + encryptedTextBytes.length];
            System.arraycopy(salt, 0, buffer, 0, salt.length);
            System.arraycopy(ivBytes, 0, buffer, salt.length, ivBytes.length);
            System.arraycopy(encryptedTextBytes, 0, buffer, salt.length + ivBytes.length, encryptedTextBytes.length);
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (InvalidParameterSpecException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (BadPaddingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        Base64 b64 = new Base64();
        return b64.encodeToString(buffer);
    }

    public String decrypt(String password, byte[] encryptedText, byte[] iv) {
        SecretKey key = null;
        SecretKeySpec secret = null;
        Cipher cipher = null;
        Base64 b64 = new Base64();
        try {
            cipher = Cipher.getInstance(this.name);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        }

        // strip off the salt and iv
 /**       
        ByteBuffer buffer = ByteBuffer.wrap(encryptedText);

        byte[] salt = new byte[16];
        System.out.println(salt.length);
        buffer.get(salt, 0, salt.length);
        byte[] ivBlock = new byte[cipher.getBlockSize()];
        
        buffer.get(ivBlock, 0, ivBlock.length);
        System.out.println(ivBlock.toString());
        byte[] encryptedTextBytes = new byte[buffer.capacity() - salt.length - ivBlock.length];

        buffer.get(encryptedTextBytes);
        // Deriving the key
        secret = deriveKey(salt, password); // for testing - aftwords pass a password in
 
        String passPhrase = "2Federate";
        int iterationCount = 1000;
        int keyStrength = 128;
        SecretKey key;
        Cipher dcipher;

        System.out.println("here");
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            KeySpec spec = new PBEKeySpec(passPhrase.toCharArray(), salt, iterationCount, keyStrength);
            SecretKey tmp = factory.generateSecret(spec);
                    key = new SecretKeySpec(tmp.getEncoded(), "AES");
                    dcipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            System.out.println("key: "+ key.toString()); 
            System.out.println("key: "+ key.toString().getBytes());        

            System.out.println("key: "+ bytesToHex(key.toString().getBytes()));  

            System.out.println("key: "+ bytesToHex(key.toString().getBytes("UTF-8")));            

      **/     
      
      try {
            //SecretKeySpec secret2 = deriveKey(salt, password); // for testing - afterwords
            // pass a password in
            // decode the base64 encoded string
            byte[] decodedKey = b64.decode("oBUkValAhbMDi9Lzq8/x4A==");
    
            System.out.println("TEST: " + bytesToHex(decodedKey));
            // rebuild key using SecretKeySpec
            //SecretKey secret3 = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    


secret = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");




       
        } catch (Exception e) {
            System.out.println("ERROR");
        }



        try {
            // cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(iv));
            cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(iv));
            System.out.println("HERE");
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace(

            );
        }
        byte[] decryptedTextBytes = null;

        ByteBuffer buffer = ByteBuffer.wrap(encryptedText);

        System.out.println("before: "+ bytesToHex(encryptedText));
        byte[] tmp = new byte[16+this.ivlength];
        byte[] encryptedTextBytes = new byte[buffer.capacity() - 16 - this.ivlength];
        buffer.get(tmp);
        buffer.get(encryptedTextBytes);

        System.out.println("after: "+ bytesToHex(encryptedTextBytes));

        try {
            decryptedTextBytes = cipher.doFinal(encryptedText);
            //decryptedTextBytes = cipher.doFinal(encryptedTextBytes);
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }

System.out.println("decrypted: " + bytesToHex(decryptedTextBytes)+"\n");
byte[] compressed = null;
        //return new String(decryptedTextBytes);
        try{
            compressed= Hex.decodeHex("789c5dce310bc2301005e0bdffe5244d32c84106715528e8e496c62bb6d43b482ed49f6f1007717af078f03d16859126c914ace91d180fc65e8d45b747676f5dacfae0a3b0d24b43cd8c12cb5c90e3930a6ac2cbe17c42bb331813a63596d2eaa1c526f9de953a2e94342c421d37481824439c94f29fe6dd47cbc4b441659dd7df41efbf77de3e66363e060606060606");

        } catch (Exception e){

        }
        System.out.println(compressed.toString());
        return compressed.toString();
    }

    //////////////////////////////////////////////////////////

    public String decrypt2(String password, byte[] encryptedText, byte[] iv) {
        Cipher cipher = null;

        try {
            cipher = Cipher.getInstance(this.name);
            System.out.println("block size: " + cipher.getBlockSize());

        } catch (NoSuchAlgorithmException | NoSuchPaddingException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        }

        // strip off the salt and iv
        System.out.println("x1");
        Base64 b64=new Base64();
        ByteBuffer buffer = ByteBuffer.wrap(b64.decode(encryptedText));

        System.out.println("x2: " + buffer.toString());

        byte[] salt = new byte[16];
        System.out.println("X" + salt.length);
        buffer.get(salt, 0, salt.length);
        byte[] ivBlock = new byte[cipher.getBlockSize()];
        buffer.get(ivBlock, 0, ivBlock.length);
         System.out.println("X=" + ivBlock.toString());
         System.out.println("X=" + iv.toString());
         //byte[] encryptedTextBytes = encryptedText;
        byte[] encryptedTextBytes = new byte[buffer.capacity() - salt.length - ivBlock.length];
         //byte[] encryptedTextBytes = new byte[buffer.capacity() - salt.length];

        System.out.println("eb: " + encryptedTextBytes.length);

        buffer.get(encryptedTextBytes);
        // Deriving the key
        SecretKeySpec secret2 = deriveKey(salt, password); // for testing - afterwords
        // pass a password in
        // decode the base64 encoded string
        byte[] decodedKey = b64.decode("oBUkValAhbMDi9Lzq8/x4A==");

        System.out.println("TEST: " + decodedKey.toString());
        // rebuild key using SecretKeySpec
        SecretKey secret = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
        byte[] x = b64.encode(secret.getEncoded());
        System.out.println("----" + x);

        try {
            // cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(iv));
            cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(iv));
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        }
        byte[] decryptedTextBytes = null;
        try {
            decryptedTextBytes = cipher.doFinal(encryptedTextBytes);
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }

        return new String(decryptedTextBytes);
    }

}