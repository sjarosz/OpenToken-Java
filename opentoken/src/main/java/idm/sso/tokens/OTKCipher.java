package idm.sso.tokens;

import java.io.UnsupportedEncodingException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.nio.ByteBuffer;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

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

    Cipher mycipher;

    byte[] salt = new String("1234567890123456").getBytes(); // length = 16
    static final int ITERATION_COUNT = 1024;
    int keyStrength = 256;
    SecretKey key;
    byte[] iv;

    static final int BLOCK_SIZE = 20;

    int id;
    String name;
    String cipher;
    int keysize;
    String padding;
    String mode;
    int ivlength;

    public OTKCipher(int id, String name, String cipher, int keysize, String padding, String mode, int ivlength) {
        this.id = id;
        this.name = name;
        this.cipher = cipher;
        this.keysize = keysize;
        this.padding = padding;
        this.mode = mode;
        this.ivlength = ivlength;
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

    public byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte bytes[] = new byte[BLOCK_SIZE];
        random.nextBytes(bytes);
        return bytes;
    }

    public String encrypt(String password, String data) {
        byte[] ivBytes;
        byte[] salt = generateSalt();
        byte[] buffer = null;
        // SecretKeySpec secret = deriveKey(salt,password);
        SecretKeySpec secret = deriveKey(salt, "2Federate"); // for testing - aftwords pass a password in

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
        return java.util.Base64.getEncoder().encodeToString(buffer);
    }

    public String decrypt(String password, String encryptedText) {

        password = "2Federate";
        Cipher cipher = null;

        try {
            cipher = Cipher.getInstance(this.name);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        }

        // strip off the salt and iv
        ByteBuffer buffer = ByteBuffer.wrap(java.util.Base64.getDecoder().decode(encryptedText));
        byte[] salt = new byte[BLOCK_SIZE];
        buffer.get(salt, 0, salt.length);
        byte[] ivBlock = new byte[cipher.getBlockSize()];
        buffer.get(ivBlock, 0, ivBlock.length);
        byte[] encryptedTextBytes = new byte[buffer.capacity() - salt.length - ivBlock.length];

        buffer.get(encryptedTextBytes);
        // Deriving the key
        SecretKeySpec secret = deriveKey(salt, "2Federate"); // for testing - aftwords pass a password in

        try {
            cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(ivBlock));
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