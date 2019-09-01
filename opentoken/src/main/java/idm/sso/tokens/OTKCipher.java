package idm.sso.tokens;

import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Cipher;
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
    int iterationCount = 1024;
    int keyStrength = 256;
    SecretKey key;
    byte[] iv;

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
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65556, this.keysize / 8);
        try {
            secretKey = factory.generateSecret(spec);
        } catch (InvalidKeySpecException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return new SecretKeySpec(secretKey.getEncoded(), this.cipher);
    }

}