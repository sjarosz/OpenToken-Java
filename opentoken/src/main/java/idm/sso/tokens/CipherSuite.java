package idm.sso.tokens;

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
public final class CipherSuite {
  private CipherSuite() {
  }

  /**
   * A cipher suite groups a cryptographic cipher with a specific key size, cipher
   * mode, and padding scheme. This grouping provides a convenient way of
   * representing these inter-dependent options and also helps the implementor
   * understand the exact cryptographic requirements for a given OTK. RE:
   * https://tools.ietf.org/id/draft-smith-opentoken-02.html
   * 
   * +----+--------+----------+------+---------+-----------+ | ID | Cipher | Key
   * Size | Mode | Padding | IV Length |
   * +----+--------+----------+------+---------+-----------+ | 0 | Null | N/A |
   * N/A | N/A | 0 | | 1 | AES | 256 bits | CBC | PKCS 5 | 16 | | 2 | AES | 128
   * bits | CBC | PKCS 5 | 16 | | 3 | 3DES | 168 bits | CBC | PKCS 5 | 8 |
   * +----+--------+----------+------+---------+-----------+
   */

  // TODO make test cipher work
  // currently same as aes256
  //////////////////////////////////
  // public static OTKCipher testCipher = new OTKCipher(0, "Null", "Null", 0,
  // "Null",
  // "Null", 0);

  public static final OTKCipher test = new OTKCipher(0, "AES/CBC/PKCS5Padding", "AES", 256, "PKCS5", "CBC", 16);

  public static final OTKCipher aes256 = new OTKCipher(1, "AES/CBC/PKCS5Padding", "AES", 256, "PKCS5", "CBC", 16);
  public static final OTKCipher aes128 = new OTKCipher(2, "AES/CBC/PKCS5Padding", "AES", 128, "PKCS5", "CBC", 16);

  // TODO make 3DES work
  // currently same as aes128
  //////////////////////////////////
  // public static OTKCipher desede = new OTKCipher(3, "DESede/CBC/PKCS5Padding",
  // "DESede",
  // 168, "PKCS5", "CBC", 8);
  public static final OTKCipher desede = new OTKCipher(3, "AES/CBC/PKCS5Padding", "AES", 128, "PKCS5", "CBC", 16);

  // construct array of ciphers, defines the OTK ciphersuite
  static private final OTKCipher otpCipherArray[] = { test, aes256, aes128, desede };

  public static OTKCipher getTokenCipher(int index) {
    // Retreive exact cipher per array index based upon extracted ciphersuite ID
    return otpCipherArray[index];
  }
}