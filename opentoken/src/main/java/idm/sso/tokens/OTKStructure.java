package idm.sso.tokens;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.Charset;
//import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;
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
public final class OTKStructure {
    private OTKStructure() {
    }

    /**
     * Generalized Token Structure for extension in OpenToken APIs.
     * 
     * @param args The arguments of the program.
     */

    static final String VALID_OTK_HEADER = "OTK";
    private final Charset UTF8_CHARSET = Charset.forName("UTF-8");

    // OTK Struction occording to specfication
    String otkHeaderLiteral; // 3 bytes
    int versionID; // 1 byte
    int cipherSuiteID; // 1 byte
    byte[] hmac = new byte[20]; // 20 bytes
    int ivLength; // 1 byte
    byte[] iv; // iv[ivLength]
    int keyInfoLength; // 1 byte
    byte[] keyInfo; // keyInfo[keyInfoLength]
    short payloadLength; // two bytes
    byte[] payload; // payload[payloadLength]

    OTKCipher tokenCipher;

    public static String stringToHex(String string) {
        StringBuilder buf = new StringBuilder(200);
        for (char ch: string.toCharArray()) {
            if (buf.length() > 0)
            buf.append(' ');
            buf.append(String.format("%04x", (int) ch));
        }
        return buf.toString();
    }

    public static String bytesToHex(byte[] in) {
        final StringBuilder builder = new StringBuilder();
        for(byte b : in) {
            builder.append(String.format("%02x", b));
        }
        return builder.toString();
    }    

    static final byte[] testToken = new String(
            "T1RLAQKrMohNdaqjSzkinkn1yr5I_tG2LBBY2TM3XYJadvGNH9gtLx5dAACQpP00vfnLe8ev-bW4xNsUu9UzR-B5TGMSh0CbvgIuIs91UWEnU1CrVg_E_q0yToWx7COkfyuOeVLeR3M8S5l7nz_LiLEJYB2efqejdgjeu9N1-vHU8GJMl1-qCFSTurQl-1I5HLuYNi3VyTomWtPiRXpQrvgknK2KwEma14wXk40JqGOwLDcKTqpr5DJZwoN4")
                    .getBytes();

    public static short bytesToShort(byte[] bytes) {
        // long result = 0x00FF & bytes[0];
        // result <<= 8;
        // result += 0x00FF & bytes[1];
        // return result;

        short[] shorts = new short[bytes.length / 2];
        // Convert the two byte read into a short.
        ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN).asShortBuffer().get(shorts);
        return shorts[0];

    }

    public static boolean isCompressed(final byte[] compressed) {
        return (compressed[0] == (byte) (GZIPInputStream.GZIP_MAGIC))
                && (compressed[1] == (byte) (GZIPInputStream.GZIP_MAGIC >> 8));
    }

    public OTKStructure(String encodedToken) throws Exception {
        // 1. Replace the "*" padding characters with standard Base 64 "=" characters
        Pattern p = Pattern.compile("\\*"); // first excape for java and the second for the regex metacharacter
        Matcher m = p.matcher(encodedToken);
        encodedToken = m.replaceAll("=");
        System.out.println(encodedToken);

        // 2. Base 64 decode the OTK and ensuring that the padding bits are set to zero.
        Hex hex = new Hex();
        byte[] decodedValue = new Base64().decode(encodedToken.getBytes());
    
        ByteBuffer buffer = ByteBuffer.wrap(decodedValue);
        System.out.println("\n" + bytesToHex(decodedValue));


        // 3. Validate the OTK header literal and version.
        // get Header
        byte header[] = new byte[3];
        buffer.get(header);
        this.otkHeaderLiteral = new String(header, UTF8_CHARSET);
        if (this.otkHeaderLiteral.equals(VALID_OTK_HEADER)) {
            System.out.println("OK: " + this.otkHeaderLiteral);
        } else {
            throw new Exception("Header Invalid: (3):" + this.otkHeaderLiteral);
        }

        // Get versionID
        this.versionID = buffer.get();
        System.out.println(this.versionID + "(+1:)" +" \n");

        // get Cipher Suite ID
        this.cipherSuiteID = buffer.get();
        System.out.println(this.cipherSuiteID+ "(+1:)" + "\n");
        tokenCipher = CipherSuite.getTokenCipher(this.cipherSuiteID); // Retreive cipher per cipher suite id

        // get HMAC
        buffer.get(this.hmac);
        System.out.println("HMAC: (20): " + bytesToHex(this.hmac)+"\n");
 

        // get IV Length and IV
        this.ivLength = buffer.get();
        System.out.println(this.ivLength);
        if (this.ivLength > 0) {
            this.iv = new byte[this.ivLength];
            buffer.get(this.iv);
            System.out.println("IV: " + bytesToHex(this.iv));            

        } else {
            System.out.println("No IV: " + this.ivLength);
        }

        // 4. Extract the Key Info (if present) and select a key for decryption.
        this.keyInfoLength = buffer.get();
        if (this.keyInfoLength > 0) {
            this.keyInfo = new byte[this.keyInfoLength];
            buffer.get(this.keyInfo);
            System.out.println("KeyInfo: " + this.keyInfo);
        } else {
            System.out.println("No Key Info: " + this.keyInfoLength);
        }

        // get Payload Length and Payload
        byte[] shortBytes = new byte[2];
        buffer.get(shortBytes);
        this.payloadLength = bytesToShort(shortBytes);

        this.payload = new byte[this.payloadLength];
        buffer.get(payload);

        System.out.println("PayloadLength: " + payloadLength);
        System.out.println("Payload: " + payload);

        // uncompress/decode/decrypt payload

        // byte[] salt2 = tokenCipher.generateSalt();
        //byte[] encodedText = Base64.decodeBase64(this.payload);
        System.out.println("payload: " + bytesToHex(this.payload));

        String decodedText = this.decode("2Federate");
        System.out.println(decodedText);
        if (isCompressed(decodedText.getBytes())) {
            System.out.println("XXXX");
        }

    }

    public String decode(String password) {
        System.out.println("=> " + tokenCipher.getID());
        System.out.println("=> " + tokenCipher.getName());
        System.out.println("=> " + tokenCipher.getCipher());
//        String p = this.tokenCipher.decrypt2(password, this.payload);
        String p = this.tokenCipher.decrypt(password, this.payload, this.iv);

        return p;
    }

    public String getHeader() {
        return this.otkHeaderLiteral;
    }

    public String toJson() {
        return "test";
    }

    @Override
    public String toString() {
        return "test";
    }

}