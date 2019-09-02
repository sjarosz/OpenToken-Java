package idm.sso.tokens;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;

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


    String otkHeaderLiteral;
    int versionID;
    int cipherSuiteID;
    byte[] hmac = new byte[20];
    int ivLength;
    byte[] iv;
    int keyInfoLenght;
    byte[] keyInfo;
    int payloadLenght;
    byte[] payload;

    static final byte[] testToken = new String(
            "T1RLAQKrMohNdaqjSzkinkn1yr5I_tG2LBBY2TM3XYJadvGNH9gtLx5dAACQpP00vfnLe8ev-bW4xNsUu9UzR-B5TGMSh0CbvgIuIs91UWEnU1CrVg_E_q0yToWx7COkfyuOeVLeR3M8S5l7nz_LiLEJYB2efqejdgjeu9N1-vHU8GJMl1-qCFSTurQl-1I5HLuYNi3VyTomWtPiRXpQrvgknK2KwEma14wXk40JqGOwLDcKTqpr5DJZwoN4")
                    .getBytes();

    public OTKStructure(String encodedToken) throws Exception {
        Pattern p = Pattern.compile("\\*"); // first excape for java and the second for the regex metacharacter
        Matcher m = p.matcher(encodedToken);
        encodedToken = m.replaceAll("=");
        System.out.println(encodedToken);
        ByteBuffer buffer = ByteBuffer.wrap(java.util.Base64.getUrlDecoder().decode(encodedToken));

        byte header[] = new byte[3];

        buffer.get(header);
        this.otkHeaderLiteral = new String(header, UTF8_CHARSET);


        //int index = 0;
        //this.otkHeaderLiteral = Charset.forName("UTF-8").decode(buffer).toString().substring(index, index + 3);
        //index = index + 3;

        if (this.otkHeaderLiteral.equals(VALID_OTK_HEADER)) {
            System.out.println("OK: "+ this.otkHeaderLiteral);
        } else {
            throw new Exception("Header Invalid: " + this.otkHeaderLiteral);
        }

        this.versionID = buffer.get();
        System.out.println(this.versionID);

        this.cipherSuiteID = buffer.get();
        System.out.println(this.cipherSuiteID);        
        buffer.get(this.hmac);
        System.out.println(this.hmac);
        this.ivLength = buffer.get();
        System.out.println(this.ivLength);
        if (this.ivLength > 0){
            this.iv = new byte[this.ivLength];
            buffer.get(this.iv);
            System.out.println(this.iv);
        } else {
            System.out.println("No IV: "+ this.ivLength);
        }

    }

    public String decode(byte[] encodedToken) {
        return "test";
    }

    public String getHeader() {
        return this.otkHeaderLiteral;
    }

    public String toJson() {
        return "test";
    }

    public String toString() {
        return "test";
    }

}