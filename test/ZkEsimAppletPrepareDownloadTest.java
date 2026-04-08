import com.licel.jcardsim.base.Simulator;
import javacard.framework.AID;
import org.junit.Test;
import zk.esim.applet.ZkEsimApplet;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

/**
 * jCardSim integration tests for PrepareDownload (ES10b, BF21).
 *
 * Per SGP.22 v3.1 section 5.7.5, the eUICC SHALL:
 * - Verify the SM-DP+ has been previously authenticated (session exists).
 * - Extract transactionId, ccRequiredFlag, optional bppEuiccOtpk from SmdpSigned2.
 * - Generate a new one-time KA key pair (otPK.EUICC.KA) if needed.
 * - Build euiccSigned2 = { transactionId [0], euiccOtpk [APPLICATION 73] }.
 * - Sign euiccSigned2 with SK.EUICC.SIG and return PrepareDownloadResponse.
 *
 * ASN.1 (rsp.asn):
 *   PrepareDownloadRequest ::= [33] SEQUENCE { -- Tag 'BF21'
 *       smdpSigned2 SmdpSigned2,
 *       smdpSignature2 [APPLICATION 55] OCTET STRING,
 *       hashCc Octet32 OPTIONAL,
 *       smdpCertificate Certificate
 *   }
 *   SmdpSigned2 ::= SEQUENCE {
 *       transactionId [0] TransactionId,
 *       ccRequiredFlag BOOLEAN,
 *       bppEuiccOtpk [APPLICATION 73] OCTET STRING OPTIONAL
 *   }
 *   PrepareDownloadResponse ::= [33] CHOICE { -- Tag 'BF21'
 *       downloadResponseOk PrepareDownloadResponseOk,
 *       downloadResponseError PrepareDownloadResponseError
 *   }
 *   PrepareDownloadResponseOk ::= SEQUENCE {
 *       euiccSigned2 EUICCSigned2,
 *       euiccSignature2 [APPLICATION 55] OCTET STRING
 *   }
 *   EUICCSigned2 ::= SEQUENCE {
 *       transactionId [0] TransactionId,
 *       euiccOtpk [APPLICATION 73] OCTET STRING
 *   }
 */
public class ZkEsimAppletPrepareDownloadTest {

    private static final byte[] APPLET_AID = fromHex("D07002CA44900101");

    // jCardSim may not support EC key pair generation; when it doesn't, the applet's
    // Crypto.ensureAsymmetricReady() catches the failure and throws SW_CONDITIONS_NOT_SATISFIED.
    private static final int SW_CRYPTO_UNAVAILABLE = 0x6985;

    private static final class ApduResult {
        final byte[] response;
        final byte[] data;
        final int sw;

        ApduResult(byte[] response) {
            this.response = response;
            this.data = new byte[response.length - 2];
            System.arraycopy(response, 0, this.data, 0, this.data.length);
            this.sw = ((response[response.length - 2] & 0xFF) << 8) | (response[response.length - 1] & 0xFF);
        }
    }

    private static byte[] fromHex(String hex) {
        int len = hex.length();
        if ((len & 1) != 0) {
            throw new IllegalArgumentException("Hex string must have even length");
        }

        byte[] out = new byte[len / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(hex.charAt(i * 2), 16);
            int lo = Character.digit(hex.charAt(i * 2 + 1), 16);
            if (hi < 0 || lo < 0) {
                throw new IllegalArgumentException("Invalid hex input");
            }
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    private static ApduResult transmit(Simulator sim, byte[] command) {
        byte[] responseBytes = sim.transmitCommand(command);
        assertTrue("Response APDU must include SW1SW2", responseBytes.length >= 2);
        int sw = ((responseBytes[responseBytes.length - 2] & 0xFF) << 8) | (responseBytes[responseBytes.length - 1] & 0xFF);
        String testName = currentTestName();
        System.out.println("[" + testName + "] APDU TX: " + toHex(command));
        System.out.println("[" + testName + "] APDU RX: " + toHex(responseBytes) + " SW=" + String.format("%04X", sw));
        return new ApduResult(responseBytes);
    }

    private static String currentTestName() {
        StackTraceElement[] stack = Thread.currentThread().getStackTrace();
        for (int i = 0; i < stack.length; i++) {
            String method = stack[i].getMethodName();
            if (method.startsWith("test")) {
                return method;
            }
        }
        return "unknown-test";
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    private static Simulator createAndSelect() {
        Simulator sim = new Simulator();
        AID aid = new AID(APPLET_AID, (short) 0, (byte) APPLET_AID.length);
        sim.installApplet(aid, ZkEsimApplet.class);
        assertTrue("Applet must be selectable", sim.selectApplet(aid));
        return sim;
    }

    /**
     * Build a PrepareDownloadRequest APDU.
     *
     * Structure:
     *   BF21 {
     *     30 { -- SmdpSigned2
     *       80 LL <txId>            -- transactionId [0]
     *       01 01 <ccFlag>          -- ccRequiredFlag BOOLEAN
     *     }
     *     5F37 LL <smdpSignature2>  -- [APPLICATION 55]
     *     30 00                     -- smdpCertificate (empty SEQUENCE placeholder)
     *   }
     */
    private static byte[] buildPrepareDownloadApdu(byte[] txId, boolean ccRequired, byte[] smdpSig) {
        // SmdpSigned2 body: 80 LL txId | 01 01 ccFlag
        int smdpSigned2Body = 2 + txId.length + 3;
        byte[] smdpSigned2 = new byte[2 + smdpSigned2Body];
        int p = 0;
        smdpSigned2[p++] = 0x30;
        smdpSigned2[p++] = (byte) smdpSigned2Body;
        smdpSigned2[p++] = (byte) 0x80;
        smdpSigned2[p++] = (byte) txId.length;
        System.arraycopy(txId, 0, smdpSigned2, p, txId.length);
        p += txId.length;
        smdpSigned2[p++] = 0x01; // BOOLEAN tag
        smdpSigned2[p++] = 0x01; // length 1
        smdpSigned2[p++] = ccRequired ? (byte) 0xFF : (byte) 0x00;

        // smdpSignature2: 5F37 LL <sig>
        byte[] sigTlv = new byte[3 + smdpSig.length];
        sigTlv[0] = 0x5F;
        sigTlv[1] = 0x37;
        sigTlv[2] = (byte) smdpSig.length;
        System.arraycopy(smdpSig, 0, sigTlv, 3, smdpSig.length);

        // smdpCertificate: 30 00
        byte[] certTlv = new byte[]{0x30, 0x00};

        int innerLen = smdpSigned2.length + sigTlv.length + certTlv.length;

        // BF21 LL <inner>
        byte[] bf21 = new byte[3 + innerLen];
        int q = 0;
        bf21[q++] = (byte) 0xBF;
        bf21[q++] = 0x21;
        bf21[q++] = (byte) innerLen;
        System.arraycopy(smdpSigned2, 0, bf21, q, smdpSigned2.length); q += smdpSigned2.length;
        System.arraycopy(sigTlv,      0, bf21, q, sigTlv.length);      q += sigTlv.length;
        System.arraycopy(certTlv,     0, bf21, q, certTlv.length);

        // STORE DATA APDU: 80 E2 11 00 Lc <data>
        byte[] apdu = new byte[5 + bf21.length];
        apdu[0] = (byte) 0x80;
        apdu[1] = (byte) 0xE2;
        apdu[2] = 0x11;
        apdu[3] = 0x00;
        apdu[4] = (byte) bf21.length;
        System.arraycopy(bf21, 0, apdu, 5, bf21.length);
        return apdu;
    }

    /**
     * Build a PrepareDownloadRequest APDU with optional bppEuiccOtpk.
     */
    private static byte[] buildPrepareDownloadApduWithOtpk(byte[] txId, boolean ccRequired,
                                                            byte[] bppEuiccOtpk, byte[] smdpSig) {
        // SmdpSigned2 body: 80 LL txId | 01 01 ccFlag | 5F49 LL otpk
        int smdpSigned2Body = 2 + txId.length + 3 + 3 + bppEuiccOtpk.length;
        byte[] smdpSigned2 = new byte[2 + smdpSigned2Body];
        int p = 0;
        smdpSigned2[p++] = 0x30;
        smdpSigned2[p++] = (byte) smdpSigned2Body;
        smdpSigned2[p++] = (byte) 0x80;
        smdpSigned2[p++] = (byte) txId.length;
        System.arraycopy(txId, 0, smdpSigned2, p, txId.length);
        p += txId.length;
        smdpSigned2[p++] = 0x01;
        smdpSigned2[p++] = 0x01;
        smdpSigned2[p++] = ccRequired ? (byte) 0xFF : (byte) 0x00;
        smdpSigned2[p++] = 0x5F;
        smdpSigned2[p++] = 0x49;
        smdpSigned2[p++] = (byte) bppEuiccOtpk.length;
        System.arraycopy(bppEuiccOtpk, 0, smdpSigned2, p, bppEuiccOtpk.length);

        byte[] sigTlv = new byte[3 + smdpSig.length];
        sigTlv[0] = 0x5F;
        sigTlv[1] = 0x37;
        sigTlv[2] = (byte) smdpSig.length;
        System.arraycopy(smdpSig, 0, sigTlv, 3, smdpSig.length);

        byte[] certTlv = new byte[]{0x30, 0x00};

        int innerLen = smdpSigned2.length + sigTlv.length + certTlv.length;
        byte[] bf21 = new byte[3 + innerLen];
        int q = 0;
        bf21[q++] = (byte) 0xBF;
        bf21[q++] = 0x21;
        bf21[q++] = (byte) innerLen;
        System.arraycopy(smdpSigned2, 0, bf21, q, smdpSigned2.length); q += smdpSigned2.length;
        System.arraycopy(sigTlv,      0, bf21, q, sigTlv.length);      q += sigTlv.length;
        System.arraycopy(certTlv,     0, bf21, q, certTlv.length);

        byte[] apdu = new byte[5 + bf21.length];
        apdu[0] = (byte) 0x80;
        apdu[1] = (byte) 0xE2;
        apdu[2] = 0x11;
        apdu[3] = 0x00;
        apdu[4] = (byte) bf21.length;
        System.arraycopy(bf21, 0, apdu, 5, bf21.length);
        return apdu;
    }

    // -- Positive tests ----------------------------------------------------------

    @Test
    public void testPrepareDownloadSuccess() {
        Simulator sim = createAndSelect();

        byte[] txId = fromHex("0A0B0C0D");
        byte[] smdpSig = fromHex("DEADBEEFCAFEBABE");

        byte[] apdu = buildPrepareDownloadApdu(txId, false, smdpSig);
        ApduResult res = transmit(sim, apdu);

        assertNotEquals("Well-formed BF21 must not be rejected as invalid data", 0x6A80, res.sw);
        assertTrue("Expected 9000 (success) or 6985 (crypto unavailable in jCardSim)",
                res.sw == 0x9000 || res.sw == SW_CRYPTO_UNAVAILABLE);
        if (res.sw == 0x9000) {
            assertTrue("Response must contain BF21 tag", res.data.length >= 3);
            assertEquals((byte) 0xBF, res.data[0]);
            assertEquals((byte) 0x21, res.data[1]);
            assertEquals("First inner element should be SEQUENCE", (byte) 0x30, res.data[3]);
        }
    }

    @Test
    public void testPrepareDownloadContainsTxIdAndOtpk() {
        Simulator sim = createAndSelect();

        byte[] txId = fromHex("AABBCCDD");
        byte[] smdpSig = fromHex("0000000000000000");

        byte[] apdu = buildPrepareDownloadApdu(txId, false, smdpSig);
        ApduResult res = transmit(sim, apdu);

        assertNotEquals("Well-formed BF21 must not be rejected as invalid data", 0x6A80, res.sw);
        assertTrue("Expected 9000 (success) or 6985 (crypto unavailable in jCardSim)",
                res.sw == 0x9000 || res.sw == SW_CRYPTO_UNAVAILABLE);
        if (res.sw == 0x9000) {
            assertTrue("Response must echo transactionId", findBytes(res.data, fromHex("8004AABBCCDD")));
            // 0x41 = 65 decimal, which is the length of an uncompressed P-256 public key (04 || X || Y)
            assertTrue("Response must contain euiccOtpk (5F49)", findBytes(res.data, fromHex("5F4941")));
        }
    }

    @Test
    public void testPrepareDownloadContainsSignature() {
        Simulator sim = createAndSelect();

        byte[] txId = fromHex("01");
        byte[] smdpSig = fromHex("FF");

        byte[] apdu = buildPrepareDownloadApdu(txId, false, smdpSig);
        ApduResult res = transmit(sim, apdu);

        assertNotEquals("Well-formed BF21 must not be rejected as invalid data", 0x6A80, res.sw);
        assertTrue("Expected 9000 (success) or 6985 (crypto unavailable in jCardSim)",
                res.sw == 0x9000 || res.sw == SW_CRYPTO_UNAVAILABLE);
        if (res.sw == 0x9000) {
            assertTrue("Response must contain euiccSignature2 (5F37)", findBytes(res.data, fromHex("5F37")));
        }
    }

    @Test
    public void testPrepareDownloadWithCcRequiredFlag() {
        Simulator sim = createAndSelect();

        byte[] txId = fromHex("01020304050607");
        byte[] smdpSig = fromHex("AABBCCDD");

        byte[] apdu = buildPrepareDownloadApdu(txId, true, smdpSig);
        ApduResult res = transmit(sim, apdu);

        assertNotEquals("Well-formed BF21 must not be rejected as invalid data", 0x6A80, res.sw);
        assertTrue("PrepareDownload with ccRequired=true: expected 9000 or 6985",
                res.sw == 0x9000 || res.sw == SW_CRYPTO_UNAVAILABLE);
        if (res.sw == 0x9000) {
            assertEquals((byte) 0xBF, res.data[0]);
            assertEquals((byte) 0x21, res.data[1]);
        }
    }

    @Test
    public void testPrepareDownloadWithBppEuiccOtpk() {
        Simulator sim = createAndSelect();

        byte[] txId = fromHex("AABB");
        byte[] otpk = new byte[65];
        otpk[0] = 0x04;
        for (int i = 1; i < 65; i++) otpk[i] = (byte) i;
        byte[] smdpSig = fromHex("1122334455667788");

        byte[] apdu = buildPrepareDownloadApduWithOtpk(txId, false, otpk, smdpSig);
        ApduResult res = transmit(sim, apdu);

        assertNotEquals("Well-formed BF21 must not be rejected as invalid data", 0x6A80, res.sw);
        assertTrue("PrepareDownload with bppEuiccOtpk: expected 9000 or 6985",
                res.sw == 0x9000 || res.sw == SW_CRYPTO_UNAVAILABLE);
        if (res.sw == 0x9000) {
            assertEquals((byte) 0xBF, res.data[0]);
            assertEquals((byte) 0x21, res.data[1]);
        }
    }

    // -- Negative tests ----------------------------------------------------------

    @Test
    public void testPrepareDownloadRejectsMalformedPayload() {
        Simulator sim = createAndSelect();

        // Malformed BF21: outer length claims more data than provided
        ApduResult res = transmit(sim, fromHex("80E2110005BF21033000"));
        assertEquals("Malformed payload must be rejected", 0x6A80, res.sw);
    }

    @Test
    public void testPrepareDownloadRejectsMissingSmdpSigned2() {
        Simulator sim = createAndSelect();

        // BF21 containing only a signature (no SmdpSigned2 SEQUENCE first)
        // BF21 { 5F37 02 AABB }
        ApduResult res = transmit(sim, fromHex("80E2110008BF21055F370200AA"));
        assertEquals("Missing SmdpSigned2 must be rejected", 0x6A80, res.sw);
    }

    @Test
    public void testPrepareDownloadRejectsTxIdTooLong() {
        Simulator sim = createAndSelect();

        // Build a PrepareDownloadRequest where txId is 17 bytes (exceeds max 16)
        byte[] txId = new byte[17];
        for (int i = 0; i < 17; i++) txId[i] = (byte) i;

        // Manual construction with oversized txId
        // SmdpSigned2: 30 { 80 11 <17 bytes> 01 01 00 }
        byte[] smdpSigned2Body = new byte[2 + 17 + 3];
        int p = 0;
        smdpSigned2Body[p++] = (byte) 0x80;
        smdpSigned2Body[p++] = 0x11; // 17
        System.arraycopy(txId, 0, smdpSigned2Body, p, 17); p += 17;
        smdpSigned2Body[p++] = 0x01;
        smdpSigned2Body[p++] = 0x01;
        smdpSigned2Body[p++] = 0x00;

        byte[] smdpSigned2 = new byte[2 + smdpSigned2Body.length];
        smdpSigned2[0] = 0x30;
        smdpSigned2[1] = (byte) smdpSigned2Body.length;
        System.arraycopy(smdpSigned2Body, 0, smdpSigned2, 2, smdpSigned2Body.length);

        byte[] sigTlv = fromHex("5F370100");
        byte[] certTlv = fromHex("3000");

        int innerLen = smdpSigned2.length + sigTlv.length + certTlv.length;
        byte[] bf21 = new byte[3 + innerLen];
        int q = 0;
        bf21[q++] = (byte) 0xBF;
        bf21[q++] = 0x21;
        bf21[q++] = (byte) innerLen;
        System.arraycopy(smdpSigned2, 0, bf21, q, smdpSigned2.length); q += smdpSigned2.length;
        System.arraycopy(sigTlv,      0, bf21, q, sigTlv.length);      q += sigTlv.length;
        System.arraycopy(certTlv,     0, bf21, q, certTlv.length);

        byte[] apdu = new byte[5 + bf21.length];
        apdu[0] = (byte) 0x80;
        apdu[1] = (byte) 0xE2;
        apdu[2] = 0x11;
        apdu[3] = 0x00;
        apdu[4] = (byte) bf21.length;
        System.arraycopy(bf21, 0, apdu, 5, bf21.length);

        ApduResult res = transmit(sim, apdu);
        assertEquals("TxId > 16 bytes must be rejected", 0x6A80, res.sw);
    }

    // -- Helpers -----------------------------------------------------------------

    private static boolean findBytes(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }
}
