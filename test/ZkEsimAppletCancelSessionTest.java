import com.licel.jcardsim.base.Simulator;
import javacard.framework.AID;
import org.junit.Test;
import zk.esim.applet.ZkEsimApplet;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.io.ByteArrayOutputStream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * jCardSim integration tests for CancelSession (ES10b, BF41).
 *
 * Per SGP.22 v3.1 section 5.7.14, the eUICC SHALL:
 * - Verify that an RSP Session exists with a matching transactionId.
 * - If not found, return a cancelSessionError response with code 0x05.
 * - Build a CancelSessionResponse containing transactionId, SM-DP+ OID, and reason.
 * - Sign the response with SK.EUICC.SIG and clear the session state.
 *
 * ASN.1 (rsp.asn):
 *   CancelSessionRequest ::= [65] SEQUENCE { -- Tag 'BF41'
 *       transactionId [0] TransactionId,
 *       reason        [1] CancelSessionReason  -- INTEGER (exactly 1 byte)
 *   }
 *   CancelSessionResponse ::= [65] CHOICE {
 *       cancelSessionResponseOk    CancelSessionResponseOk,
 *       cancelSessionResponseError CancelSessionResponseError
 *   }
 *   CancelSessionResponseOk ::= SEQUENCE {
 *       euiccCancelSessionSigned    EuiccCancelSessionSigned,
 *       euiccCancelSessionSignature [APPLICATION 55] OCTET STRING
 *   }
 *   EuiccCancelSessionSigned ::= SEQUENCE {
 *       transactionId OCTET STRING,
 *       smdpOid       OBJECT IDENTIFIER,
 *       reason        INTEGER
 *   }
 */
public class ZkEsimAppletCancelSessionTest {

    private static final byte[] APPLET_AID = fromHex("D07002CA44900101");
    private static final byte[] TEST_PRIVATE_KEY_DER = fromHex(
            "308187020100301306072A8648CE3D020106082A8648CE3D030107046D306B02010104200A7CC1C244E60C52CD5B7807AB8C360C26524601507DCABC5DD598B5A616D5D5A144034200044DFED4F4694791BF1695CEA0307A35B418019695387BB75B7D2447B6B5209F0445AE4E5E521CD13888D75FE07C8580222AE20DBAAC1D77CD76304993421BD739"
    );

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
        ByteArrayOutputStream allData = new ByteArrayOutputStream();
        byte[] responseBytes = sim.transmitCommand(command);
        assertTrue("Response APDU must include SW1SW2", responseBytes.length >= 2);
        int sw = ((responseBytes[responseBytes.length - 2] & 0xFF) << 8) | (responseBytes[responseBytes.length - 1] & 0xFF);
        allData.write(responseBytes, 0, responseBytes.length - 2);

        while ((sw & 0xFF00) == 0x9100) {
            byte[] getResp = new byte[]{0x00, (byte) 0xC0, 0x00, 0x00, 0x00};
            responseBytes = sim.transmitCommand(getResp);
            assertTrue("GET RESPONSE APDU must include SW1SW2", responseBytes.length >= 2);
            sw = ((responseBytes[responseBytes.length - 2] & 0xFF) << 8)
                    | (responseBytes[responseBytes.length - 1] & 0xFF);
            allData.write(responseBytes, 0, responseBytes.length - 2);
        }

        byte[] fullResponse = new byte[allData.size() + 2];
        byte[] data = allData.toByteArray();
        System.arraycopy(data, 0, fullResponse, 0, data.length);
        fullResponse[fullResponse.length - 2] = (byte) ((sw >> 8) & 0xFF);
        fullResponse[fullResponse.length - 1] = (byte) (sw & 0xFF);

        String testName = currentTestName();
        System.out.println("[" + testName + "] APDU TX: " + toHex(command));
        System.out.println("[" + testName + "] APDU RX: " + toHex(fullResponse) + " SW=" + String.format("%04X", sw));
        return new ApduResult(fullResponse);
    }

    private static String currentTestName() {
        StackTraceElement[] stack = Thread.currentThread().getStackTrace();
        for (StackTraceElement element : stack) {
            if (element.getMethodName().startsWith("test")) {
                return element.getMethodName();
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

    private static byte[] sign(byte[] data) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(TEST_PRIVATE_KEY_DER));
            Signature signer = Signature.getInstance("SHA256withECDSA");
            signer.initSign(privateKey);
            signer.update(data);
            return derEcdsaToRaw(signer.sign());
        } catch (Exception e) {
            throw new RuntimeException("Unable to sign test payload", e);
        }
    }

    private static byte[] derEcdsaToRaw(byte[] derSig) {
        if (derSig.length < 8 || derSig[0] != 0x30) {
            throw new IllegalArgumentException("Expected DER ECDSA signature");
        }

        int offset = 1;
        int seqLen = derSig[offset] & 0xFF;
        offset++;
        if ((seqLen & 0x80) != 0) {
            int lenBytes = seqLen & 0x7F;
            if (lenBytes != 1 || offset >= derSig.length) {
                throw new IllegalArgumentException("Unsupported DER ECDSA length");
            }
            seqLen = derSig[offset] & 0xFF;
            offset++;
        }

        if (derSig[offset++] != 0x02) {
            throw new IllegalArgumentException("Expected DER INTEGER for r");
        }
        int rLen = derSig[offset++] & 0xFF;
        int rStart = offset;
        offset += rLen;

        if (derSig[offset++] != 0x02) {
            throw new IllegalArgumentException("Expected DER INTEGER for s");
        }
        int sLen = derSig[offset++] & 0xFF;
        int sStart = offset;

        byte[] raw = new byte[64];
        copyDerIntegerToRaw(derSig, rStart, rLen, raw, 0);
        copyDerIntegerToRaw(derSig, sStart, sLen, raw, 32);
        return raw;
    }

    private static void copyDerIntegerToRaw(byte[] derSig, int derOff, int derLen, byte[] rawOut, int rawOff) {
        int src = derOff;
        int srcEnd = derOff + derLen;
        while (src < srcEnd && derSig[src] == 0x00) {
            src++;
        }
        int outLen = srcEnd - src;
        if (outLen > 32) {
            throw new IllegalArgumentException("DER integer too large for raw P-256 signature");
        }
        int pad = 32 - outLen;
        for (int i = 0; i < pad; i++) {
            rawOut[rawOff + i] = 0x00;
        }
        System.arraycopy(derSig, src, rawOut, rawOff + pad, outLen);
    }

    /**
     * Install, select, run GetEuiccChallenge, and then AuthenticateServer to establish
     * an active RSP session for the given transactionId.
     */
    private static Simulator setupActiveSession(byte[] txId) {
        Simulator sim = createAndSelect();

        ApduResult challengeRes = transmit(sim, fromHex("80E2910003BF2E00"));
        assertEquals("GetEuiccChallenge must succeed", 0x9000, challengeRes.sw);
        byte[] challenge = new byte[16];
        assertTrue("Challenge response too short", challengeRes.data.length >= 21);
        System.arraycopy(challengeRes.data, 5, challenge, 0, 16);

        byte[] serverAddress = fromHex("736D64702E746573742E636F6D"); // "smdp.test.com"
        byte[] serverChallenge = fromHex("AABBCCDD11223344AABBCCDD11223344");
        byte[] ciPKId = fromHex("01020304");

        byte[] authApdu = buildAuthenticateServerApdu(txId, challenge, serverAddress, serverChallenge, ciPKId);
        ApduResult authRes = transmit(sim, authApdu);
        assertEquals("AuthenticateServer must succeed to establish session", 0x9000, authRes.sw);

        return sim;
    }

    /**
     * Build a CancelSessionRequest APDU.
     *
     * Structure:
     *   BF41 {
     *     80 LL <txId>    -- [0] TransactionId
     *     81 01 <reason>  -- [1] CancelSessionReason
     *   }
     */
    private static byte[] buildCancelSessionApdu(byte[] txId, byte reason) {
        int innerLen = 2 + txId.length + 3;
        byte[] bf41 = new byte[3 + innerLen];
        int p = 0;
        bf41[p++] = (byte) 0xBF;
        bf41[p++] = 0x41;
        bf41[p++] = (byte) innerLen;
        bf41[p++] = (byte) 0x80;
        bf41[p++] = (byte) txId.length;
        System.arraycopy(txId, 0, bf41, p, txId.length);
        p += txId.length;
        bf41[p++] = (byte) 0x81;
        bf41[p++] = 0x01;
        bf41[p]   = reason;

        byte[] apdu = new byte[5 + bf41.length];
        apdu[0] = (byte) 0x80;
        apdu[1] = (byte) 0xE2;
        apdu[2] = (byte) 0x91;
        apdu[3] = 0x00;
        apdu[4] = (byte) bf41.length;
        System.arraycopy(bf41, 0, apdu, 5, bf41.length);
        return apdu;
    }

    /**
     * Build an AuthenticateServerRequest APDU (mirrors ZkEsimAppletAuthenticateServerTest).
     */
    private static byte[] buildAuthenticateServerApdu(byte[] txId, byte[] euiccChallenge,
                                                       byte[] serverAddress, byte[] serverChallenge,
                                                       byte[] ciPKId) {
        int ssLen = 2 + txId.length + 2 + 16 + 2 + serverAddress.length + 2 + 16;
        byte[] serverSigned1 = new byte[2 + ssLen];
        int p = 0;
        serverSigned1[p++] = 0x30;
        serverSigned1[p++] = (byte) ssLen;
        serverSigned1[p++] = (byte) 0x80;
        serverSigned1[p++] = (byte) txId.length;
        System.arraycopy(txId, 0, serverSigned1, p, txId.length); p += txId.length;
        serverSigned1[p++] = (byte) 0x81;
        serverSigned1[p++] = 0x10;
        System.arraycopy(euiccChallenge, 0, serverSigned1, p, 16); p += 16;
        serverSigned1[p++] = (byte) 0x83;
        serverSigned1[p++] = (byte) serverAddress.length;
        System.arraycopy(serverAddress, 0, serverSigned1, p, serverAddress.length); p += serverAddress.length;
        serverSigned1[p++] = (byte) 0x84;
        serverSigned1[p++] = 0x10;
        System.arraycopy(serverChallenge, 0, serverSigned1, p, 16);

        byte[] serverSig = sign(serverSigned1);

        byte[] sigTlv = new byte[3 + serverSig.length];
        sigTlv[0] = 0x5F; sigTlv[1] = 0x37; sigTlv[2] = (byte) serverSig.length;
        System.arraycopy(serverSig, 0, sigTlv, 3, serverSig.length);

        byte[] ciTlv = new byte[2 + ciPKId.length];
        ciTlv[0] = 0x04; ciTlv[1] = (byte) ciPKId.length;
        System.arraycopy(ciPKId, 0, ciTlv, 2, ciPKId.length);

        byte[] certTlv = {0x30, 0x00};
        byte[] ctxTlv  = {(byte) 0xA0, 0x00};

        int innerLen = serverSigned1.length + sigTlv.length + ciTlv.length + certTlv.length + ctxTlv.length;
        byte[] bf38 = new byte[4 + innerLen];
        int q = 0;
        bf38[q++] = (byte) 0xBF;
        bf38[q++] = 0x38;
        bf38[q++] = (byte) 0x81;
        bf38[q++] = (byte) innerLen;
        System.arraycopy(serverSigned1, 0, bf38, q, serverSigned1.length); q += serverSigned1.length;
        System.arraycopy(sigTlv,        0, bf38, q, sigTlv.length);        q += sigTlv.length;
        System.arraycopy(ciTlv,         0, bf38, q, ciTlv.length);         q += ciTlv.length;
        System.arraycopy(certTlv,       0, bf38, q, certTlv.length);       q += certTlv.length;
        System.arraycopy(ctxTlv,        0, bf38, q, ctxTlv.length);

        byte[] apdu = new byte[5 + bf38.length];
        apdu[0] = (byte) 0x80; apdu[1] = (byte) 0xE2; apdu[2] = (byte) 0x91;
        apdu[3] = 0x00; apdu[4] = (byte) bf38.length;
        System.arraycopy(bf38, 0, apdu, 5, bf38.length);
        return apdu;
    }

    // -- Positive tests ----------------------------------------------------------

    @Test
    public void testCancelSessionSucceeds() {
        byte[] txId = fromHex("0102030405");
        Simulator sim = setupActiveSession(txId);

        ApduResult res = transmit(sim, buildCancelSessionApdu(txId, (byte) 0x00));

        assertEquals("CancelSession with active session must succeed", 0x9000, res.sw);
        assertTrue("Response must be at least 3 bytes", res.data.length >= 3);
        assertEquals((byte) 0xBF, res.data[0]);
        assertEquals(0x41, res.data[1]);
        // First element inside BF41 is a signed SEQUENCE (0x30)
        assertEquals("First inner element must be SEQUENCE", 0x30, res.data[3]);
    }

    @Test
    public void testCancelSessionResponseContainsTxId() {
        byte[] txId = fromHex("AABBCCDD");
        Simulator sim = setupActiveSession(txId);

        ApduResult res = transmit(sim, buildCancelSessionApdu(txId, (byte) 0x01));

        assertEquals(0x9000, res.sw);
        // buildCancelSessionResponse encodes txId as OCTET STRING: 04 04 AA BB CC DD
        assertTrue("Response must echo transactionId as OCTET STRING",
                findBytes(res.data, fromHex("0404AABBCCDD")));
    }

    @Test
    public void testCancelSessionResponseContainsReason() {
        byte[] txId = fromHex("CAFE");
        Simulator sim = setupActiveSession(txId);

        ApduResult res = transmit(sim, buildCancelSessionApdu(txId, (byte) 0x03));

        assertEquals(0x9000, res.sw);
        // Reason is encoded as INTEGER: 02 01 03
        assertTrue("Response must contain reason code 0x03", findBytes(res.data, fromHex("020103")));
    }

    @Test
    public void testCancelSessionResponseContainsSignature() {
        byte[] txId = fromHex("01");
        Simulator sim = setupActiveSession(txId);

        ApduResult res = transmit(sim, buildCancelSessionApdu(txId, (byte) 0x00));

        assertEquals(0x9000, res.sw);
        // Signature tagged APPLICATION 55: 5F 37
        assertTrue("Response must contain euiccSignature (5F37)", findBytes(res.data, fromHex("5F37")));
    }

    @Test
    public void testCancelSessionClearsSessionState() {
        byte[] txId = fromHex("DEADBEEF");
        Simulator sim = setupActiveSession(txId);
        byte[] apdu = buildCancelSessionApdu(txId, (byte) 0x00);

        ApduResult firstRes = transmit(sim, apdu);
        assertEquals("First CancelSession must succeed", 0x9000, firstRes.sw);
        assertEquals((byte) 0xBF, firstRes.data[0]);
        assertEquals(0x41, firstRes.data[1]);

        // After cancel the session is gone; a second cancel must return the error payload.
        ApduResult secondRes = transmit(sim, apdu);
        assertEquals("Second CancelSession must return 9000 with error payload", 0x9000, secondRes.sw);
        assertEquals((byte) 0xBF, secondRes.data[0]);
        assertEquals(0x41, secondRes.data[1]);
        assertTrue("Second cancel must report cancelSessionError (0x05)",
                findBytes(secondRes.data, fromHex("020105")));
    }

    // -- Negative tests: session validation -------------------------------------

    @Test
    public void testCancelSessionRejectsWithoutSession() {
        // No GetEuiccChallenge / AuthenticateServer — no active session.
        Simulator sim = createAndSelect();

        ApduResult res = transmit(sim, buildCancelSessionApdu(fromHex("01020304"), (byte) 0x00));

        assertEquals("Should return 9000 with error payload", 0x9000, res.sw);
        assertEquals((byte) 0xBF, res.data[0]);
        assertEquals(0x41, res.data[1]);
        assertTrue("Response must contain cancelSessionError code (0x05)",
                findBytes(res.data, fromHex("020105")));
    }

    @Test
    public void testCancelSessionRejectsWrongTxId() {
        byte[] correctTxId = fromHex("AABB1234");
        byte[] wrongTxId   = fromHex("DEADBEEF");
        Simulator sim = setupActiveSession(correctTxId);

        ApduResult res = transmit(sim, buildCancelSessionApdu(wrongTxId, (byte) 0x00));

        assertEquals("Should return 9000 with error payload", 0x9000, res.sw);
        assertEquals((byte) 0xBF, res.data[0]);
        assertEquals(0x41, res.data[1]);
        assertTrue("Response must contain cancelSessionError code (0x05)",
                findBytes(res.data, fromHex("020105")));
    }

    @Test
    public void testCancelSessionRejectsTxIdLengthMismatch() {
        byte[] correctTxId        = fromHex("AABB");
        byte[] differentLengthTxId = fromHex("AABBCC"); // 3 bytes vs 2
        Simulator sim = setupActiveSession(correctTxId);

        ApduResult res = transmit(sim, buildCancelSessionApdu(differentLengthTxId, (byte) 0x00));

        assertEquals("Should return 9000 with error payload", 0x9000, res.sw);
        assertEquals((byte) 0xBF, res.data[0]);
        assertEquals(0x41, res.data[1]);
        assertTrue("Response must contain cancelSessionError code (0x05)",
                findBytes(res.data, fromHex("020105")));
    }

    // -- Negative tests: malformed payloads -------------------------------------

    @Test
    public void testCancelSessionRejectsMalformedPayload() {
        Simulator sim = createAndSelect();

        // BF41 03 30 00: outer length claims 3 bytes but only 2 bytes follow
        ApduResult res = transmit(sim, fromHex("80E2910005BF41033000"));
        assertEquals("Malformed payload must be rejected", 0x6A80, res.sw);
    }

    @Test
    public void testCancelSessionRejectsMissingReasonField() {
        Simulator sim = createAndSelect();

        // BF41 { 80 01 AA } — txId present but no reason [1] field
        // BF41 03 80 01 AA → APDU: 80 E2 91 00 06 BF 41 03 80 01 AA
        ApduResult res = transmit(sim, fromHex("80E2910006BF41038001AA"));
        assertEquals("Missing reason field must be rejected", 0x6A80, res.sw);
    }

    @Test
    public void testCancelSessionRejectsOversizedReason() {
        Simulator sim = createAndSelect();

        // BF41 { 80 01 AA | 81 02 AA BB } — reason must be exactly 1 byte
        // inner = 3 + 4 = 7 bytes → BF41 07 80 01 AA 81 02 AA BB
        // APDU: 80 E2 91 00 0A BF 41 07 80 01 AA 81 02 AA BB
        ApduResult res = transmit(sim, fromHex("80E291000ABF41078001AA8102AABB"));
        assertEquals("Reason > 1 byte must be rejected", 0x6A80, res.sw);
    }

    @Test
    public void testCancelSessionRejectsTxIdTooLong() {
        Simulator sim = createAndSelect();

        // txId of 17 bytes exceeds the allowed maximum of 16
        byte[] txId = new byte[17];
        for (int i = 0; i < 17; i++) txId[i] = (byte) i;

        int innerLen = 2 + txId.length + 3;
        byte[] bf41 = new byte[3 + innerLen];
        int p = 0;
        bf41[p++] = (byte) 0xBF;
        bf41[p++] = 0x41;
        bf41[p++] = (byte) innerLen;
        bf41[p++] = (byte) 0x80;
        bf41[p++] = (byte) txId.length;
        System.arraycopy(txId, 0, bf41, p, txId.length); p += txId.length;
        bf41[p++] = (byte) 0x81;
        bf41[p++] = 0x01;
        bf41[p]   = 0x00;

        byte[] apdu = new byte[5 + bf41.length];
        apdu[0] = (byte) 0x80; apdu[1] = (byte) 0xE2; apdu[2] = (byte) 0x91;
        apdu[3] = 0x00; apdu[4] = (byte) bf41.length;
        System.arraycopy(bf41, 0, apdu, 5, bf41.length);

        ApduResult res = transmit(sim, apdu);
        assertEquals("TxId > 16 bytes must be rejected", 0x6A80, res.sw);
    }

    @Test
    public void testCancelSessionRejectsTxIdZeroLength() {
        Simulator sim = createAndSelect();

        // BF41 { 80 00 | 81 01 00 } — txId of zero length is invalid (min 1)
        // inner = 2 + 3 = 5 bytes → BF41 05 80 00 81 01 00
        // APDU: 80 E2 91 00 08 BF 41 05 80 00 81 01 00
        ApduResult res = transmit(sim, fromHex("80E2910008BF41058000810100"));
        assertEquals("TxId of zero length must be rejected", 0x6A80, res.sw);
    }

    // -- Helpers -----------------------------------------------------------------

    private static boolean findBytes(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) continue outer;
            }
            return true;
        }
        return false;
    }
}
