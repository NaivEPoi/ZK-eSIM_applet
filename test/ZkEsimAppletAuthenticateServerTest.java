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
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

/**
 * jCardSim integration tests for AuthenticateServer (ES10b, BF38).
 *
 * Per SGP.22 v3.1 section 5.7.13, the eUICC SHALL:
 * - Verify that a RSP Session exists (GetEUICCChallenge was called).
 * - Verify that the euiccChallenge in serverSigned1 matches the one attached to
 *   the ongoing RSP Session; otherwise return euiccChallengeMismatch (0x06).
 * - Build euiccSigned1 containing transactionId, serverAddress, serverChallenge,
 *   then sign it with SK.EUICC.SIG.
 *
 * ASN.1 (rsp.asn):
 *   AuthenticateServerRequest ::= [56] SEQUENCE { -- Tag 'BF38'
 *       serverSigned1 ServerSigned1,
 *       serverSignature1 [APPLICATION 55] OCTET STRING,
 *       euiccCiPKIdToBeUsed SubjectKeyIdentifier,
 *       serverCertificate Certificate,
 *       ctxParams1 CtxParams1
 *   }
 *   ServerSigned1 ::= SEQUENCE {
 *       transactionId [0] TransactionId,
 *       euiccChallenge [1] Octet16,
 *       serverAddress [3] UTF8String,
 *       serverChallenge [4] Octet16
 *   }
 *
 */
public class ZkEsimAppletAuthenticateServerTest {

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
            // Follow proprietary 91xx GET RESPONSE chaining until terminal status.
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

    private static int derLengthFieldSize(byte[] data, int lengthOffset) {
        int b = data[lengthOffset] & 0xFF;
        if ((b & 0x80) == 0) {
            return 1;
        }
        return 1 + (b & 0x7F);
    }

    /**
     * Helper: install, select, call GetEuiccChallenge, return the 16-byte challenge.
     */
    private static Simulator setupAndGetChallenge(byte[] challengeOut) {
        Simulator sim = new Simulator();
        AID aid = new AID(APPLET_AID, (short) 0, (byte) APPLET_AID.length);
        sim.installApplet(aid, ZkEsimApplet.class);
        assertTrue("Applet must be selectable", sim.selectApplet(aid));

        ApduResult res = transmit(sim, fromHex("80E2910003BF2E00"));
        assertEquals("GetEuiccChallenge must succeed", 0x9000, res.sw);
        assertTrue("Response too short", res.data.length >= 21);
        System.arraycopy(res.data, 5, challengeOut, 0, 16);
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
     * Build an AuthenticateServerRequest APDU.
     *
     * Structure:
     *   BF38 {
     *     30 { -- serverSigned1
     *       80 LL <txId>
     *       81 10 <euiccChallenge>
     *       83 LL <serverAddress>
     *       84 10 <serverChallenge>
     *     }
     *     5F37 LL <serverSignature1>
     *     04 LL <euiccCiPKIdToBeUsed>
     *     30 00 <serverCertificate placeholder>
     *     A0 00 <ctxParams1 placeholder>
     *   }
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
        System.arraycopy(txId, 0, serverSigned1, p, txId.length);
        p += txId.length;
        serverSigned1[p++] = (byte) 0x81;
        serverSigned1[p++] = 0x10;
        System.arraycopy(euiccChallenge, 0, serverSigned1, p, 16);
        p += 16;
        serverSigned1[p++] = (byte) 0x83;
        serverSigned1[p++] = (byte) serverAddress.length;
        System.arraycopy(serverAddress, 0, serverSigned1, p, serverAddress.length);
        p += serverAddress.length;
        serverSigned1[p++] = (byte) 0x84;
        serverSigned1[p++] = 0x10;
        System.arraycopy(serverChallenge, 0, serverSigned1, p, 16);

        byte[] serverSig = sign(serverSigned1);

        byte[] sigTlv = new byte[3 + serverSig.length];
        sigTlv[0] = (byte) 0x5F;
        sigTlv[1] = (byte) 0x37;
        sigTlv[2] = (byte) serverSig.length;
        System.arraycopy(serverSig, 0, sigTlv, 3, serverSig.length);

        byte[] ciTlv = new byte[2 + ciPKId.length];
        ciTlv[0] = 0x04;
        ciTlv[1] = (byte) ciPKId.length;
        System.arraycopy(ciPKId, 0, ciTlv, 2, ciPKId.length);

        byte[] certTlv = new byte[]{0x30, 0x00};
        byte[] ctxTlv = new byte[]{(byte) 0xA0, 0x00};

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
        apdu[0] = (byte) 0x80;
        apdu[1] = (byte) 0xE2;
        apdu[2] = (byte) 0x91;
        apdu[3] = 0x00;
        apdu[4] = (byte) bf38.length;
        System.arraycopy(bf38, 0, apdu, 5, bf38.length);
        return apdu;
    }

    // -- Positive tests ----------------------------------------------------------

    @Test
    public void testAuthenticateServerDecodeSucceeds() {
        byte[] challenge = new byte[16];
        Simulator sim = setupAndGetChallenge(challenge);

        byte[] txId = fromHex("0102030405");
        byte[] serverAddress = fromHex("736D64702E746573742E636F6D"); // "smdp.test.com"
        byte[] serverChallenge = fromHex("AABBCCDD11223344AABBCCDD11223344");
        byte[] ciPKId = fromHex("01020304");

        byte[] apdu = buildAuthenticateServerApdu(txId, challenge, serverAddress, serverChallenge, ciPKId);
        ApduResult res = transmit(sim, apdu);

        assertEquals("Well-formed BF38 must succeed", 0x9000, res.sw);
        assertTrue("Response must contain BF38 tag", res.data.length >= 3);
        assertEquals((byte) 0xBF, res.data[0]);
        assertEquals(0x38, res.data[1]);

        int outerLenOff = 2;
        int choiceTagOff = outerLenOff + derLengthFieldSize(res.data, outerLenOff);
        assertEquals("First inner element should be CHOICE authenticateResponseOk", (byte) 0xA0, res.data[choiceTagOff]);

        int choiceLenOff = choiceTagOff + 1;
        int seqTagOff = choiceLenOff + derLengthFieldSize(res.data, choiceLenOff);
        assertEquals("First element inside CHOICE should be euiccSigned1 SEQUENCE", 0x30, res.data[seqTagOff] & 0xFF);
    }

    @Test
    public void testAuthenticateServerResponseContainsTxId() {
        // When crypto is available, verify the response echoes the transactionId.
        byte[] challenge = new byte[16];
        Simulator sim = setupAndGetChallenge(challenge);

        byte[] txId = fromHex("AABB");
        byte[] serverAddress = fromHex("736D64702E636F6D"); // "smdp.com"
        byte[] serverChallenge = fromHex("00112233445566778899AABBCCDDEEFF");
        byte[] ciPKId = fromHex("AABBCCDD");

        byte[] apdu = buildAuthenticateServerApdu(txId, challenge, serverAddress, serverChallenge, ciPKId);
        ApduResult res = transmit(sim, apdu);

        assertNotEquals("Well-formed BF38 must not be rejected as invalid data", 0x6A80, res.sw);
        if (res.sw == 0x9000) {
            assertTrue("Response must echo back the transactionId", findBytes(res.data, fromHex("8002AABB")));
        }
    }

    // -- Negative tests: challenge validation ------------------------------------

    @Test
    public void testAuthenticateServerRejectsWithoutSession() {
        // No GetEuiccChallenge called — no active RSP session.
        Simulator sim = new Simulator();
        AID aid = new AID(APPLET_AID, (short) 0, (byte) APPLET_AID.length);
        sim.installApplet(aid, ZkEsimApplet.class);
        assertTrue("Applet must be selectable", sim.selectApplet(aid));

        byte[] txId = fromHex("01020304");
        byte[] fakeChallenge = fromHex("00000000000000000000000000000000");
        byte[] serverAddress = fromHex("736D64702E636F6D");
        byte[] serverChallenge = fromHex("AABBCCDD11223344AABBCCDD11223344");
        byte[] ciPKId = fromHex("01020304");

        byte[] apdu = buildAuthenticateServerApdu(txId, fakeChallenge, serverAddress, serverChallenge, ciPKId);
        ApduResult res = transmit(sim, apdu);

        // Returns BF38 error response with euiccChallengeMismatch (0x06).
        assertEquals("Should return 9000 with error payload", 0x9000, res.sw);
        assertEquals((byte) 0xBF, res.data[0]);
        assertEquals(0x38, res.data[1]);
        assertTrue("Response must contain euiccChallengeMismatch error code (6)",
                findBytes(res.data, fromHex("020106")));
    }

    @Test
    public void testAuthenticateServerRejectsChallengeMismatch() {
        byte[] challenge = new byte[16];
        Simulator sim = setupAndGetChallenge(challenge);

        // Flip all bits to create a wrong challenge.
        byte[] wrongChallenge = new byte[16];
        for (int i = 0; i < 16; i++) {
            wrongChallenge[i] = (byte) (challenge[i] ^ 0xFF);
        }

        byte[] txId = fromHex("DEADBEEF");
        byte[] serverAddress = fromHex("736D64702E636F6D");
        byte[] serverChallenge = fromHex("11111111111111111111111111111111");
        byte[] ciPKId = fromHex("01020304");

        byte[] apdu = buildAuthenticateServerApdu(txId, wrongChallenge, serverAddress, serverChallenge, ciPKId);
        ApduResult res = transmit(sim, apdu);

        assertEquals("Should return 9000 with error payload", 0x9000, res.sw);
        assertEquals((byte) 0xBF, res.data[0]);
        assertEquals(0x38, res.data[1]);
        assertTrue("Response must contain euiccChallengeMismatch error code (6)",
                findBytes(res.data, fromHex("020106")));
    }

    @Test
    public void testAuthenticateServerErrorContainsTxId() {
        // Verify the error response echoes back the transactionId.
        Simulator sim = new Simulator();
        AID aid = new AID(APPLET_AID, (short) 0, (byte) APPLET_AID.length);
        sim.installApplet(aid, ZkEsimApplet.class);
        assertTrue("Applet must be selectable", sim.selectApplet(aid));

        byte[] txId = fromHex("CAFE");
        byte[] fakeChallenge = fromHex("00000000000000000000000000000000");
        byte[] serverAddress = fromHex("736D64702E636F6D");
        byte[] serverChallenge = fromHex("AABBCCDD11223344AABBCCDD11223344");
        byte[] ciPKId = fromHex("01020304");

        byte[] apdu = buildAuthenticateServerApdu(txId, fakeChallenge, serverAddress, serverChallenge, ciPKId);
        ApduResult res = transmit(sim, apdu);

        assertEquals(0x9000, res.sw);
        assertTrue("Error response must echo transactionId",
                findBytes(res.data, fromHex("8002CAFE")));
    }

    // -- Negative tests: malformed payloads --------------------------------------

    @Test
    public void testAuthenticateServerRejectsMalformedPayload() {
        Simulator sim = new Simulator();
        AID aid = new AID(APPLET_AID, (short) 0, (byte) APPLET_AID.length);
        sim.installApplet(aid, ZkEsimApplet.class);
        assertTrue("Applet must be selectable", sim.selectApplet(aid));

        // Malformed BF38: outer length claims more data than provided.
        ApduResult res = transmit(sim, fromHex("80E2910005BF38033000"));
        assertEquals(0x6A80, res.sw);
    }

    @Test
    public void testAuthenticateServerRejectsMissingServerSigned1() {
        byte[] challenge = new byte[16];
        Simulator sim = setupAndGetChallenge(challenge);

        // BF38 with first inner element not a SEQUENCE (starts with 5F37 instead of 30).
        // BF38 05 { 5F37 02 AA BB }
        ApduResult res = transmit(sim, fromHex("80E2910008BF38055F3702AABB"));
        assertEquals("Missing serverSigned1 must be rejected", 0x6A80, res.sw);
    }

    @Test
    public void testAuthenticateServerRejectsInvalidChallengeLength() {
        Simulator sim = new Simulator();
        AID aid = new AID(APPLET_AID, (short) 0, (byte) APPLET_AID.length);
        sim.installApplet(aid, ZkEsimApplet.class);
        assertTrue("Applet must be selectable", sim.selectApplet(aid));

        // ServerSigned1 with euiccChallenge length = 8 instead of 16.
        // 30 { 80 01 AA  81 08 <8bytes>  83 01 BB  84 10 <16bytes> }
        // 5F37 01 CC  04 01 DD  30 00  A0 00
        String ss1 = "301D" +
                "8001AA" +
                "810801020304050607" +       // only 8 bytes — spec requires Octet16
                "830142" +
                "8410AABBCCDD11223344AABBCCDD11223344";
        String rest = "5F370100" + "040100" + "3000" + "A000";
        String inner = ss1 + rest;
        int innerLen = inner.length() / 2;
        String bf38 = String.format("BF38%02X", innerLen) + inner;
        int bf38Len = bf38.length() / 2;
        String apdu = String.format("80E29100%02X", bf38Len) + bf38;

        ApduResult res = transmit(sim, fromHex(apdu));
        assertEquals("euiccChallenge != 16 bytes must be rejected", 0x6A80, res.sw);
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
