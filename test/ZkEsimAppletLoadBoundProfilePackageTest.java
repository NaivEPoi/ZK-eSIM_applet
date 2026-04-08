import com.licel.jcardsim.base.Simulator;
import javacard.framework.AID;
import org.junit.Test;
import zk.esim.applet.ZkEsimApplet;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * jCardSim integration tests for LoadBoundProfilePackage (ES10b, BF36).
 *
 * Per SGP.22 v3.1 section 5.7.6, the eUICC SHALL:
 * - Transfer a Bound Profile Package to the eUICC.
 * - Erase otSK.EUICC.KA attached to the RSP Session.
 * - Discard the session (euiccChallenge cleared).
 * - Return no response payload for the local load step (just SW 9000).
 *
 * ASN.1 (rsp.asn):
 *   BoundProfilePackage ::= [54] SEQUENCE { -- Tag 'BF36'
 *       initialiseSecureChannelRequest [35] InitialiseSecureChannelRequest, -- Tag 'BF23'
 *       firstSequenceOf87 [0] SEQUENCE OF [7] OCTET STRING,
 *       sequenceOf88 [1] SEQUENCE OF [8] OCTET STRING,
 *       secondSequenceOf87 [2] SEQUENCE OF [7] OCTET STRING OPTIONAL,
 *       sequenceOf86 [3] SEQUENCE OF [6] OCTET STRING
 *   }
 *   InitialiseSecureChannelRequest ::= [35] SEQUENCE { -- Tag 'BF23'
 *       remoteOpId RemoteOpId,  -- INTEGER, value = installBoundProfilePackage(1)
 *       transactionId [0] TransactionId,
 *       controlRefTemplate [6] IMPLICIT ControlRefTemplate,
 *       smdpOtpk [APPLICATION 73] OCTET STRING,
 *       smdpSign [APPLICATION 55] OCTET STRING
 *   }
 */
public class ZkEsimAppletLoadBoundProfilePackageTest {

    private static final byte[] APPLET_AID = fromHex("D07002CA44900101");

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
     * Build a minimal BoundProfilePackage APDU.
     *
     * BF36 {
     *   BF23 {  -- InitialiseSecureChannelRequest
     *     02 01 01                 -- remoteOpId INTEGER = 1 (installBoundProfilePackage)
     *     80 LL <txId>             -- transactionId [0]
     *     A6 { 80 01 88 }         -- controlRefTemplate [6] { keyType [0] = 0x88 (AES) }
     *     5F49 LL <smdpOtpk>      -- [APPLICATION 73]
     *     5F37 LL <smdpSign>      -- [APPLICATION 55]
     *   }
     *   A0 { 87 LL <data> }       -- [0] SEQUENCE OF [7] OCTET STRING
     *   A1 { 88 LL <data> }       -- [1] SEQUENCE OF [8] OCTET STRING
     *   A3 { 86 LL <data> }       -- [3] SEQUENCE OF [6] OCTET STRING
     * }
     */
    private static byte[] buildLoadBppApdu(byte[] txId) {
        // -- InitialiseSecureChannelRequest body --
        byte[] remoteOpId = fromHex("020101"); // INTEGER 1

        // transactionId [0]
        byte[] txIdTlv = new byte[2 + txId.length];
        txIdTlv[0] = (byte) 0x80;
        txIdTlv[1] = (byte) txId.length;
        System.arraycopy(txId, 0, txIdTlv, 2, txId.length);

        // controlRefTemplate [6] IMPLICIT: A6 { 80 01 88 }
        byte[] crt = fromHex("A603800188");

        // smdpOtpk [APPLICATION 73]: 5F49 LL <65 bytes dummy>
        byte[] otpk = new byte[65];
        otpk[0] = 0x04;
        for (int i = 1; i < 65; i++) otpk[i] = (byte) i;
        byte[] otpkTlv = new byte[3 + otpk.length];
        otpkTlv[0] = 0x5F;
        otpkTlv[1] = 0x49;
        otpkTlv[2] = (byte) otpk.length;
        System.arraycopy(otpk, 0, otpkTlv, 3, otpk.length);

        // smdpSign [APPLICATION 55]: 5F37 LL <8 bytes dummy>
        byte[] sign = fromHex("5F370801020304050607080000000000");
        // Actually let's build it cleanly
        byte[] signData = fromHex("0102030405060708");
        sign = new byte[3 + signData.length];
        sign[0] = 0x5F;
        sign[1] = 0x37;
        sign[2] = (byte) signData.length;
        System.arraycopy(signData, 0, sign, 3, signData.length);

        int bf23BodyLen = remoteOpId.length + txIdTlv.length + crt.length + otpkTlv.length + sign.length;
        byte[] bf23 = new byte[3 + bf23BodyLen];
        int p = 0;
        bf23[p++] = (byte) 0xBF;
        bf23[p++] = 0x23;
        bf23[p++] = (byte) bf23BodyLen;
        System.arraycopy(remoteOpId, 0, bf23, p, remoteOpId.length); p += remoteOpId.length;
        System.arraycopy(txIdTlv,    0, bf23, p, txIdTlv.length);    p += txIdTlv.length;
        System.arraycopy(crt,        0, bf23, p, crt.length);        p += crt.length;
        System.arraycopy(otpkTlv,    0, bf23, p, otpkTlv.length);    p += otpkTlv.length;
        System.arraycopy(sign,       0, bf23, p, sign.length);

        // [0] SEQUENCE OF [7] OCTET STRING: A0 { 87 02 AABB }
        byte[] a0 = fromHex("A00487020102");

        // [1] SEQUENCE OF [8] OCTET STRING: A1 { 88 02 CCDD }
        byte[] a1 = fromHex("A10488020304");

        // [3] SEQUENCE OF [6] OCTET STRING: A3 { 86 02 EEFF }
        byte[] a3 = fromHex("A30486020506");

        int bf36BodyLen = bf23.length + a0.length + a1.length + a3.length;

        // Use 2-byte length encoding if needed
        byte[] bf36;
        if (bf36BodyLen < 128) {
            bf36 = new byte[3 + bf36BodyLen];
            int q = 0;
            bf36[q++] = (byte) 0xBF;
            bf36[q++] = 0x36;
            bf36[q++] = (byte) bf36BodyLen;
            System.arraycopy(bf23, 0, bf36, q, bf23.length); q += bf23.length;
            System.arraycopy(a0,   0, bf36, q, a0.length);   q += a0.length;
            System.arraycopy(a1,   0, bf36, q, a1.length);   q += a1.length;
            System.arraycopy(a3,   0, bf36, q, a3.length);
        } else {
            bf36 = new byte[4 + bf36BodyLen];
            int q = 0;
            bf36[q++] = (byte) 0xBF;
            bf36[q++] = 0x36;
            bf36[q++] = (byte) 0x81;
            bf36[q++] = (byte) bf36BodyLen;
            System.arraycopy(bf23, 0, bf36, q, bf23.length); q += bf23.length;
            System.arraycopy(a0,   0, bf36, q, a0.length);   q += a0.length;
            System.arraycopy(a1,   0, bf36, q, a1.length);   q += a1.length;
            System.arraycopy(a3,   0, bf36, q, a3.length);
        }

        // STORE DATA APDU: 80 E2 11 00 Lc <data>
        byte[] apdu = new byte[5 + bf36.length];
        apdu[0] = (byte) 0x80;
        apdu[1] = (byte) 0xE2;
        apdu[2] = 0x11;
        apdu[3] = 0x00;
        apdu[4] = (byte) bf36.length;
        System.arraycopy(bf36, 0, apdu, 5, bf36.length);
        return apdu;
    }

    /**
     * Build a BoundProfilePackage with optional [2] SEQUENCE OF [7] OCTET STRING.
     */
    private static byte[] buildLoadBppApduWithOptionalA2(byte[] txId) {
        byte[] remoteOpId = fromHex("020101");
        byte[] txIdTlv = new byte[2 + txId.length];
        txIdTlv[0] = (byte) 0x80;
        txIdTlv[1] = (byte) txId.length;
        System.arraycopy(txId, 0, txIdTlv, 2, txId.length);
        byte[] crt = fromHex("A603800188");

        byte[] otpk = new byte[65];
        otpk[0] = 0x04;
        for (int i = 1; i < 65; i++) otpk[i] = (byte) i;
        byte[] otpkTlv = new byte[3 + otpk.length];
        otpkTlv[0] = 0x5F; otpkTlv[1] = 0x49; otpkTlv[2] = (byte) otpk.length;
        System.arraycopy(otpk, 0, otpkTlv, 3, otpk.length);

        byte[] signData = fromHex("0102030405060708");
        byte[] sign = new byte[3 + signData.length];
        sign[0] = 0x5F; sign[1] = 0x37; sign[2] = (byte) signData.length;
        System.arraycopy(signData, 0, sign, 3, signData.length);

        int bf23BodyLen = remoteOpId.length + txIdTlv.length + crt.length + otpkTlv.length + sign.length;
        byte[] bf23 = new byte[3 + bf23BodyLen];
        int p = 0;
        bf23[p++] = (byte) 0xBF; bf23[p++] = 0x23; bf23[p++] = (byte) bf23BodyLen;
        System.arraycopy(remoteOpId, 0, bf23, p, remoteOpId.length); p += remoteOpId.length;
        System.arraycopy(txIdTlv,    0, bf23, p, txIdTlv.length);    p += txIdTlv.length;
        System.arraycopy(crt,        0, bf23, p, crt.length);        p += crt.length;
        System.arraycopy(otpkTlv,    0, bf23, p, otpkTlv.length);    p += otpkTlv.length;
        System.arraycopy(sign,       0, bf23, p, sign.length);

        byte[] a0 = fromHex("A00487020102");
        byte[] a1 = fromHex("A10488020304");
        byte[] a2 = fromHex("A20487020708"); // optional [2]
        byte[] a3 = fromHex("A30486020506");

        int bf36BodyLen = bf23.length + a0.length + a1.length + a2.length + a3.length;
        byte[] bf36;
        if (bf36BodyLen < 128) {
            bf36 = new byte[3 + bf36BodyLen];
            int q = 0;
            bf36[q++] = (byte) 0xBF; bf36[q++] = 0x36; bf36[q++] = (byte) bf36BodyLen;
            System.arraycopy(bf23, 0, bf36, q, bf23.length); q += bf23.length;
            System.arraycopy(a0,   0, bf36, q, a0.length);   q += a0.length;
            System.arraycopy(a1,   0, bf36, q, a1.length);   q += a1.length;
            System.arraycopy(a2,   0, bf36, q, a2.length);   q += a2.length;
            System.arraycopy(a3,   0, bf36, q, a3.length);
        } else {
            bf36 = new byte[4 + bf36BodyLen];
            int q = 0;
            bf36[q++] = (byte) 0xBF; bf36[q++] = 0x36; bf36[q++] = (byte) 0x81; bf36[q++] = (byte) bf36BodyLen;
            System.arraycopy(bf23, 0, bf36, q, bf23.length); q += bf23.length;
            System.arraycopy(a0,   0, bf36, q, a0.length);   q += a0.length;
            System.arraycopy(a1,   0, bf36, q, a1.length);   q += a1.length;
            System.arraycopy(a2,   0, bf36, q, a2.length);   q += a2.length;
            System.arraycopy(a3,   0, bf36, q, a3.length);
        }

        byte[] apdu = new byte[5 + bf36.length];
        apdu[0] = (byte) 0x80; apdu[1] = (byte) 0xE2; apdu[2] = 0x11; apdu[3] = 0x00;
        apdu[4] = (byte) bf36.length;
        System.arraycopy(bf36, 0, apdu, 5, bf36.length);
        return apdu;
    }

    // -- Positive tests ----------------------------------------------------------

    @Test
    public void testLoadBoundProfilePackageSuccess() {
        Simulator sim = createAndSelect();

        byte[] txId = fromHex("0A0B0C0D");
        byte[] apdu = buildLoadBppApdu(txId);
        ApduResult res = transmit(sim, apdu);

        assertEquals("LoadBoundProfilePackage must succeed", 0x9000, res.sw);
        // No response payload is expected for the local load step
        assertEquals("No response data expected", 0, res.data.length);
    }

    @Test
    public void testLoadBoundProfilePackageWithOptionalA2() {
        Simulator sim = createAndSelect();

        byte[] txId = fromHex("DEADBEEF");
        byte[] apdu = buildLoadBppApduWithOptionalA2(txId);
        ApduResult res = transmit(sim, apdu);

        assertEquals("LoadBPP with optional [2] must succeed", 0x9000, res.sw);
        assertEquals("No response data expected", 0, res.data.length);
    }

    @Test
    public void testLoadBppClearsSessionState() {
        // After LoadBPP, the session should be cleared. A subsequent AuthenticateServer
        // with a previously-valid challenge should fail with euiccChallengeMismatch.
        Simulator sim = new Simulator();
        AID aid = new AID(APPLET_AID, (short) 0, (byte) APPLET_AID.length);
        sim.installApplet(aid, ZkEsimApplet.class);
        assertTrue("Applet must be selectable", sim.selectApplet(aid));

        // 1. GetEuiccChallenge
        ApduResult challengeRes = transmit(sim, fromHex("80E2110005BF2E023000"));
        assertEquals(0x9000, challengeRes.sw);
        byte[] challenge = new byte[16];
        System.arraycopy(challengeRes.data, 7, challenge, 0, 16);

        // 2. LoadBPP (clears session)
        byte[] txId = fromHex("01020304");
        byte[] bppApdu = buildLoadBppApdu(txId);
        ApduResult bppRes = transmit(sim, bppApdu);
        assertEquals(0x9000, bppRes.sw);

        // 3. AuthenticateServer with the old challenge — should fail
        byte[] serverAddress = fromHex("736D64702E636F6D");
        byte[] serverChallenge = fromHex("AABBCCDD11223344AABBCCDD11223344");
        byte[] serverSig = fromHex("DEADBEEFCAFEBABE");
        byte[] ciPKId = fromHex("01020304");
        byte[] authApdu = buildAuthServerApdu(txId, challenge, serverAddress, serverChallenge, serverSig, ciPKId);
        ApduResult authRes = transmit(sim, authApdu);

        assertEquals("Should return 9000 with error payload", 0x9000, authRes.sw);
        assertEquals((byte) 0xBF, authRes.data[0]);
        assertEquals((byte) 0x38, authRes.data[1]);
        // euiccChallengeMismatch = 6
        boolean foundErr = findBytes(authRes.data, fromHex("020106"));
        assertTrue("Session must be cleared after LoadBPP", foundErr);
    }

    @Test
    public void testLoadBppMultipleSequenceOf87Elements() {
        // Test with multiple [7] elements inside [0]
        Simulator sim = createAndSelect();

        byte[] remoteOpId = fromHex("020101");
        byte[] txIdTlv = fromHex("80040A0B0C0D");
        byte[] crt = fromHex("A603800188");

        byte[] otpk = new byte[65];
        otpk[0] = 0x04;
        for (int i = 1; i < 65; i++) otpk[i] = (byte) i;
        byte[] otpkTlv = new byte[3 + otpk.length];
        otpkTlv[0] = 0x5F; otpkTlv[1] = 0x49; otpkTlv[2] = (byte) otpk.length;
        System.arraycopy(otpk, 0, otpkTlv, 3, otpk.length);

        byte[] sign = fromHex("5F37080102030405060708");

        int bf23BodyLen = remoteOpId.length + txIdTlv.length + crt.length + otpkTlv.length + sign.length;
        byte[] bf23 = new byte[3 + bf23BodyLen];
        int p = 0;
        bf23[p++] = (byte) 0xBF; bf23[p++] = 0x23; bf23[p++] = (byte) bf23BodyLen;
        System.arraycopy(remoteOpId, 0, bf23, p, remoteOpId.length); p += remoteOpId.length;
        System.arraycopy(txIdTlv,    0, bf23, p, txIdTlv.length);    p += txIdTlv.length;
        System.arraycopy(crt,        0, bf23, p, crt.length);        p += crt.length;
        System.arraycopy(otpkTlv,    0, bf23, p, otpkTlv.length);    p += otpkTlv.length;
        System.arraycopy(sign,       0, bf23, p, sign.length);

        // A0 with two [7] elements: A0 { 87 02 AABB 87 02 CCDD }
        byte[] a0 = fromHex("A008870201028702AABB");
        byte[] a1 = fromHex("A10488020304");
        byte[] a3 = fromHex("A30486020506");

        int bf36BodyLen = bf23.length + a0.length + a1.length + a3.length;
        byte[] bf36;
        if (bf36BodyLen < 128) {
            bf36 = new byte[3 + bf36BodyLen];
            int q = 0;
            bf36[q++] = (byte) 0xBF; bf36[q++] = 0x36; bf36[q++] = (byte) bf36BodyLen;
            System.arraycopy(bf23, 0, bf36, q, bf23.length); q += bf23.length;
            System.arraycopy(a0,   0, bf36, q, a0.length);   q += a0.length;
            System.arraycopy(a1,   0, bf36, q, a1.length);   q += a1.length;
            System.arraycopy(a3,   0, bf36, q, a3.length);
        } else {
            bf36 = new byte[4 + bf36BodyLen];
            int q = 0;
            bf36[q++] = (byte) 0xBF; bf36[q++] = 0x36; bf36[q++] = (byte) 0x81; bf36[q++] = (byte) bf36BodyLen;
            System.arraycopy(bf23, 0, bf36, q, bf23.length); q += bf23.length;
            System.arraycopy(a0,   0, bf36, q, a0.length);   q += a0.length;
            System.arraycopy(a1,   0, bf36, q, a1.length);   q += a1.length;
            System.arraycopy(a3,   0, bf36, q, a3.length);
        }

        byte[] apdu = new byte[5 + bf36.length];
        apdu[0] = (byte) 0x80; apdu[1] = (byte) 0xE2; apdu[2] = 0x11; apdu[3] = 0x00;
        apdu[4] = (byte) bf36.length;
        System.arraycopy(bf36, 0, apdu, 5, bf36.length);

        ApduResult res = transmit(sim, apdu);
        assertEquals("Multiple 87 elements in A0 must succeed", 0x9000, res.sw);
    }

    // -- Negative tests ----------------------------------------------------------

    @Test
    public void testLoadBppRejectsMalformedPayload() {
        Simulator sim = createAndSelect();

        // BF36 with outer length claiming more data than provided
        ApduResult res = transmit(sim, fromHex("80E2110005BF36033000"));
        assertEquals("Malformed payload must be rejected", 0x6A80, res.sw);
    }

    @Test
    public void testLoadBppRejectsMissingInitSecureChannel() {
        Simulator sim = createAndSelect();

        // BF36 { 30 00 } — starts with a plain SEQUENCE instead of BF23
        ApduResult res = transmit(sim, fromHex("80E2110005BF36023000"));
        assertEquals("Missing BF23 must be rejected", 0x6A80, res.sw);
    }

    @Test
    public void testLoadBppRejectsWrongRemoteOpId() {
        Simulator sim = createAndSelect();

        // BF36 { BF23 { 02 01 02 ... } ... } — remoteOpId = 2 instead of 1
        // Build a minimal BF23 with remoteOpId=2
        byte[] remoteOpId = fromHex("020102"); // INTEGER 2 (wrong)
        byte[] txIdTlv = fromHex("80040A0B0C0D");
        byte[] crt = fromHex("A603800188");

        byte[] otpk = new byte[65];
        otpk[0] = 0x04;
        byte[] otpkTlv = new byte[3 + otpk.length];
        otpkTlv[0] = 0x5F; otpkTlv[1] = 0x49; otpkTlv[2] = (byte) otpk.length;

        byte[] sign = fromHex("5F37080102030405060708");

        int bf23BodyLen = remoteOpId.length + txIdTlv.length + crt.length + otpkTlv.length + sign.length;
        byte[] bf23 = new byte[3 + bf23BodyLen];
        int p = 0;
        bf23[p++] = (byte) 0xBF; bf23[p++] = 0x23; bf23[p++] = (byte) bf23BodyLen;
        System.arraycopy(remoteOpId, 0, bf23, p, remoteOpId.length); p += remoteOpId.length;
        System.arraycopy(txIdTlv,    0, bf23, p, txIdTlv.length);    p += txIdTlv.length;
        System.arraycopy(crt,        0, bf23, p, crt.length);        p += crt.length;
        System.arraycopy(otpkTlv,    0, bf23, p, otpkTlv.length);    p += otpkTlv.length;
        System.arraycopy(sign,       0, bf23, p, sign.length);

        byte[] a0 = fromHex("A00487020102");
        byte[] a1 = fromHex("A10488020304");
        byte[] a3 = fromHex("A30486020506");

        int bf36BodyLen = bf23.length + a0.length + a1.length + a3.length;
        byte[] bf36;
        if (bf36BodyLen < 128) {
            bf36 = new byte[3 + bf36BodyLen];
            int q = 0;
            bf36[q++] = (byte) 0xBF; bf36[q++] = 0x36; bf36[q++] = (byte) bf36BodyLen;
            System.arraycopy(bf23, 0, bf36, q, bf23.length); q += bf23.length;
            System.arraycopy(a0,   0, bf36, q, a0.length);   q += a0.length;
            System.arraycopy(a1,   0, bf36, q, a1.length);   q += a1.length;
            System.arraycopy(a3,   0, bf36, q, a3.length);
        } else {
            bf36 = new byte[4 + bf36BodyLen];
            int q = 0;
            bf36[q++] = (byte) 0xBF; bf36[q++] = 0x36; bf36[q++] = (byte) 0x81; bf36[q++] = (byte) bf36BodyLen;
            System.arraycopy(bf23, 0, bf36, q, bf23.length); q += bf23.length;
            System.arraycopy(a0,   0, bf36, q, a0.length);   q += a0.length;
            System.arraycopy(a1,   0, bf36, q, a1.length);   q += a1.length;
            System.arraycopy(a3,   0, bf36, q, a3.length);
        }

        byte[] apdu = new byte[5 + bf36.length];
        apdu[0] = (byte) 0x80; apdu[1] = (byte) 0xE2; apdu[2] = 0x11; apdu[3] = 0x00;
        apdu[4] = (byte) bf36.length;
        System.arraycopy(bf36, 0, apdu, 5, bf36.length);

        ApduResult res = transmit(sim, apdu);
        assertEquals("remoteOpId != 1 must be rejected", 0x6A80, res.sw);
    }

    @Test
    public void testLoadBppRejectsWrongTagInSequenceOf() {
        Simulator sim = createAndSelect();

        // Build valid BF36 but with wrong inner tag in A0 (use 88 instead of 87)
        byte[] remoteOpId = fromHex("020101");
        byte[] txIdTlv = fromHex("80040A0B0C0D");
        byte[] crt = fromHex("A603800188");

        byte[] otpk = new byte[65];
        otpk[0] = 0x04;
        byte[] otpkTlv = new byte[3 + otpk.length];
        otpkTlv[0] = 0x5F; otpkTlv[1] = 0x49; otpkTlv[2] = (byte) otpk.length;

        byte[] sign = fromHex("5F37080102030405060708");

        int bf23BodyLen = remoteOpId.length + txIdTlv.length + crt.length + otpkTlv.length + sign.length;
        byte[] bf23 = new byte[3 + bf23BodyLen];
        int p = 0;
        bf23[p++] = (byte) 0xBF; bf23[p++] = 0x23; bf23[p++] = (byte) bf23BodyLen;
        System.arraycopy(remoteOpId, 0, bf23, p, remoteOpId.length); p += remoteOpId.length;
        System.arraycopy(txIdTlv,    0, bf23, p, txIdTlv.length);    p += txIdTlv.length;
        System.arraycopy(crt,        0, bf23, p, crt.length);        p += crt.length;
        System.arraycopy(otpkTlv,    0, bf23, p, otpkTlv.length);    p += otpkTlv.length;
        System.arraycopy(sign,       0, bf23, p, sign.length);

        // A0 with WRONG inner tag 88 (should be 87)
        byte[] a0 = fromHex("A00488020102");
        byte[] a1 = fromHex("A10488020304");
        byte[] a3 = fromHex("A30486020506");

        int bf36BodyLen = bf23.length + a0.length + a1.length + a3.length;
        byte[] bf36;
        if (bf36BodyLen < 128) {
            bf36 = new byte[3 + bf36BodyLen];
            int q = 0;
            bf36[q++] = (byte) 0xBF; bf36[q++] = 0x36; bf36[q++] = (byte) bf36BodyLen;
            System.arraycopy(bf23, 0, bf36, q, bf23.length); q += bf23.length;
            System.arraycopy(a0,   0, bf36, q, a0.length);   q += a0.length;
            System.arraycopy(a1,   0, bf36, q, a1.length);   q += a1.length;
            System.arraycopy(a3,   0, bf36, q, a3.length);
        } else {
            bf36 = new byte[4 + bf36BodyLen];
            int q = 0;
            bf36[q++] = (byte) 0xBF; bf36[q++] = 0x36; bf36[q++] = (byte) 0x81; bf36[q++] = (byte) bf36BodyLen;
            System.arraycopy(bf23, 0, bf36, q, bf23.length); q += bf23.length;
            System.arraycopy(a0,   0, bf36, q, a0.length);   q += a0.length;
            System.arraycopy(a1,   0, bf36, q, a1.length);   q += a1.length;
            System.arraycopy(a3,   0, bf36, q, a3.length);
        }

        byte[] apdu = new byte[5 + bf36.length];
        apdu[0] = (byte) 0x80; apdu[1] = (byte) 0xE2; apdu[2] = 0x11; apdu[3] = 0x00;
        apdu[4] = (byte) bf36.length;
        System.arraycopy(bf36, 0, apdu, 5, bf36.length);

        ApduResult res = transmit(sim, apdu);
        assertEquals("Wrong inner tag in A0 (88 instead of 87) must be rejected", 0x6A80, res.sw);
    }

    // -- Helpers (AuthenticateServer APDU builder for session-clear test) ---------

    private static byte[] buildAuthServerApdu(byte[] txId, byte[] euiccChallenge,
                                               byte[] serverAddress, byte[] serverChallenge,
                                               byte[] serverSig, byte[] ciPKId) {
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

        byte[] sigTlv = new byte[3 + serverSig.length];
        sigTlv[0] = 0x5F; sigTlv[1] = 0x37; sigTlv[2] = (byte) serverSig.length;
        System.arraycopy(serverSig, 0, sigTlv, 3, serverSig.length);

        byte[] ciTlv = new byte[2 + ciPKId.length];
        ciTlv[0] = 0x04; ciTlv[1] = (byte) ciPKId.length;
        System.arraycopy(ciPKId, 0, ciTlv, 2, ciPKId.length);

        byte[] certTlv = new byte[]{0x30, 0x00};
        byte[] ctxTlv = new byte[]{0x30, 0x00};

        int innerLen = serverSigned1.length + sigTlv.length + ciTlv.length + certTlv.length + ctxTlv.length;
        byte[] bf38 = new byte[3 + innerLen];
        int q = 0;
        bf38[q++] = (byte) 0xBF; bf38[q++] = 0x38; bf38[q++] = (byte) innerLen;
        System.arraycopy(serverSigned1, 0, bf38, q, serverSigned1.length); q += serverSigned1.length;
        System.arraycopy(sigTlv,        0, bf38, q, sigTlv.length);        q += sigTlv.length;
        System.arraycopy(ciTlv,         0, bf38, q, ciTlv.length);         q += ciTlv.length;
        System.arraycopy(certTlv,       0, bf38, q, certTlv.length);       q += certTlv.length;
        System.arraycopy(ctxTlv,        0, bf38, q, ctxTlv.length);

        byte[] apdu = new byte[5 + bf38.length];
        apdu[0] = (byte) 0x80; apdu[1] = (byte) 0xE2; apdu[2] = 0x11; apdu[3] = 0x00;
        apdu[4] = (byte) bf38.length;
        System.arraycopy(bf38, 0, apdu, 5, bf38.length);
        return apdu;
    }

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
