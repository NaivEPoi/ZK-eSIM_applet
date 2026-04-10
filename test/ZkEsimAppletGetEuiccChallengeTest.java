import com.licel.jcardsim.base.Simulator;
import javacard.framework.AID;
import org.junit.Test;
import zk.esim.applet.ZkEsimApplet;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class ZkEsimAppletGetEuiccChallengeTest {

    private static final byte[] APPLET_AID = fromHex("D07002CA44900101");

    // GetEuiccChallengeRequest = BF2E with empty body (lpac/es10b helper format)
    private static final byte[] CMD_GET_EUICC_CHALLENGE = fromHex("80E2910003BF2E00");

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

    private static Simulator installAndSelect() {
        Simulator sim = new Simulator();
        AID aid = new AID(APPLET_AID, (short) 0, (byte) APPLET_AID.length);
        sim.installApplet(aid, ZkEsimApplet.class);
        assertTrue("Applet must be selectable", sim.selectApplet(aid));
        return sim;
    }

    /** Extracts the 16-byte euiccChallenge value from a well-formed GetEuiccChallengeResponse. */
    private static byte[] extractChallenge(byte[] data) {
        // Response layout: BF 2E 12 80 10 [16 bytes]
        assertEquals("Response must be exactly 21 bytes", 21, data.length);
        byte[] challenge = new byte[16];
        System.arraycopy(data, 5, challenge, 0, 16);
        return challenge;
    }

    private static boolean isAllZero(byte[] b) {
        for (byte v : b) {
            if (v != 0) return false;
        }
        return true;
    }

    // -------------------------------------------------------------------------
    // Success-path structure
    // -------------------------------------------------------------------------

    @Test
    public void testGetEuiccChallengeStoreData() {
        Simulator sim = installAndSelect();

        ApduResult res = transmit(sim, CMD_GET_EUICC_CHALLENGE);
        ApduResult res2 = transmit(sim, CMD_GET_EUICC_CHALLENGE);

        assertEquals(0x9000, res.sw);
        assertEquals(0x9000, res2.sw);
        assertTrue("Expected BF2E response", res.data.length >= 21);
        assertTrue("Expected BF2E response", res2.data.length >= 21);
        assertEquals((byte) 0xBF, res.data[0]);
        assertEquals(0x2E, res.data[1]);
        assertEquals(0x12, res.data[2]);  // outer value length = 18
        assertEquals((byte) 0x80, res.data[3]);  // context tag for challenge
        assertEquals(0x10, res.data[4]);  // challenge length = 16

        assertEquals((byte) 0xBF, res2.data[0]);
        assertEquals(0x2E, res2.data[1]);
        assertEquals(0x12, res2.data[2]);
        assertEquals((byte) 0x80, res2.data[3]);
        assertEquals(0x10, res2.data[4]);
    }

    @Test
    public void testGetEuiccChallengeContainsNonZeroRandomBytes() {
        Simulator sim = installAndSelect();

        ApduResult res = transmit(sim, CMD_GET_EUICC_CHALLENGE);

        assertEquals("GetEuiccChallenge must succeed", 0x9000, res.sw);
        byte[] challenge = extractChallenge(res.data);
        assertFalse("euiccChallenge must not be all zeros (RNG must be working)", isAllZero(challenge));
    }

    @Test
    public void testGetEuiccChallengesAreDifferentOnRepeat() {
        Simulator sim = installAndSelect();

        ApduResult res1 = transmit(sim, CMD_GET_EUICC_CHALLENGE);
        ApduResult res2 = transmit(sim, CMD_GET_EUICC_CHALLENGE);

        assertEquals("First GetEuiccChallenge must succeed",  0x9000, res1.sw);
        assertEquals("Second GetEuiccChallenge must succeed", 0x9000, res2.sw);

        byte[] c1 = extractChallenge(res1.data);
        byte[] c2 = extractChallenge(res2.data);

        boolean same = true;
        for (int i = 0; i < 16; i++) {
            if (c1[i] != c2[i]) { same = false; break; }
        }
        assertFalse("Sequential euiccChallenge values must differ (challenge must be fresh each call)", same);
    }

    // -------------------------------------------------------------------------
    // ASN.1 decoder edge cases
    // -------------------------------------------------------------------------

    @Test
    public void testGetEuiccChallengeRejectsMalformedPayload() {
        Simulator sim = installAndSelect();

        // BF2E 03 30 00: outer length claims 3 bytes but value is only 2 bytes long
        ApduResult res = transmit(sim, fromHex("80E2910005BF2E033000"));
        assertEquals(0x6A80, res.sw);
    }

    @Test
    public void testGetEuiccChallengeAcceptsEmptyBody() {
        Simulator sim = installAndSelect();

        // BF2E 00: accepted in lpac/es10b format.
        ApduResult res = transmit(sim, CMD_GET_EUICC_CHALLENGE);
        assertEquals(0x9000, res.sw);
    }

    @Test
    public void testGetEuiccChallengeRejectsNonEmptyInnerSequence() {
        Simulator sim = installAndSelect();

        // BF2E 04 30 02 00 00: inner SEQUENCE has value length 2, not 0 — must be rejected
        ApduResult res = transmit(sim, fromHex("80E291000 7BF2E0430020000".replace(" ", "")));
        assertEquals(0x6A80, res.sw);
    }

    @Test
    public void testGetEuiccChallengeRejectsWrongInnerTag() {
        Simulator sim = installAndSelect();

        // BF2E 02 04 00: inner element is OCTET STRING (04), not SEQUENCE (30) — must be rejected
        ApduResult res = transmit(sim, fromHex("80E2910005BF2E020400"));
        assertEquals(0x6A80, res.sw);
    }

    @Test
    public void testGetEuiccChallengeRejectsNonCanonicalLength() {
        Simulator sim = installAndSelect();

        // Non-canonical DER: length 0 encoded in long form (81 00) instead of 00.
        ApduResult res = transmit(sim, fromHex("80E2910004BF2E8100"));
        assertEquals(0x6A80, res.sw);
    }

    // -------------------------------------------------------------------------
    // Transport-level rejection
    // -------------------------------------------------------------------------

    @Test
    public void testGetEuiccChallengeRejectsNonTransportCla() {
        Simulator sim = installAndSelect();

        // CLA=0x00 is not in the ES10x transport range (0x80-0x83 or 0xC0-0xCF)
        ApduResult res = transmit(sim, fromHex("00E2910003BF2E00"));
        assertEquals("Non-transport CLA must return 6E00", 0x6E00, res.sw);
    }
}
