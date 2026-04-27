import com.licel.jcardsim.base.Simulator;
import javacard.framework.AID;
import org.junit.Test;
import zk.esim.applet.ZkEsimApplet;

import java.io.ByteArrayOutputStream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * jCardSim integration tests for ZKProfileRequest (BF42).
 *
 * The eUICC SHALL:
 *  - Require Phase 0 (BF44→BF45→BF46→BF47) to have completed before accepting BF42.
 *  - Accept a BF42 APDU carrying a 16-byte MNO challenge (mnoChallenge).
 *  - Compute pid = SHA256(SHA256(SK_B_SEED || mnoChallenge) || EID).
 *  - Compute EncEid = ECIES(pk_LEA, EID).
 *  - Compute a Schnorr proof π_req over the 356-byte ZKStatement (includes H(σ_EID)).
 *  - Return BF42 { A0 { 30 { ZKStatement | PCert_U | 5F37 π_req } } }.
 *  - Reject without Phase 0 with BF42 { A1 { 02 01 02 } } (certInitRequired).
 *  - Reject malformed challenges (wrong length) with BF42 { A1 { 02 01 01 } }.
 */
public class ZkEsimAppletZKProfileRequestTest {

    private static final byte[] APPLET_AID = fromHex("D07002CA44900101");

    // -----------------------------------------------------------------------
    // Infrastructure
    // -----------------------------------------------------------------------

    private static final class ApduResult {
        final byte[] data;
        final int sw;

        ApduResult(byte[] response) {
            assertTrue("Response must have at least SW1SW2", response.length >= 2);
            sw = ((response[response.length - 2] & 0xFF) << 8) | (response[response.length - 1] & 0xFF);
            data = new byte[response.length - 2];
            System.arraycopy(response, 0, data, 0, data.length);
        }
    }

    private static byte[] fromHex(String hex) {
        int len = hex.length();
        if ((len & 1) != 0) throw new IllegalArgumentException("Odd hex length");
        byte[] out = new byte[len / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(hex.charAt(i * 2), 16);
            int lo = Character.digit(hex.charAt(i * 2 + 1), 16);
            if (hi < 0 || lo < 0) throw new IllegalArgumentException("Bad hex char");
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    private static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte v : b) sb.append(String.format("%02X", v));
        return sb.toString();
    }

    private static ApduResult transmit(Simulator sim, byte[] apdu) {
        ByteArrayOutputStream allData = new ByteArrayOutputStream();
        byte[] resp;
        if (apdu.length >= 7 && apdu[1] == (byte) 0xE2 && apdu[4] == 0x00) {
            resp = transmitStoreDataChained(sim, apdu);
        } else {
            resp = sim.transmitCommand(apdu);
        }
        assertTrue("Response length >= 2", resp.length >= 2);
        int sw = ((resp[resp.length - 2] & 0xFF) << 8) | (resp[resp.length - 1] & 0xFF);
        allData.write(resp, 0, resp.length - 2);
        while ((sw & 0xFF00) == 0x9100) {
            byte[] getResp = new byte[]{0x00, (byte) 0xC0, 0x00, 0x00, 0x00};
            resp = sim.transmitCommand(getResp);
            assertTrue("GET RESPONSE >= 2", resp.length >= 2);
            sw = ((resp[resp.length - 2] & 0xFF) << 8) | (resp[resp.length - 1] & 0xFF);
            allData.write(resp, 0, resp.length - 2);
        }
        byte[] full = allData.toByteArray();
        byte[] combined = new byte[full.length + 2];
        System.arraycopy(full, 0, combined, 0, full.length);
        combined[combined.length - 2] = (byte) (sw >> 8);
        combined[combined.length - 1] = (byte) sw;
        System.out.println("[BF42 test] TX: " + toHex(apdu));
        System.out.println("[BF42 test] RX: " + toHex(combined) + " SW=" + String.format("%04X", sw));
        return new ApduResult(combined);
    }

    private static byte[] transmitStoreDataChained(Simulator sim, byte[] command) {
        int dataLen = ((command[5] & 0xFF) << 8) | (command[6] & 0xFF);
        int dataOff = 7;
        int blockNo = 0, pos = dataOff;
        byte[] response = null;
        final int MAX_CHUNK = 240;
        while (pos < dataOff + dataLen) {
            int remaining = (dataOff + dataLen) - pos;
            int chunkLen = Math.min(MAX_CHUNK, remaining);
            boolean last = (pos + chunkLen) == (dataOff + dataLen);
            byte[] chunk = new byte[5 + chunkLen];
            chunk[0] = command[0];
            chunk[1] = command[1];
            chunk[2] = last ? (byte) 0x91 : (byte) 0x11;
            chunk[3] = (byte) (blockNo & 0xFF);
            chunk[4] = (byte) chunkLen;
            System.arraycopy(command, pos, chunk, 5, chunkLen);
            response = sim.transmitCommand(chunk);
            pos += chunkLen;
            blockNo++;
        }
        if (response == null) throw new IllegalStateException("No APDU blocks transmitted");
        return response;
    }

    /** Wrap data in an 80 E2 91/11 xx Lc … STORE DATA APDU. */
    private static byte[] buildStoreDataApdu(byte[] data) {
        if (data.length <= 255) {
            byte[] apdu = new byte[5 + data.length];
            apdu[0] = (byte) 0x80;
            apdu[1] = (byte) 0xE2;
            apdu[2] = (byte) 0x91;
            apdu[3] = 0x00;
            apdu[4] = (byte) data.length;
            System.arraycopy(data, 0, apdu, 5, data.length);
            return apdu;
        }
        byte[] apdu = new byte[7 + data.length];
        apdu[0] = (byte) 0x80;
        apdu[1] = (byte) 0xE2;
        apdu[2] = (byte) 0x91;
        apdu[3] = 0x00;
        apdu[4] = 0x00;
        apdu[5] = (byte) ((data.length >> 8) & 0xFF);
        apdu[6] = (byte) (data.length & 0xFF);
        System.arraycopy(data, 0, apdu, 7, data.length);
        return apdu;
    }

    /** Build BF42 { 80 10 <challenge> } request TLV (21 bytes). */
    private static byte[] buildBF42Request(byte[] challenge) {
        assertEquals("challenge must be 16 bytes", 16, challenge.length);
        // BF 42 12  80 10 <16B>
        byte[] tlv = new byte[21];
        tlv[0] = (byte) 0xBF;
        tlv[1] = 0x42;
        tlv[2] = 0x12; // value = 2 + 16 = 18
        tlv[3] = (byte) 0x80;
        tlv[4] = 0x10;
        System.arraycopy(challenge, 0, tlv, 5, 16);
        return tlv;
    }

    private static Simulator freshApplet() {
        Simulator sim = new Simulator();
        AID aid = new AID(APPLET_AID, (short) 0, (byte) APPLET_AID.length);
        sim.installApplet(aid, ZkEsimApplet.class);
        assertTrue("Applet selectable", sim.selectApplet(aid));
        return sim;
    }

    private static void reselectApplet(Simulator sim) {
        AID aid = new AID(APPLET_AID, (short) 0, (byte) APPLET_AID.length);
        assertTrue("Applet reselectable", sim.selectApplet(aid));
    }

    /**
     * Drive the applet through Phase 0 (BF44→BF45→BF46→BF47) using stub inputs.
     * This sets hasPhase0aCredential and hasSessionKey, enabling BF42.
     *
     * BF44 input: R_MNO = P-256 generator G (any valid point works).
     * BF45 input: s = 32 zero bytes (unblinding always succeeds; σ_EID may be invalid
     *             as a Schnorr sig, but BF42 only needs hasPhase0aCredential = true).
     * BF46 input: r_seed = 32 zero bytes (deterministic sk_U).
     * BF47 input: 3-byte placeholder cert (applet just stores the bytes).
     */
    private static void runPhase0Setup(Simulator sim) {
        // P-256 generator G (uncompressed, 65 bytes)
        byte[] G = fromHex(
            "04" +
            "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296" +
            "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"
        );

        // BF44 { 80 41 G }
        byte[] bf44 = new byte[3 + 2 + G.length];
        bf44[0] = (byte) 0xBF; bf44[1] = 0x44; bf44[2] = (byte) (2 + G.length);
        bf44[3] = (byte) 0x80; bf44[4] = (byte) G.length;
        System.arraycopy(G, 0, bf44, 5, G.length);
        ApduResult r44 = transmit(sim, buildStoreDataApdu(bf44));
        assertEquals("Phase 0.a BF44 SW", 0x9000, r44.sw);
        assertEquals("Phase 0.a BF44 outer tag[0]", (byte) 0xBF, r44.data[0]);
        assertEquals("Phase 0.a BF44 outer tag[1]", (byte) 0x44, r44.data[1]);

        // BF45 { 80 20 <32 zero bytes> }
        byte[] bf45 = new byte[3 + 2 + 32];
        bf45[0] = (byte) 0xBF; bf45[1] = 0x45; bf45[2] = (byte) (2 + 32);
        bf45[3] = (byte) 0x80; bf45[4] = 0x20;
        ApduResult r45 = transmit(sim, buildStoreDataApdu(bf45));
        assertEquals("Phase 0.a BF45 SW", 0x9000, r45.sw);
        assertEquals("Phase 0.a BF45 outer tag[1]", (byte) 0x45, r45.data[1]);
        reselectApplet(sim);

        // BF46 { 80 20 <32 zero bytes> }
        byte[] bf46 = new byte[3 + 2 + 32];
        bf46[0] = (byte) 0xBF; bf46[1] = 0x46; bf46[2] = (byte) (2 + 32);
        bf46[3] = (byte) 0x80; bf46[4] = 0x20;
        ApduResult r46 = transmit(sim, buildStoreDataApdu(bf46));
        assertEquals("Phase 0.b BF46 SW", 0x9000, r46.sw);
        assertEquals("Phase 0.b BF46 outer tag[1]", (byte) 0x46, r46.data[1]);

        // BF47 { 80 03 30 01 00 }  — placeholder cert (applet just stores the bytes)
        byte[] cert = fromHex("300100");
        byte[] bf47 = new byte[3 + 2 + cert.length];
        bf47[0] = (byte) 0xBF; bf47[1] = 0x47; bf47[2] = (byte) (2 + cert.length);
        bf47[3] = (byte) 0x80; bf47[4] = (byte) cert.length;
        System.arraycopy(cert, 0, bf47, 5, cert.length);
        ApduResult r47 = transmit(sim, buildStoreDataApdu(bf47));
        assertEquals("Phase 0.b BF47 SW", 0x9000, r47.sw);
        assertEquals("Phase 0.b BF47 outer tag[1]", (byte) 0x47, r47.data[1]);
        reselectApplet(sim);
    }

    // -----------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------

    /**
     * Happy path: after Phase 0 setup, send a 16-byte MNO challenge.
     * Expects BF42 { A0 { 30 { ZKStatement(fields 80–86) | PCert_U | 5F37 π_req(97B) } } }.
     */
    @Test
    public void testZKProfileRequest_happyPath() {
        Simulator sim = freshApplet();
        runPhase0Setup(sim);
        byte[] challenge = new byte[16];
        for (int i = 0; i < 16; i++) challenge[i] = (byte) (0x11 + i);

        byte[] req = buildBF42Request(challenge);
        ApduResult res = transmit(sim, buildStoreDataApdu(req));

        assertEquals("SW must be 9000", 0x9000, res.sw);
        assertTrue("Response must be non-empty", res.data.length > 5);

        // Check outer tag: BF 42
        assertEquals("Outer tag byte 0 must be BF", (byte) 0xBF, res.data[0]);
        assertEquals("Outer tag byte 1 must be 42", (byte) 0x42, res.data[1]);

        // Locate value start (skip outer length field)
        int outerLenOff = 2;
        int outerLenSize = derLenFieldSize(res.data, outerLenOff);
        int outerValOff = outerLenOff + outerLenSize;

        // First byte of value must be A0 (success CHOICE)
        assertEquals("First inner tag must be A0 (success)", (byte) 0xA0, res.data[outerValOff]);

        // Locate A0 value
        int a0LenOff = outerValOff + 1;
        int a0LenSize = derLenFieldSize(res.data, a0LenOff);
        int a0ValOff = a0LenOff + a0LenSize;

        // A0 value must start with 30 (SEQUENCE for ZKProfileResponseOk)
        assertEquals("A0 value must start with 30", 0x30, res.data[a0ValOff] & 0xFF);

        // Find the 5F37 proof tag inside the response
        int proofIdx = findTag(res.data, a0ValOff, res.data.length - a0ValOff, (byte) 0x5F, (byte) 0x37);
        assertTrue("5F37 (zkProof) tag must be present", proofIdx >= 0);

        // Proof length: R(65) + s(32) = 97 bytes
        int proofLenOff = proofIdx + 2;
        int proofLen = res.data[proofLenOff] & 0xFF;
        assertEquals("Schnorr proof must be 97 bytes", 97, proofLen);
    }

    @Test
    public void testPhase0CanRunAgainOnSameApplet() {
        Simulator sim = freshApplet();
        runPhase0Setup(sim);
        runPhase0Setup(sim);

        byte[] challenge = new byte[16];
        for (int i = 0; i < 16; i++) challenge[i] = (byte) (0x21 + i);
        ApduResult res = transmit(sim, buildStoreDataApdu(buildBF42Request(challenge)));
        assertEquals("SW must be 9000 after repeated Phase 0", 0x9000, res.sw);
        assertEquals("Outer tag byte 0 must be BF", (byte) 0xBF, res.data[0]);
        assertEquals("Outer tag byte 1 must be 42", (byte) 0x42, res.data[1]);
    }

    /**
     * Different challenge value: verifying the applet produces a fresh response
     * (pid and proof change per challenge).  Both simulators go through Phase 0.
     */
    @Test
    public void testZKProfileRequest_differentChallenge() {
        Simulator sim = freshApplet();
        runPhase0Setup(sim);

        byte[] challenge1 = new byte[16];
        byte[] challenge2 = new byte[16];
        for (int i = 0; i < 16; i++) {
            challenge1[i] = (byte) i;
            challenge2[i] = (byte) (0xFF - i);
        }

        ApduResult res1 = transmit(sim, buildStoreDataApdu(buildBF42Request(challenge1)));
        assertEquals(0x9000, res1.sw);

        Simulator sim2 = freshApplet();
        runPhase0Setup(sim2);
        ApduResult res2 = transmit(sim2, buildStoreDataApdu(buildBF42Request(challenge2)));
        assertEquals(0x9000, res2.sw);

        // The two responses must differ (different pid / proof)
        assertTrue("Responses for different challenges must differ", !java.util.Arrays.equals(res1.data, res2.data));
    }

    /**
     * Malformed: challenge shorter than 16 bytes → BF42 { A1 { 02 01 01 } } (invalidChallenge).
     */
    @Test
    public void testZKProfileRequest_shortChallenge() {
        Simulator sim = freshApplet();

        // Build BF42 { 80 08 <8B> } — wrong challenge length
        byte[] req = new byte[]{
            (byte) 0xBF, 0x42, 0x0A,   // BF42, value len = 10
            (byte) 0x80, 0x08,          // tag 80, len 8
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
        };
        ApduResult res = transmit(sim, buildStoreDataApdu(req));
        assertEquals("SW must be 9000", 0x9000, res.sw);

        assertEquals("Error tag byte 0 must be BF", (byte) 0xBF, res.data[0]);
        assertEquals("Error tag byte 1 must be 42", (byte) 0x42, res.data[1]);

        // Locate inner tag — must be A1 (error CHOICE)
        int outerLenOff = 2;
        int outerLenSize = derLenFieldSize(res.data, outerLenOff);
        int outerValOff = outerLenOff + outerLenSize;
        assertEquals("Error CHOICE must be A1", (byte) 0xA1, res.data[outerValOff]);
    }

    /**
     * Malformed: challenge longer than 16 bytes → error response.
     */
    @Test
    public void testZKProfileRequest_longChallenge() {
        Simulator sim = freshApplet();

        byte[] req = new byte[]{
            (byte) 0xBF, 0x42, 0x14,   // BF42, value len = 20
            (byte) 0x80, 0x12,          // tag 80, len 18 (> 16)
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x11, 0x12
        };
        ApduResult res = transmit(sim, buildStoreDataApdu(req));
        assertEquals("SW must be 9000", 0x9000, res.sw);

        assertEquals("Error outer tag[0] must be BF", (byte) 0xBF, res.data[0]);
        assertEquals("Error outer tag[1] must be 42", (byte) 0x42, res.data[1]);
        int outerValOff = 2 + derLenFieldSize(res.data, 2);
        assertEquals("Error CHOICE must be A1", (byte) 0xA1, res.data[outerValOff]);
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /** Number of bytes used to encode DER length field starting at data[off]. */
    private static int derLenFieldSize(byte[] data, int off) {
        int b = data[off] & 0xFF;
        if ((b & 0x80) == 0) return 1;
        return 1 + (b & 0x7F);
    }

    /**
     * Scan data[start..start+len) for a two-byte tag (t0, t1).
     * Returns the index of t0 if found, or -1.
     */
    private static int findTag(byte[] data, int start, int len, byte t0, byte t1) {
        for (int i = start; i < start + len - 1; i++) {
            if (data[i] == t0 && data[i + 1] == t1) return i;
        }
        return -1;
    }
}
