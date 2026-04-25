import com.licel.jcardsim.base.Simulator;
import javacard.framework.AID;
import org.junit.Test;
import zk.esim.applet.ZkEsimApplet;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * jCardSim integration tests for SetEligibilityDataRequest (BF43).
 *
 * The eUICC SHALL:
 *  - Accept a BF43 APDU carrying an EligibilityData SEQUENCE with fields:
 *      80 hpid(32B), 81 sigCred(≤64B), 82 authToken(≤64B),
 *      83 accRoot(32B), 84 sigRoot(≤64B), 85 accProof(variable).
 *  - Return BF43 { A0 00 } on success.
 *  - Reject malformed input (wrong field length, unknown tag) with BF43 { A1 { 02 01 01 } }.
 */
public class ZkEsimAppletSetEligibilityDataTest {

    private static final byte[] APPLET_AID = fromHex("D07002CA44900101");

    // -----------------------------------------------------------------------
    // Infrastructure (shared with ZkEsimAppletZKProfileRequestTest)
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
        System.out.println("[BF43 test] TX: " + toHex(apdu));
        System.out.println("[BF43 test] RX: " + toHex(combined) + " SW=" + String.format("%04X", sw));
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

    /**
     * Build BF43 { 30 { 80(hpid) 81(sigCred) 82(authTok) 83(accRoot) 84(sigRoot) 85(piInc) } }.
     * Any field may be null to omit it (for malformed-input tests).
     */
    private static byte[] buildBF43Request(byte[] hpid, byte[] sigCred, byte[] authTok,
                                            byte[] accRoot, byte[] sigRoot, byte[] piInc) {
        try {
            ByteArrayOutputStream inner = new ByteArrayOutputStream();
            if (hpid    != null) appendTlv(inner, (byte) 0x80, hpid);
            if (sigCred != null) appendTlv(inner, (byte) 0x81, sigCred);
            if (authTok != null) appendTlv(inner, (byte) 0x82, authTok);
            if (accRoot != null) appendTlv(inner, (byte) 0x83, accRoot);
            if (sigRoot != null) appendTlv(inner, (byte) 0x84, sigRoot);
            if (piInc   != null) appendTlv(inner, (byte) 0x85, piInc);

            byte[] innerBytes = inner.toByteArray();

            ByteArrayOutputStream seq = new ByteArrayOutputStream();
            seq.write(0x30);
            writeDerLen(seq, innerBytes.length);
            seq.write(innerBytes);
            byte[] seqBytes = seq.toByteArray();

            ByteArrayOutputStream bf43 = new ByteArrayOutputStream();
            bf43.write(0xBF);
            bf43.write(0x43);
            writeDerLen(bf43, seqBytes.length);
            bf43.write(seqBytes);
            return bf43.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static void appendTlv(ByteArrayOutputStream out, byte tag, byte[] value) throws IOException {
        out.write(tag & 0xFF);
        writeDerLen(out, value.length);
        out.write(value);
    }

    private static void writeDerLen(ByteArrayOutputStream out, int len) throws IOException {
        if (len <= 127) {
            out.write(len);
        } else if (len <= 255) {
            out.write(0x81);
            out.write(len);
        } else {
            out.write(0x82);
            out.write((len >> 8) & 0xFF);
            out.write(len & 0xFF);
        }
    }

    private static Simulator freshApplet() {
        Simulator sim = new Simulator();
        AID aid = new AID(APPLET_AID, (short) 0, (byte) APPLET_AID.length);
        sim.installApplet(aid, ZkEsimApplet.class);
        assertTrue("Applet selectable", sim.selectApplet(aid));
        return sim;
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private static int derLenFieldSize(byte[] data, int off) {
        int b = data[off] & 0xFF;
        if ((b & 0x80) == 0) return 1;
        return 1 + (b & 0x7F);
    }

    private static byte[] bytes(int count, byte fill) {
        byte[] b = new byte[count];
        for (int i = 0; i < count; i++) b[i] = fill;
        return b;
    }

    // -----------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------

    /**
     * Happy path: all six fields at their nominal lengths.
     * Expects BF43 { A0 00 } — success response (5 bytes).
     */
    @Test
    public void testSetEligibilityData_happyPath() {
        Simulator sim = freshApplet();

        byte[] hpid    = bytes(32, (byte) 0xAA);
        byte[] sigCred = bytes(64, (byte) 0xBB);
        byte[] authTok = bytes(64, (byte) 0xCC);
        byte[] accRoot = bytes(32, (byte) 0xDD);
        byte[] sigRoot = bytes(64, (byte) 0xEE);
        byte[] piInc   = new byte[0];

        byte[] req = buildBF43Request(hpid, sigCred, authTok, accRoot, sigRoot, piInc);
        ApduResult res = transmit(sim, buildStoreDataApdu(req));

        assertEquals("SW must be 9000", 0x9000, res.sw);
        assertTrue("Response must be non-empty", res.data.length >= 5);

        assertEquals("Outer tag[0] must be BF", (byte) 0xBF, res.data[0]);
        assertEquals("Outer tag[1] must be 43", (byte) 0x43, res.data[1]);

        int outerLenOff = 2;
        int outerLenSize = derLenFieldSize(res.data, outerLenOff);
        int outerValOff = outerLenOff + outerLenSize;

        assertEquals("Inner tag must be A0 (success)", (byte) 0xA0, res.data[outerValOff]);
        assertEquals("A0 length must be 00", (byte) 0x00, res.data[outerValOff + 1]);
    }

    /**
     * Malformed: hpid is 16 bytes (not 32) → BF43 { A1 { ... } } error.
     */
    @Test
    public void testSetEligibilityData_wrongHpidLength() {
        Simulator sim = freshApplet();

        byte[] hpid    = bytes(16, (byte) 0x11); // wrong: must be 32
        byte[] sigCred = bytes(64, (byte) 0xBB);
        byte[] authTok = bytes(64, (byte) 0xCC);
        byte[] accRoot = bytes(32, (byte) 0xDD);
        byte[] sigRoot = bytes(64, (byte) 0xEE);
        byte[] piInc   = new byte[0];

        byte[] req = buildBF43Request(hpid, sigCred, authTok, accRoot, sigRoot, piInc);
        ApduResult res = transmit(sim, buildStoreDataApdu(req));

        assertEquals("SW must be 9000", 0x9000, res.sw);
        assertEquals("Outer tag[0] must be BF", (byte) 0xBF, res.data[0]);
        assertEquals("Outer tag[1] must be 43", (byte) 0x43, res.data[1]);

        int outerValOff = 2 + derLenFieldSize(res.data, 2);
        assertEquals("Error CHOICE must be A1", (byte) 0xA1, res.data[outerValOff]);
    }

    /**
     * Malformed: accRoot is 16 bytes (not 32) → BF43 { A1 { ... } } error.
     */
    @Test
    public void testSetEligibilityData_wrongAccRootLength() {
        Simulator sim = freshApplet();

        byte[] hpid    = bytes(32, (byte) 0xAA);
        byte[] sigCred = bytes(64, (byte) 0xBB);
        byte[] authTok = bytes(64, (byte) 0xCC);
        byte[] accRoot = bytes(16, (byte) 0x22); // wrong: must be 32
        byte[] sigRoot = bytes(64, (byte) 0xEE);
        byte[] piInc   = new byte[0];

        byte[] req = buildBF43Request(hpid, sigCred, authTok, accRoot, sigRoot, piInc);
        ApduResult res = transmit(sim, buildStoreDataApdu(req));

        assertEquals("SW must be 9000", 0x9000, res.sw);
        assertEquals("Outer tag[0] must be BF", (byte) 0xBF, res.data[0]);
        assertEquals("Outer tag[1] must be 43", (byte) 0x43, res.data[1]);

        int outerValOff = 2 + derLenFieldSize(res.data, 2);
        assertEquals("Error CHOICE must be A1", (byte) 0xA1, res.data[outerValOff]);
    }

    /**
     * Happy path with non-empty accProof: verify the response is still success.
     * The applet stores accProof without validating its content.
     */
    @Test
    public void testSetEligibilityData_withAccProof() {
        Simulator sim = freshApplet();

        byte[] hpid    = bytes(32, (byte) 0xAA);
        byte[] sigCred = bytes(64, (byte) 0xBB);
        byte[] authTok = bytes(64, (byte) 0xCC);
        byte[] accRoot = bytes(32, (byte) 0xDD);
        byte[] sigRoot = bytes(64, (byte) 0xEE);
        // Merkle proof: two 32-byte sibling hashes
        byte[] piInc   = bytes(64, (byte) 0x55);

        byte[] req = buildBF43Request(hpid, sigCred, authTok, accRoot, sigRoot, piInc);
        ApduResult res = transmit(sim, buildStoreDataApdu(req));

        assertEquals("SW must be 9000", 0x9000, res.sw);
        assertEquals("Outer tag[0] must be BF", (byte) 0xBF, res.data[0]);
        assertEquals("Outer tag[1] must be 43", (byte) 0x43, res.data[1]);

        int outerValOff = 2 + derLenFieldSize(res.data, 2);
        assertEquals("Inner tag must be A0 (success)", (byte) 0xA0, res.data[outerValOff]);
    }
}
