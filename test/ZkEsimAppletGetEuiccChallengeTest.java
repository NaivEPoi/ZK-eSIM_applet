import com.licel.jcardsim.base.Simulator;
import javacard.framework.AID;
import org.junit.Test;
import zk.esim.applet.ZkEsimApplet;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class ZkEsimAppletGetEuiccChallengeTest {

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

    @Test
    public void testGetEuiccChallengeStoreData() {
        Simulator sim = new Simulator();
        AID aid = new AID(APPLET_AID, (short) 0, (byte) APPLET_AID.length);
        sim.installApplet(aid, ZkEsimApplet.class);
        assertTrue("Applet must be selectable", sim.selectApplet(aid));

        // STORE DATA with GetEuiccChallengeRequest = BF2E { 30 00 }
        ApduResult res = transmit(sim, fromHex("80E2110005BF2E023000"));
        ApduResult res2 = transmit(sim, fromHex("80E2110005BF2E023000"));

        assertEquals(0x9000, res.sw);
        assertEquals(0x9000, res2.sw);
        assertTrue("Expected BF2E response", res.data.length >= 23);
        assertTrue("Expected BF2E response", res2.data.length >= 23);
        assertEquals((byte) 0xBF, res.data[0]);
        assertEquals((byte) 0x2E, res.data[1]);
        assertEquals((byte) 0x14, res.data[2]);
        assertEquals((byte) 0x30, res.data[3]);
        assertEquals((byte) 0x12, res.data[4]);
        assertEquals((byte) 0x04, res.data[5]);
        assertEquals((byte) 0x10, res.data[6]);

        assertEquals((byte) 0xBF, res2.data[0]);
        assertEquals((byte) 0x2E, res2.data[1]);
        assertEquals((byte) 0x14, res2.data[2]);
        assertEquals((byte) 0x30, res2.data[3]);
        assertEquals((byte) 0x12, res2.data[4]);
        assertEquals((byte) 0x04, res2.data[5]);
        assertEquals((byte) 0x10, res2.data[6]);
    }

    @Test
    public void testGetEuiccChallengeRejectsMalformedPayload() {
        Simulator sim = new Simulator();
        AID aid = new AID(APPLET_AID, (short) 0, (byte) APPLET_AID.length);
        sim.installApplet(aid, ZkEsimApplet.class);
        assertTrue("Applet must be selectable", sim.selectApplet(aid));

        // Malformed BF2E: outer length claims more data than provided.
        ApduResult res = transmit(sim, fromHex("80E2110005BF2E033000"));
        assertEquals(0x6A80, res.sw);
    }
}
