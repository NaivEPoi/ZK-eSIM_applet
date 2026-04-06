import com.licel.jcardsim.base.Simulator;
import javacard.framework.AID;
import org.junit.Test;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import zk.esim.applet.ZkEsimApplet;

import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class ZkEsimAppletGetEuiccChallengeTest {

    private static final byte[] APPLET_AID = fromHex("D07002CA44900101");

    private static final class ApduResult {
        final ResponseAPDU response;
        final byte[] data;
        final int sw;

        ApduResult(ResponseAPDU response) {
            this.response = response;
            this.data = response.getData();
            this.sw = response.getSW();
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

    private static ApduResult transmit(Simulator sim, CommandAPDU command) {
        byte[] responseBytes = sim.transmitCommand(command.getBytes());
        assertTrue("Response APDU must include SW1SW2", responseBytes.length >= 2);
        ResponseAPDU response = new ResponseAPDU(responseBytes);
        System.out.println("APDU TX: " + toHex(command.getBytes()));
        System.out.println("APDU RX: " + toHex(responseBytes) + " SW=" + String.format("%04X", response.getSW()));
        return new ApduResult(response);
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
        ApduResult res = transmit(sim, new CommandAPDU(fromHex("80E2110005BF2E023000")));
        ApduResult res2 = transmit(sim, new CommandAPDU(fromHex("80E2110005BF2E023000")));

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

        byte[] challenge1 = new byte[16];
        byte[] challenge2 = new byte[16];
        System.arraycopy(res.data, 7, challenge1, 0, 16);
        System.arraycopy(res2.data, 7, challenge2, 0, 16);

        assertTrue("Consecutive challenges should differ", !Arrays.equals(challenge1, challenge2));
    }

    @Test
    public void testGetEuiccChallengeRejectsMalformedPayload() {
        Simulator sim = new Simulator();
        AID aid = new AID(APPLET_AID, (short) 0, (byte) APPLET_AID.length);
        sim.installApplet(aid, ZkEsimApplet.class);
        assertTrue("Applet must be selectable", sim.selectApplet(aid));

        // Malformed BF2E: outer length claims more data than provided.
        ApduResult res = transmit(sim, new CommandAPDU(fromHex("80E2110005BF2E033000")));
        assertEquals(0x6A80, res.sw);
    }
}
