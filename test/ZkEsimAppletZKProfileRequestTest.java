import com.licel.jcardsim.base.Simulator;
import javacard.framework.AID;
import org.junit.Test;
import zk.esim.applet.ZkEsimApplet;

import java.io.ByteArrayOutputStream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class ZkEsimAppletZKProfileRequestTest {
    private static final byte[] APPLET_AID = fromHex("D07002CA44900101");

    private static byte[] fromHex(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private static Simulator setup() {
        Simulator sim = new Simulator();
        AID aid = new AID(APPLET_AID, (short) 0, (byte) APPLET_AID.length);
        sim.installApplet(aid, ZkEsimApplet.class);
        assertTrue(sim.selectApplet(aid));
        return sim;
    }

    private static byte[] buildStoreDataApdu(byte[] data) {
        byte[] apdu = new byte[5 + data.length];
        apdu[0] = (byte) 0x80;
        apdu[1] = (byte) 0xE2;
        apdu[2] = (byte) 0x91;
        apdu[3] = 0x00;
        apdu[4] = (byte) data.length;
        System.arraycopy(data, 0, apdu, 5, data.length);
        return apdu;
    }

    private static ApduResult transmit(Simulator sim, byte[] command) {
        ByteArrayOutputStream allData = new ByteArrayOutputStream();
        byte[] response = sim.transmitCommand(command);
        int sw = ((response[response.length - 2] & 0xFF) << 8) | (response[response.length - 1] & 0xFF);
        allData.write(response, 0, response.length - 2);
        while ((sw & 0xFF00) == 0x9100) {
            response = sim.transmitCommand(new byte[]{0x00, (byte) 0xC0, 0x00, 0x00, 0x00});
            sw = ((response[response.length - 2] & 0xFF) << 8) | (response[response.length - 1] & 0xFF);
            allData.write(response, 0, response.length - 2);
        }
        byte[] data = allData.toByteArray();
        return new ApduResult(data, sw);
    }

    @Test
    public void testZkProfileRequestReturnsOkChoice() {
        Simulator sim = setup();
        byte[] req = fromHex("BF42128010000102030405060708090A0B0C0D0E0F");
        ApduResult res = transmit(sim, buildStoreDataApdu(req));
        assertEquals(0x9000, res.sw);
        assertTrue(res.data.length > 400);
        assertEquals((byte) 0xBF, res.data[0]);
        assertEquals((byte) 0x42, res.data[1]);
        assertTrue("BF42 response must contain ok CHOICE A0", containsByte(res.data, (byte) 0xA0));
        assertTrue("BF42 response must contain ZKStatement SEQUENCE", containsByte(res.data, (byte) 0x30));
        assertTrue("BF42 response must contain zkProof tag 5F37", containsTag5f37(res.data));
    }

    private static boolean containsByte(byte[] data, byte value) {
        for (byte b : data) {
            if (b == value) {
                return true;
            }
        }
        return false;
    }

    private static boolean containsTag5f37(byte[] data) {
        for (int i = 0; i + 1 < data.length; i++) {
            if ((data[i] & 0xFF) == 0x5F && (data[i + 1] & 0xFF) == 0x37) {
                return true;
            }
        }
        return false;
    }

    private static final class ApduResult {
        final byte[] data;
        final int sw;
        ApduResult(byte[] data, int sw) {
            this.data = data;
            this.sw = sw;
        }
    }
}
