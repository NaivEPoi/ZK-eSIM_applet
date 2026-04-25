import com.licel.jcardsim.base.Simulator;
import javacard.framework.AID;
import org.junit.Test;
import zk.esim.applet.ZkEsimApplet;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class ZkEsimAppletSetEligibilityDataTest {
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

    private static byte[] store(byte[] data) {
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

    private static byte[] transmit(Simulator sim, byte[] command) {
        int dataLen = ((command[5] & 0xFF) << 8) | (command[6] & 0xFF);
        int pos = 7;
        int end = pos + dataLen;
        int blockNo = 0;
        byte[] response = null;
        while (pos < end) {
            int chunkLen = Math.min(240, end - pos);
            boolean last = pos + chunkLen == end;
            byte[] chunk = new byte[5 + chunkLen];
            chunk[0] = command[0];
            chunk[1] = command[1];
            chunk[2] = last ? (byte) 0x91 : (byte) 0x11;
            chunk[3] = (byte) blockNo++;
            chunk[4] = (byte) chunkLen;
            System.arraycopy(command, pos, chunk, 5, chunkLen);
            response = sim.transmitCommand(chunk);
            pos += chunkLen;
        }
        return response;
    }

    @Test
    public void testSetEligibilityDataAcceptsValidBundle() {
        Simulator sim = setup();
        byte[] req = buildRequest();
        byte[] response = transmit(sim, store(req));
        int sw = ((response[response.length - 2] & 0xFF) << 8) | (response[response.length - 1] & 0xFF);
        assertEquals(0x9000, sw);
        assertEquals((byte) 0xBF, response[0]);
        assertEquals((byte) 0x43, response[1]);
        assertEquals((byte) 0xA0, response[3]);
    }

    private static byte[] buildRequest() {
        int bodyLen = (2 + 32) + (2 + 64) + (2 + 64) + (2 + 32) + (2 + 64) + 2;
        byte[] req = new byte[5 + 4 + bodyLen];
        int pos = 0;
        req[pos++] = (byte) 0xBF;
        req[pos++] = 0x43;
        pos = writeLen(req, pos, 4 + bodyLen);
        req[pos++] = (byte) 0xA0;
        pos = writeLen(req, pos, bodyLen);
        pos = append(req, pos, 0x80, 32, (byte) 0x11);
        pos = append(req, pos, 0x81, 64, (byte) 0x22);
        pos = append(req, pos, 0x82, 64, (byte) 0x33);
        pos = append(req, pos, 0x83, 32, (byte) 0x44);
        pos = append(req, pos, 0x84, 64, (byte) 0x55);
        append(req, pos, 0x85, 0, (byte) 0x00);
        return req;
    }

    private static int writeLen(byte[] out, int pos, int len) {
        if (len < 128) {
            out[pos++] = (byte) len;
        } else if (len < 256) {
            out[pos++] = (byte) 0x81;
            out[pos++] = (byte) len;
        } else {
            out[pos++] = (byte) 0x82;
            out[pos++] = (byte) ((len >> 8) & 0xFF);
            out[pos++] = (byte) (len & 0xFF);
        }
        return pos;
    }

    private static int append(byte[] out, int pos, int tag, int len, byte value) {
        out[pos++] = (byte) tag;
        out[pos++] = (byte) len;
        for (int i = 0; i < len; i++) {
            out[pos++] = value;
        }
        return pos;
    }
}
