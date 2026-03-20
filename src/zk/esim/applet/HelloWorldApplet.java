package zk.esim.applet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

public final class HelloWorldApplet extends Applet {
    private static final byte CLA_PLAIN = (byte) 0x00;
    private static final byte CLA_PROPRIETARY = (byte) 0x80;
    private static final byte INS_HELLO = (byte) 0x90;
    private static final byte INS_HELLO_T0_SAFE = (byte) 0x10;

    private static final byte[] HELLO_WORLD = {
        (byte) 'h', (byte) 'e', (byte) 'l', (byte) 'l', (byte) 'o',
        (byte) '-', (byte) 'w', (byte) 'o', (byte) 'r', (byte) 'l', (byte) 'd'
    };

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new HelloWorldApplet();
    }

    private HelloWorldApplet() {
        register();
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }

        byte[] buf = apdu.getBuffer();

        byte cla = buf[ISO7816.OFFSET_CLA];
        byte ins = buf[ISO7816.OFFSET_INS];

        if (cla != CLA_PLAIN && cla != CLA_PROPRIETARY) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        // Keep the original 00/90 command and also support a T=0-safe variant 80/10.
        if (!((cla == CLA_PLAIN && ins == INS_HELLO) ||
                (cla == CLA_PROPRIETARY && ins == INS_HELLO_T0_SAFE))) {
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
        if (buf[ISO7816.OFFSET_P1] != (byte) 0x00 || buf[ISO7816.OFFSET_P2] != (byte) 0x00) {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }

        short lc = (short) (buf[ISO7816.OFFSET_LC] & 0x00FF);
        if (lc != (short) 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        Util.arrayCopyNonAtomic(HELLO_WORLD, (short) 0, buf, (short) 0, (short) HELLO_WORLD.length);
        apdu.setOutgoingAndSend((short) 0, (short) HELLO_WORLD.length);
    }
}
