package zk.esim.applet;

import javacard.framework.Util;

final class TlvWriter {

    private TlvWriter() {
    }

    static short appendEmptySequence(byte[] out, short pos) {
        out[pos++] = (byte) 0x30;
        out[pos++] = (byte) 0x00;
        return pos;
    }

    static short appendTlv(byte[] out, short pos, short tag, byte[] value, short valueOff, short valueLen) {
        pos = writeTag(out, pos, tag);
        pos = writeLength(out, pos, valueLen);
        Util.arrayCopyNonAtomic(value, valueOff, out, pos, valueLen);
        return (short) (pos + valueLen);
    }

    static short writeLength(byte[] out, short pos, short len) {
        if (len < 0x80) {
            out[pos++] = (byte) len;
        } else if (len <= 0xFF) {
            out[pos++] = (byte) 0x81;
            out[pos++] = (byte) len;
        } else {
            out[pos++] = (byte) 0x82;
            out[pos++] = (byte) ((len >> 8) & 0xFF);
            out[pos++] = (byte) (len & 0xFF);
        }
        return pos;
    }

    private static short writeTag(byte[] out, short pos, short tag) {
        if ((tag & (short) 0xFF00) != 0) {
            out[pos++] = (byte) ((tag >> 8) & 0xFF);
        }
        out[pos++] = (byte) (tag & 0xFF);
        return pos;
    }
}
