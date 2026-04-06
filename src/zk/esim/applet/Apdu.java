package zk.esim.applet;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

/**
 * APDU reassembly helper for ES10x STORE DATA transport.
 *
 * Implements SGP.22 transport coding where:
 * - P1 is 0x11 (last block) or 0x91 (more blocks)
 * - P2 is the incrementing block number.
 */
public final class Apdu {

    public static final byte RESULT_MORE_SEGMENTS = (byte) 0x01;
    public static final byte RESULT_COMPLETE = (byte) 0x02;

    private static final byte P1_MORE_BLOCKS_MASK = (byte) 0x80;
    private static final byte P1_EXPECTED_BASE = (byte) 0x11;

    // Existing APDU state is invalid or inconsistent.
    private static final short SW_BAD_CHAINING_STATE = (short) 0x6A80;

    private final byte[] assembly;
    private short length;
    private boolean inProgress;
    private byte expectedClaNoChain;
    private byte expectedIns;
    private short expectedBlockNumber;

    public Apdu(byte[] assemblyBuffer) {
        assembly = assemblyBuffer;
        reset();
    }

    public void reset() {
        length = 0;
        inProgress = false;
        expectedClaNoChain = (byte) 0x00;
        expectedIns = (byte) 0x00;
        expectedBlockNumber = 0;
    }

    public byte[] getBuffer() {
        return assembly;
    }

    public short getLength() {
        return length;
    }

    public byte ingest(APDU apdu, byte cla, byte ins) {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        short p2 = (short) (buf[ISO7816.OFFSET_P2] & 0xFF);

        validateP1(p1);

        byte claNoChain = cla;
        boolean hasMore = hasMoreSegments(p1);

        if (!inProgress) {
            expectedClaNoChain = claNoChain;
            expectedIns = ins;
            expectedBlockNumber = 0;
        } else {
            if (claNoChain != expectedClaNoChain || ins != expectedIns) {
                reset();
                ISOException.throwIt(SW_BAD_CHAINING_STATE);
            }
        }

        if (p2 != expectedBlockNumber) {
            reset();
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }

        short copied = readIncoming(apdu, assembly, length, (short) assembly.length);
        length = (short) (length + copied);
        expectedBlockNumber = (short) ((expectedBlockNumber + 1) & 0x00FF);

        if (hasMore) {
            inProgress = true;
            return RESULT_MORE_SEGMENTS;
        }

        inProgress = false;
        return RESULT_COMPLETE;
    }

    public static boolean hasMoreSegments(byte p1) {
        return (p1 & P1_MORE_BLOCKS_MASK) != 0;
    }

    public static void validateP1(byte p1) {
        byte normalized = (byte) (p1 & (byte) 0x7F);
        if (normalized != P1_EXPECTED_BASE) {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }
    }

    private static short readIncoming(APDU apdu, byte[] dst, short dstOff, short dstMax) {
        short copied = 0;
        short read = apdu.setIncomingAndReceive();

        while (read > 0) {
            if ((short) (dstOff + copied + read) > dstMax) {
                ISOException.throwIt(ISO7816.SW_FILE_FULL);
            }

            Util.arrayCopyNonAtomic(apdu.getBuffer(), ISO7816.OFFSET_CDATA, dst, (short) (dstOff + copied), read);
            copied = (short) (copied + read);
            read = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
        }

        return copied;
    }
}
