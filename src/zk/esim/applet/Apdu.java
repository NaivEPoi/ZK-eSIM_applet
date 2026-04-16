package zk.esim.applet;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * APDU reassembly helper for ES10x STORE DATA transport.
 *
 * Implements SGP.22 transport coding where:
 * - P1 is 0x91 (last block) or 0x11 (more blocks)
 * - P2 is the incrementing block number.
 */
public final class Apdu {

    public static final byte RESULT_MORE_SEGMENTS = 0x01;
    public static final byte RESULT_COMPLETE = 0x02;

    private static final byte P1_MORE_BLOCKS_MASK = (byte) 0x80;
    private static final byte P1_EXPECTED_BASE = 0x11;

    private static final short MAX_DEFAULT_CHUNK = (short) 256;

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
        expectedClaNoChain = 0;
        expectedIns = 0;
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
        return (p1 & P1_MORE_BLOCKS_MASK) == 0;
    }

    public static void validateP1(byte p1) {
        byte normalized = (byte) (p1 & 0x7F);
        if (normalized != P1_EXPECTED_BASE) {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }
    }

    public static boolean isTransportCla(byte cla) {
        short claU = (short) (cla & 0xFF);
        return (claU >= 0x80 && claU <= 0x83) || (claU >= 0xC0 && claU <= 0xCF);
    }

    public static final class PendingResponse {
        private final byte[] buffer;
        private final short maxChunkSize;
        private short length;
        private short offset;
        private boolean active;

        public PendingResponse(short capacity, short maxChunk) {
            buffer = JCSystem.makeTransientByteArray(capacity, JCSystem.CLEAR_ON_DESELECT);
            maxChunkSize = maxChunk;
            clear();
        }

        public boolean isActive() {
            return active;
        }

        public void clear() {
            length = 0;
            offset = 0;
            active = false;
        }

        public void stageAndSend(APDU apdu, byte[] src, short len) {
            if (len < 0 || len > (short) buffer.length) {
                ISOException.throwIt(ISO7816.SW_FILE_FULL);
            }
            Util.arrayCopyNonAtomic(src, (short) 0, buffer, (short) 0, len);
            length = len;
            offset = 0;
            active = true;
            sendChunk(apdu, false);
        }

        public void sendChunk(APDU apdu, boolean respectLe) {
            short remaining = (short) (length - offset);
            if (remaining <= 0) {
                clear();
                return;
            }

            short chunk = remaining;
            if (respectLe) {
                short le = getRequestedLe(apdu);
                if (chunk > le) {
                    chunk = le;
                }
            }
            if (chunk > maxChunkSize) {
                chunk = maxChunkSize;
            }

            apdu.setOutgoing();
            apdu.setOutgoingLength(chunk);
            apdu.sendBytesLong(buffer, offset, chunk);
            offset = (short) (offset + chunk);

            short leftAfterSend = (short) (length - offset);
            if (leftAfterSend > 0) {
                short sw2 = leftAfterSend > 255 ? 0 : leftAfterSend;
                ISOException.throwIt((short) (0x6100 | sw2));
            }

            clear();
        }

        private static short getRequestedLe(APDU apdu) {
            byte[] b = apdu.getBuffer();
            short le = (short) (b[ISO7816.OFFSET_LC] & 0xFF);
            return le == 0 ? MAX_DEFAULT_CHUNK : le;
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
