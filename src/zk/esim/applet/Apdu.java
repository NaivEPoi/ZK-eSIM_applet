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
    // Proprietary "more data pending" SW1; host issues GET RESPONSE with Le=sw2.
    private static final short SW_MORE_DATA_PROP_00 = (short) 0x9100;
    private static final short MAX_REASSEMBLED_APDU = (short) 1536;

    private final byte[] buffer;
    private short length;
    private boolean inProgress;
    private byte expectedClaNoChain;
    private byte expectedIns;
    private short expectedBlockNumber;

    public Apdu() {
        buffer = JCSystem.makeTransientByteArray(MAX_REASSEMBLED_APDU, JCSystem.CLEAR_ON_RESET);
        reset();
    }

    public void reset() {
        Util.arrayFillNonAtomic(buffer, (short) 0, (short) buffer.length, (byte) 0x00);
        length = 0;
        inProgress = false;
        expectedClaNoChain = 0;
        expectedIns = 0;
        expectedBlockNumber = 0;
    }

    public byte[] getBuffer() {
        return buffer;
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

        short copied = readIncoming(apdu, buffer, length, (short) buffer.length);
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
        // The source buffer must remain valid until the response is fully drained via GET RESPONSE.
        private final byte[] buffer;
        private final short maxChunkSize;
        private short length;
        private short offset;
        private boolean active;

        public PendingResponse(byte[] sourceBuffer, short maxChunk) {
            buffer = sourceBuffer;
            maxChunkSize = maxChunk > MAX_DEFAULT_CHUNK ? MAX_DEFAULT_CHUNK : maxChunk;
            clear();
        }

        public boolean isActive() {
            return active;
        }

        public void clear() {
            Util.arrayFillNonAtomic(buffer, (short) 0, (short) buffer.length, (byte) 0x00);
            length = 0;
            offset = 0;
            active = false;
        }

        public void stageAndSend(APDU apdu, short len) {
            if (len < 0 || len > (short) buffer.length) {
                ISOException.throwIt(ISO7816.SW_FILE_FULL);
            }
            length = len;
            offset = 0;
            active = true;

            if (len == 0) {
                clear();
                return;
            }

            sendChunk(apdu);
        }

        // Send a single T=0 frame (≤256 bytes) and signal "more data pending" with a
        // proprietary 91xx status word when the response is not yet drained.
        //
        // Real-card behavior: on transport CLA 0x81, throw-based 61xx during response
        // staging can cause the card runtime to emit an immediate 6F00 instead of the
        // expected GET RESPONSE handshake. Emitting 91xx avoids the runtime's T=0
        // auto-chaining path; the host loop recognises 91xx as a synonym for 61xx
        // ("issue GET RESPONSE with Le=sw2") and continues pulling.
        public void sendChunk(APDU apdu) {
            short bytesRemaining = (short) (length - offset);
            if (bytesRemaining <= 0) {
                clear();
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }

            // Cap to 256 bytes per T=0 frame before calling setOutgoingLength()
            short chunkSize = bytesRemaining > maxChunkSize ? maxChunkSize : bytesRemaining;

            apdu.setOutgoing();
            apdu.setOutgoingLength(chunkSize);
            apdu.sendBytesLong(buffer, offset, chunkSize);

            offset = (short) (offset + chunkSize);
            short stillRemaining = (short) (length - offset);
            if (stillRemaining <= 0) {
                clear();
            }
            else {
                short sw2 = stillRemaining > (short) 0xFF ? (short) 0x00 : stillRemaining;
                ISOException.throwIt((short) (SW_MORE_DATA_PROP_00 + sw2));
            }
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
