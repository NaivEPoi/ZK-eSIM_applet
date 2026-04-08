package zk.esim.applet;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

/**
 * Compact definite-length ASN.1 BER/DER decoder for selected SGP.22 objects.
 *
 * This decoder intentionally rejects indefinite-length encoding (0x80 length)
 * to keep parser complexity and memory pressure bounded on JavaCard.
 */
public final class Asn1 {

    public static final byte TYPE_GET_EUICC_CHALLENGE_REQUEST = (byte) 0x2E; // [46] BF2E
    public static final byte TYPE_PREPARE_DOWNLOAD_REQUEST = (byte) 0x21; // [33] BF21
    public static final byte TYPE_AUTHENTICATE_SERVER_REQUEST = (byte) 0x38; // [56] BF38
    public static final byte TYPE_BOUND_PROFILE_PACKAGE = (byte) 0x36; // [54] BF36

    private static final short TAG_SEQUENCE = (short) 0x0030;
    private static final short TAG_INTEGER = (short) 0x0002;
    private static final short TAG_OCTET_STRING = (short) 0x0004;

    private static final short TAG_APP_55 = (short) 0x5F37;
    private static final short TAG_APP_73 = (short) 0x5F49;

    private static final short TAG_BF21 = (short) 0xBF21;
    private static final short TAG_BF23 = (short) 0xBF23;
    private static final short TAG_BF2E = (short) 0xBF2E;
    private static final short TAG_BF36 = (short) 0xBF36;
    private static final short TAG_BF38 = (short) 0xBF38;

    private static final short TAG_CTX_0 = (short) 0x0080;
    private static final short TAG_CTX_1 = (short) 0x0081;
    private static final short TAG_CTX_3 = (short) 0x0083;
    private static final short TAG_CTX_4 = (short) 0x0084;

    private static final short TAG_A0 = (short) 0x00A0;
    private static final short TAG_A1 = (short) 0x00A1;
    private static final short TAG_A2 = (short) 0x00A2;
    private static final short TAG_A3 = (short) 0x00A3;
    private static final short TAG_A6 = (short) 0x00A6;

    private static final short TAG_87 = (short) 0x0087;
    private static final short TAG_88 = (short) 0x0088;
    private static final short TAG_86 = (short) 0x0086;

    // We use invalid-data for malformed ASN.1 structure.
    private static final short SW_ASN1_INVALID = (short) 0x6A80;

    private final Tlv tlvA = new Tlv();
    private final Tlv tlvB = new Tlv();
    private final Tlv tlvC = new Tlv();

    public static final class DecodedMessage {
        public byte type;
        public boolean ccRequiredFlag;
        public short txIdLen;
        public final byte[] txId = new byte[16];
        public short euiccChallengeLen;
        public final byte[] euiccChallenge = new byte[16];
        public short serverAddressLen;
        public final byte[] serverAddress = new byte[128];
        public short serverChallengeLen;
        public final byte[] serverChallenge = new byte[16];

        public void clear() {
            type = (byte) 0x00;
            ccRequiredFlag = false;
            txIdLen = 0;
            euiccChallengeLen = 0;
            serverAddressLen = 0;
            serverChallengeLen = 0;
            Util.arrayFillNonAtomic(txId, (short) 0, (short) txId.length, (byte) 0x00);
            Util.arrayFillNonAtomic(euiccChallenge, (short) 0, (short) euiccChallenge.length, (byte) 0x00);
            Util.arrayFillNonAtomic(serverAddress, (short) 0, (short) serverAddress.length, (byte) 0x00);
            Util.arrayFillNonAtomic(serverChallenge, (short) 0, (short) serverChallenge.length, (byte) 0x00);
        }
    }

    private static final class Tlv {
        short tag;
        short headerLen;
        short valueOff;
        short valueLen;
        short totalLen;
    }

    public void decode(byte[] data, short dataLen, DecodedMessage out) {
        out.clear();

        parseTlv(data, (short) 0, dataLen, tlvA);
        if (tlvA.totalLen != dataLen) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }

        if (tlvA.tag == TAG_BF21) {
            out.type = TYPE_PREPARE_DOWNLOAD_REQUEST;
            decodePrepareDownloadRequest(data, tlvA.valueOff, (short) (tlvA.valueOff + tlvA.valueLen), out);
            return;
        }

        if (tlvA.tag == TAG_BF2E) {
            out.type = TYPE_GET_EUICC_CHALLENGE_REQUEST;
            decodeGetEuiccChallengeRequest(data, tlvA.valueOff, (short) (tlvA.valueOff + tlvA.valueLen));
            return;
        }

        if (tlvA.tag == TAG_BF38) {
            out.type = TYPE_AUTHENTICATE_SERVER_REQUEST;
            decodeAuthenticateServerRequest(data, tlvA.valueOff, (short) (tlvA.valueOff + tlvA.valueLen), out);
            return;
        }

        if (tlvA.tag == TAG_BF36) {
            out.type = TYPE_BOUND_PROFILE_PACKAGE;
            decodeBoundProfilePackage(data, tlvA.valueOff, (short) (tlvA.valueOff + tlvA.valueLen), out);
            return;
        }

        // Unknown command request data object for ES10x STORE DATA.
        ISOException.throwIt((short) 0x6A88);
    }

    private void decodePrepareDownloadRequest(byte[] data, short off, short end, DecodedMessage out) {
        // smdpSigned2
        short pos = off;
        parseTlv(data, pos, end, tlvA);
        if (tlvA.tag != TAG_SEQUENCE) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
        short seqTotalLen = tlvA.totalLen;
        decodeSmdpSigned2(data, tlvA.valueOff, (short) (tlvA.valueOff + tlvA.valueLen), out);
        pos = (short) (pos + seqTotalLen);

        // smdpSignature2 [APPLICATION 55] OCTET STRING
        parseTlv(data, pos, end, tlvB);
        if (tlvB.tag != TAG_APP_55) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
        pos = (short) (pos + tlvB.totalLen);

        // Optional hashCc OCTET STRING, then mandatory certificate SEQUENCE
        parseTlv(data, pos, end, tlvC);
        if (tlvC.tag == TAG_OCTET_STRING) {
            pos = (short) (pos + tlvC.totalLen);
            parseTlv(data, pos, end, tlvC);
        }

        if (tlvC.tag != TAG_SEQUENCE) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }

        pos = (short) (pos + tlvC.totalLen);
        if (pos != end) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
    }

    private void decodeSmdpSigned2(byte[] data, short off, short end, DecodedMessage out) {
        // transactionId [0] TransactionId (implicit OCTET STRING)
        short pos = off;
        parseTlv(data, pos, end, tlvA);
        if (tlvA.tag != TAG_CTX_0 || tlvA.valueLen < 1 || tlvA.valueLen > 16) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
        copyTxId(data, tlvA.valueOff, tlvA.valueLen, out);
        pos = (short) (pos + tlvA.totalLen);

        // ccRequiredFlag BOOLEAN (universal tag 0x01)
        parseTlv(data, pos, end, tlvB);
        if (tlvB.tag != (short) 0x0001 || tlvB.valueLen != 1) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
        out.ccRequiredFlag = data[tlvB.valueOff] != (byte) 0x00;
        pos = (short) (pos + tlvB.totalLen);

        // optional bppEuiccOtpk [APPLICATION 73]
        if (pos < end) {
            parseTlv(data, pos, end, tlvC);
            if (tlvC.tag != TAG_APP_73) {
                ISOException.throwIt(SW_ASN1_INVALID);
            }
            pos = (short) (pos + tlvC.totalLen);
        }

        if (pos != end) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
    }

    private void decodeAuthenticateServerRequest(byte[] data, short off, short end, DecodedMessage out) {
        short pos = off;

        // serverSigned1 SEQUENCE
        parseTlv(data, pos, end, tlvA);
        if (tlvA.tag != TAG_SEQUENCE) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
        short seqTotalLen = tlvA.totalLen;
        decodeServerSigned1(data, tlvA.valueOff, (short) (tlvA.valueOff + tlvA.valueLen), out);
        pos = (short) (pos + seqTotalLen);

        // serverSignature1 [APPLICATION 55]
        parseTlv(data, pos, end, tlvB);
        if (tlvB.tag != TAG_APP_55) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
        pos = (short) (pos + tlvB.totalLen);

        // euiccCiPKIdToBeUsed SubjectKeyIdentifier (OCTET STRING in PKIX implicit)
        parseTlv(data, pos, end, tlvC);
        if (tlvC.tag != TAG_OCTET_STRING) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
        pos = (short) (pos + tlvC.totalLen);

        // serverCertificate Certificate (SEQUENCE)
        parseTlv(data, pos, end, tlvA);
        if (tlvA.tag != TAG_SEQUENCE) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
        pos = (short) (pos + tlvA.totalLen);

        // ctxParams1 CHOICE, currently expected as SEQUENCE
        parseTlv(data, pos, end, tlvB);
        if (tlvB.tag != TAG_SEQUENCE) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
        pos = (short) (pos + tlvB.totalLen);

        if (pos != end) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
    }

    private void decodeServerSigned1(byte[] data, short off, short end, DecodedMessage out) {
        short pos = off;

        // transactionId [0]
        parseTlv(data, pos, end, tlvA);
        if (tlvA.tag != TAG_CTX_0 || tlvA.valueLen < 1 || tlvA.valueLen > 16) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
        copyTxId(data, tlvA.valueOff, tlvA.valueLen, out);
        pos = (short) (pos + tlvA.totalLen);

        // euiccChallenge [1] Octet16
        parseTlv(data, pos, end, tlvB);
        if (tlvB.tag != TAG_CTX_1 || tlvB.valueLen != 16) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
        copyBytes(data, tlvB.valueOff, tlvB.valueLen, out.euiccChallenge);
        out.euiccChallengeLen = tlvB.valueLen;
        pos = (short) (pos + tlvB.totalLen);

        // serverAddress [3] UTF8String (implicit)
        parseTlv(data, pos, end, tlvC);
        if (tlvC.tag != TAG_CTX_3 || tlvC.valueLen < 1 || tlvC.valueLen > out.serverAddress.length) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
        copyBytes(data, tlvC.valueOff, tlvC.valueLen, out.serverAddress);
        out.serverAddressLen = tlvC.valueLen;
        pos = (short) (pos + tlvC.totalLen);

        // serverChallenge [4] Octet16
        parseTlv(data, pos, end, tlvA);
        if (tlvA.tag != TAG_CTX_4 || tlvA.valueLen != 16) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
        copyBytes(data, tlvA.valueOff, tlvA.valueLen, out.serverChallenge);
        out.serverChallengeLen = tlvA.valueLen;
        pos = (short) (pos + tlvA.totalLen);

        if (pos != end) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
    }

    private void decodeGetEuiccChallengeRequest(byte[] data, short off, short end) {
        parseTlv(data, off, end, tlvA);
        if (tlvA.tag != TAG_SEQUENCE || tlvA.valueLen != 0) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
        if ((short) (off + tlvA.totalLen) != end) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
    }

    private void decodeBoundProfilePackage(byte[] data, short off, short end, DecodedMessage out) {
        short pos = off;

        // initialiseSecureChannelRequest [35]
        parseTlv(data, pos, end, tlvA);
        if (tlvA.tag != TAG_BF23) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
        short iscTotalLen = tlvA.totalLen;
        decodeInitialiseSecureChannelRequest(data, tlvA.valueOff, (short) (tlvA.valueOff + tlvA.valueLen), out);
        pos = (short) (pos + iscTotalLen);

        // [0] SEQUENCE OF [7] OCTET STRING
        parseTlv(data, pos, end, tlvB);
        if (tlvB.tag != TAG_A0) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
        validateSequenceOfTaggedOctets(data, tlvB.valueOff, (short) (tlvB.valueOff + tlvB.valueLen), TAG_87);
        pos = (short) (pos + tlvB.totalLen);

        // [1] SEQUENCE OF [8] OCTET STRING
        parseTlv(data, pos, end, tlvC);
        if (tlvC.tag != TAG_A1) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
        short a1TotalLen = tlvC.totalLen;
        validateSequenceOfTaggedOctets(data, tlvC.valueOff, (short) (tlvC.valueOff + tlvC.valueLen), TAG_88);
        pos = (short) (pos + a1TotalLen);

        // Optional [2] SEQUENCE OF [7] OCTET STRING
        parseTlv(data, pos, end, tlvA);
        if (tlvA.tag == TAG_A2) {
            validateSequenceOfTaggedOctets(data, tlvA.valueOff, (short) (tlvA.valueOff + tlvA.valueLen), TAG_87);
            pos = (short) (pos + tlvA.totalLen);
            parseTlv(data, pos, end, tlvA);
        }

        // [3] SEQUENCE OF [6] OCTET STRING
        if (tlvA.tag != TAG_A3) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
        validateSequenceOfTaggedOctets(data, tlvA.valueOff, (short) (tlvA.valueOff + tlvA.valueLen), TAG_86);
        pos = (short) (pos + tlvA.totalLen);

        if (pos != end) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
    }

    private void decodeInitialiseSecureChannelRequest(byte[] data, short off, short end, DecodedMessage out) {
        short pos = off;

        // remoteOpId INTEGER, expected installBoundProfilePackage(1)
        parseTlv(data, pos, end, tlvA);
        if (tlvA.tag != TAG_INTEGER || tlvA.valueLen < 1 || tlvA.valueLen > 2) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
        if (!isIntegerValueOne(data, tlvA.valueOff, tlvA.valueLen)) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
        pos = (short) (pos + tlvA.totalLen);

        // transactionId [0]
        parseTlv(data, pos, end, tlvB);
        if (tlvB.tag != TAG_CTX_0 || tlvB.valueLen < 1 || tlvB.valueLen > 16) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
        copyTxId(data, tlvB.valueOff, tlvB.valueLen, out);
        pos = (short) (pos + tlvB.totalLen);

        // controlRefTemplate [6]
        parseTlv(data, pos, end, tlvC);
        if (tlvC.tag != TAG_A6) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
        pos = (short) (pos + tlvC.totalLen);

        // smdpOtpk [APPLICATION 73]
        parseTlv(data, pos, end, tlvA);
        if (tlvA.tag != TAG_APP_73) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
        pos = (short) (pos + tlvA.totalLen);

        // smdpSign [APPLICATION 55]
        parseTlv(data, pos, end, tlvB);
        if (tlvB.tag != TAG_APP_55) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
        pos = (short) (pos + tlvB.totalLen);

        if (pos != end) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
    }

    private void validateSequenceOfTaggedOctets(byte[] data, short off, short end, short expectedTag) {
        short pos = off;
        while (pos < end) {
            parseTlv(data, pos, end, tlvC);
            if (tlvC.tag != expectedTag) {
                ISOException.throwIt(SW_ASN1_INVALID);
            }
            pos = (short) (pos + tlvC.totalLen);
        }

        if (pos != end) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
    }

    private static void copyTxId(byte[] data, short off, short len, DecodedMessage out) {
        out.txIdLen = len;
        Util.arrayCopyNonAtomic(data, off, out.txId, (short) 0, len);
    }

    private static void copyBytes(byte[] data, short off, short len, byte[] out) {
        Util.arrayCopyNonAtomic(data, off, out, (short) 0, len);
    }

    private static boolean isIntegerValueOne(byte[] data, short off, short len) {
        if (len == 1) {
            return data[off] == (byte) 0x01;
        }
        if (len == 2) {
            return data[off] == (byte) 0x00 && data[(short) (off + 1)] == (byte) 0x01;
        }
        return false;
    }

    private static void parseTlv(byte[] data, short off, short end, Tlv out) {
        if (off >= end) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }

        short pos = off;
        short tag;

        byte first = data[pos];
        pos++;

        if ((short) (first & 0x1F) == 0x1F) {
            if (pos >= end) {
                ISOException.throwIt(SW_ASN1_INVALID);
            }
            byte second = data[pos];
            pos++;

            if ((second & (byte) 0x80) != 0) {
                // High-tag-number form longer than two bytes is intentionally unsupported.
                ISOException.throwIt(SW_ASN1_INVALID);
            }
            tag = (short) (((short) (first & 0xFF) << 8) | (short) (second & 0xFF));
        } else {
            tag = (short) (first & 0xFF);
        }

        if (pos >= end) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }

        byte lenB = data[pos];
        pos++;

        short len;
        if ((lenB & (byte) 0x80) == 0) {
            len = (short) (lenB & 0x7F);
        } else {
            byte numLenBytes = (byte) (lenB & 0x7F);
            if (numLenBytes == 0) {
                // Indefinite length is not supported.
                ISOException.throwIt(SW_ASN1_INVALID);
            }
            if (numLenBytes > 2) {
                ISOException.throwIt(SW_ASN1_INVALID);
            }
            if ((short) (pos + numLenBytes) > end) {
                ISOException.throwIt(SW_ASN1_INVALID);
            }

            len = 0;
            for (byte i = 0; i < numLenBytes; i++) {
                len = (short) ((short) (len << 8) | (short) (data[(short) (pos + i)] & 0xFF));
            }
            pos = (short) (pos + numLenBytes);
        }

        if ((short) (pos + len) > end) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }

        out.tag = tag;
        out.headerLen = (short) (pos - off);
        out.valueOff = pos;
        out.valueLen = len;
        out.totalLen = (short) (out.headerLen + out.valueLen);
    }
}
