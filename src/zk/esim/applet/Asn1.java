package zk.esim.applet;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * Compact strict-canonical DER decoder for selected SGP.22 objects.
 *
 * This decoder intentionally rejects non-canonical BER forms (including
 * indefinite lengths and non-minimal definite length encodings) to keep
 * parser behavior deterministic and standards-aligned on JavaCard.
 */
public final class Asn1 {

    public static final byte TYPE_GET_EUICC_CHALLENGE_REQUEST = 0x2E; // [46] BF2E
    public static final byte TYPE_GET_EUICC_INFO1_REQUEST = 0x20; // [32] BF20
    public static final byte TYPE_PREPARE_DOWNLOAD_REQUEST = 0x21; // [33] BF21
    public static final byte TYPE_AUTHENTICATE_SERVER_REQUEST = 0x38; // [56] BF38
    public static final byte TYPE_CANCEL_SESSION_REQUEST = 0x41; // [65] BF41
    public static final byte TYPE_ZK_PROFILE_REQUEST = 0x42; // [66] BF42
    public static final byte TYPE_SET_ELIGIBILITY_DATA_REQUEST = 0x43; // [67] BF43
    public static final byte TYPE_BOUND_PROFILE_PACKAGE = 0x36; // [54] BF36
    public static final byte TYPE_ZK_REGISTER_CHALLENGE = 0x44; // [68] BF44 Phase 0.a leg 1
    public static final byte TYPE_ZK_REGISTER_CREDENTIAL = 0x45; // [69] BF45 Phase 0.a leg 2
    public static final byte TYPE_ZK_CERT_INIT_REQUEST = 0x46; // [70] BF46 Phase 0.b leg 1
    public static final byte TYPE_ZK_CERT_INIT_COMPLETE = 0x47; // [71] BF47 Phase 0.b leg 2

    private static final short TAG_SEQUENCE = (short) 0x0030;
    private static final short TAG_INTEGER = (short) 0x0002;
    private static final short TAG_OCTET_STRING = (short) 0x0004;
    private static final short TAG_UTF8_STRING = (short) 0x000C;

    private static final short TAG_APP_55 = (short) 0x5F37;
    private static final short TAG_APP_73 = (short) 0x5F49;

    private static final short TAG_BF21 = (short) 0xBF21;
    private static final short TAG_BF23 = (short) 0xBF23;
    private static final short TAG_BF20 = (short) 0xBF20;
    private static final short TAG_BF2E = (short) 0xBF2E;
    private static final short TAG_BF36 = (short) 0xBF36;
    private static final short TAG_BF38 = (short) 0xBF38;
    private static final short TAG_BF41 = (short) 0xBF41;
    private static final short TAG_BF42 = (short) 0xBF42;
    private static final short TAG_BF43 = (short) 0xBF43;
    private static final short TAG_BF44 = (short) 0xBF44;
    private static final short TAG_BF45 = (short) 0xBF45;
    private static final short TAG_BF46 = (short) 0xBF46;
    private static final short TAG_BF47 = (short) 0xBF47;

    private static final short TAG_CTX_0 = (short) 0x0080;
    private static final short TAG_CTX_1 = (short) 0x0081;
    private static final short TAG_CTX_2 = (short) 0x0082;
    private static final short TAG_CTX_3 = (short) 0x0083;
    private static final short TAG_CTX_4 = (short) 0x0084;
    private static final short TAG_CTX_5 = (short) 0x0085;

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
        public final byte[] txId;
        public short smdpSignature2Len;
        public final byte[] smdpSignature2;
        public short serverSignature1Len;
        public final byte[] serverSignature1;
        public short bppEuiccOtpkLen;
        public final byte[] bppEuiccOtpk;
        public short smdpCertificateLen;
        public final byte[] smdpCertificate;
        public short euiccChallengeLen;
        public final byte[] euiccChallenge;
        public short serverAddressLen;
        public final byte[] serverAddress;
        public short serverChallengeLen;
        public final byte[] serverChallenge;
        public byte cancelSessionReason;
        public short bf23SmdpOtpkOff;
        public short bf23SmdpOtpkLen;
        public short bf23SmdpSignOff;
        public short bf23SmdpSignLen;
        public short bf23SignedStart;
        public short bf23SignedEnd;
        public short bf23CrtOff;
        public short bf23CrtLen;
        public short hostIdOff;
        public short hostIdLen;
        public short a0Off;
        public short a0Len;
        public short a1Off;
        public short a1Len;
        public short a2Off;
        public short a2Len;
        public short a3Off;
        public short a3Len;
        public final byte[] eligibilityData;
        public short eligibilityDataLen;
        // Phase 0: single 80-tagged field — nonce (≤32B), σ̃ (≤72B), r_seed (32B), or PCert_U (≤512B)
        public final byte[] phase0Data;
        public short phase0DataLen;

        public DecodedMessage() {
            // Parsing scratch/output buffers are session state and do not need EEPROM persistence.
            txId = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);
            eligibilityData = JCSystem.makeTransientByteArray((short) 512, JCSystem.CLEAR_ON_DESELECT);
            phase0Data = JCSystem.makeTransientByteArray((short) 512, JCSystem.CLEAR_ON_DESELECT);
            smdpSignature2 = JCSystem.makeTransientByteArray((short) 80, JCSystem.CLEAR_ON_DESELECT);
            serverSignature1 = JCSystem.makeTransientByteArray((short) 80, JCSystem.CLEAR_ON_DESELECT);
            bppEuiccOtpk = JCSystem.makeTransientByteArray((short) 65, JCSystem.CLEAR_ON_DESELECT);
            smdpCertificate = JCSystem.makeTransientByteArray((short) 700, JCSystem.CLEAR_ON_DESELECT);
            euiccChallenge = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);
            serverAddress = JCSystem.makeTransientByteArray((short) 128, JCSystem.CLEAR_ON_DESELECT);
            serverChallenge = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);
        }

        public void clear() {
            type = 0;
            ccRequiredFlag = false;
            txIdLen = 0;
            smdpSignature2Len = 0;
            serverSignature1Len = 0;
            bppEuiccOtpkLen = 0;
            smdpCertificateLen = 0;
            euiccChallengeLen = 0;
            serverAddressLen = 0;
            serverChallengeLen = 0;
            cancelSessionReason = 0;
            bf23SmdpOtpkOff = 0;
            bf23SmdpOtpkLen = 0;
            bf23SmdpSignOff = 0;
            bf23SmdpSignLen = 0;
            bf23SignedStart = 0;
            bf23SignedEnd = 0;
            bf23CrtOff = 0;
            bf23CrtLen = 0;
            hostIdOff = 0;
            hostIdLen = 0;
            a0Off = 0;
            a0Len = 0;
            a1Off = 0;
            a1Len = 0;
            a2Off = 0;
            a2Len = 0;
            a3Off = 0;
            a3Len = 0;
            eligibilityDataLen = 0;
            Util.arrayFillNonAtomic(eligibilityData, (short) 0, (short) eligibilityData.length, (byte) 0);
            phase0DataLen = 0;
            Util.arrayFillNonAtomic(phase0Data, (short) 0, (short) phase0Data.length, (byte) 0);
            Util.arrayFillNonAtomic(txId, (short) 0, (short) txId.length, (byte) 0);
            Util.arrayFillNonAtomic(smdpSignature2, (short) 0, (short) smdpSignature2.length, (byte) 0);
            Util.arrayFillNonAtomic(serverSignature1, (short) 0, (short) serverSignature1.length, (byte) 0);
            Util.arrayFillNonAtomic(bppEuiccOtpk, (short) 0, (short) bppEuiccOtpk.length, (byte) 0);
            Util.arrayFillNonAtomic(smdpCertificate, (short) 0, (short) smdpCertificate.length, (byte) 0);
            Util.arrayFillNonAtomic(euiccChallenge, (short) 0, (short) euiccChallenge.length, (byte) 0);
            Util.arrayFillNonAtomic(serverAddress, (short) 0, (short) serverAddress.length, (byte) 0);
            Util.arrayFillNonAtomic(serverChallenge, (short) 0, (short) serverChallenge.length, (byte) 0);
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

        if (tlvA.tag == TAG_BF20) {
            out.type = TYPE_GET_EUICC_INFO1_REQUEST;
            decodeGetEuiccChallengeRequest(data, tlvA.valueOff, (short) (tlvA.valueOff + tlvA.valueLen));
            return;
        }

        if (tlvA.tag == TAG_BF38) {
            out.type = TYPE_AUTHENTICATE_SERVER_REQUEST;
            decodeAuthenticateServerRequest(data, tlvA.valueOff, (short) (tlvA.valueOff + tlvA.valueLen), out);
            return;
        }

        if (tlvA.tag == TAG_BF41) {
            out.type = TYPE_CANCEL_SESSION_REQUEST;
            decodeCancelSessionRequest(data, tlvA.valueOff, (short) (tlvA.valueOff + tlvA.valueLen), out);
            return;
        }

        if (tlvA.tag == TAG_BF42) {
            out.type = TYPE_ZK_PROFILE_REQUEST;
            decodeZKProfileRequest(data, tlvA.valueOff, (short) (tlvA.valueOff + tlvA.valueLen), out);
            return;
        }

        if (tlvA.tag == TAG_BF43) {
            out.type = TYPE_SET_ELIGIBILITY_DATA_REQUEST;
            decodeSetEligibilityDataRequest(data, tlvA.valueOff, (short) (tlvA.valueOff + tlvA.valueLen), out);
            return;
        }

        if (tlvA.tag == TAG_BF36) {
            out.type = TYPE_BOUND_PROFILE_PACKAGE;
            decodeBoundProfilePackage(data, tlvA.valueOff, (short) (tlvA.valueOff + tlvA.valueLen), out);
            return;
        }

        if (tlvA.tag == TAG_BF44) {
            out.type = TYPE_ZK_REGISTER_CHALLENGE;
            decodePhase0SingleField(data, tlvA.valueOff, (short) (tlvA.valueOff + tlvA.valueLen), out);
            return;
        }

        if (tlvA.tag == TAG_BF45) {
            out.type = TYPE_ZK_REGISTER_CREDENTIAL;
            decodePhase0SingleField(data, tlvA.valueOff, (short) (tlvA.valueOff + tlvA.valueLen), out);
            return;
        }

        if (tlvA.tag == TAG_BF46) {
            out.type = TYPE_ZK_CERT_INIT_REQUEST;
            decodePhase0SingleField(data, tlvA.valueOff, (short) (tlvA.valueOff + tlvA.valueLen), out);
            return;
        }

        if (tlvA.tag == TAG_BF47) {
            out.type = TYPE_ZK_CERT_INIT_COMPLETE;
            decodePhase0SingleField(data, tlvA.valueOff, (short) (tlvA.valueOff + tlvA.valueLen), out);
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
        copyBytes(data, tlvB.valueOff, tlvB.valueLen, out.smdpSignature2);
        out.smdpSignature2Len = tlvB.valueLen;
        pos = (short) (pos + tlvB.totalLen);

        // Optional hashCc OCTET STRING, then mandatory certificate SEQUENCE
        parseTlv(data, pos, end, tlvC);
        if (tlvC.tag == TAG_OCTET_STRING) {
            if (tlvC.valueLen != 32) {
                ISOException.throwIt(SW_ASN1_INVALID);
            }
            pos = (short) (pos + tlvC.totalLen);
            parseTlv(data, pos, end, tlvC);
        }

        if (tlvC.tag != TAG_SEQUENCE) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }

        copyBytes(data, pos, tlvC.totalLen, out.smdpCertificate);
        out.smdpCertificateLen = tlvC.totalLen;

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
        if (tlvB.tag != 0x0001 || tlvB.valueLen != 1) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
        if (data[tlvB.valueOff] != 0x00 && data[tlvB.valueOff] != (byte) 0xFF) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
        out.ccRequiredFlag = data[tlvB.valueOff] != 0;
        pos = (short) (pos + tlvB.totalLen);

        // optional bppEuiccOtpk [APPLICATION 73]
        if (pos < end) {
            parseTlv(data, pos, end, tlvC);
            if (tlvC.tag != TAG_APP_73) {
                ISOException.throwIt(SW_ASN1_INVALID);
            }
            copyBytes(data, tlvC.valueOff, tlvC.valueLen, out.bppEuiccOtpk);
            out.bppEuiccOtpkLen = tlvC.valueLen;
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
        copyBytes(data, tlvB.valueOff, tlvB.valueLen, out.serverSignature1);
        out.serverSignature1Len = tlvB.valueLen;
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
        copyBytes(data, pos, tlvA.totalLen, out.smdpCertificate);
        out.smdpCertificateLen = tlvA.totalLen;
        pos = (short) (pos + tlvA.totalLen);

        // ctxParams1 CHOICE, encoded with context-specific tag [0]
        parseTlv(data, pos, end, tlvB);
        if (tlvB.tag != TAG_A0) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
        short ctxParamsTotalLen = tlvB.totalLen;
        decodeCtxParams1(data, tlvB.valueOff, (short) (tlvB.valueOff + tlvB.valueLen));
        pos = (short) (pos + ctxParamsTotalLen);

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

    private void decodeZKProfileRequest(byte[] data, short off, short end, DecodedMessage out) {
        // ZKProfileRequest ::= BF42 { 80 10 <mnoChallenge> }
        // serverChallenge is repurposed for the MNO challenge.
        // Length validation is intentionally deferred to the handler so that malformed
        // challenges produce a BF42{A1} application-level error (SW=9000) rather than 6A80.
        short pos = off;
        parseTlv(data, pos, end, tlvA);
        if (tlvA.tag != TAG_CTX_0) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
        short copyLen = (tlvA.valueLen < (short) out.serverChallenge.length)
                        ? tlvA.valueLen : (short) out.serverChallenge.length;
        copyBytes(data, tlvA.valueOff, copyLen, out.serverChallenge);
        out.serverChallengeLen = tlvA.valueLen; // preserve real length so handler can check != 16
        pos = (short) (pos + tlvA.totalLen);
        if (pos != end) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
    }

    private void decodeGetEuiccChallengeRequest(byte[] data, short off, short end) {
        // Canonical DER for this request is an empty BF2E value.
        if (off != end) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
    }

    private void decodeCancelSessionRequest(byte[] data, short off, short end, DecodedMessage out) {
        short pos = off;

        parseTlv(data, pos, end, tlvA);
        if (tlvA.tag != TAG_CTX_0 || tlvA.valueLen < 1 || tlvA.valueLen > 16) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
        copyTxId(data, tlvA.valueOff, tlvA.valueLen, out);
        pos = (short) (pos + tlvA.totalLen);

        parseTlv(data, pos, end, tlvB);
        if (tlvB.tag != TAG_CTX_1 || tlvB.valueLen != 1) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
        out.cancelSessionReason = data[tlvB.valueOff];
        pos = (short) (pos + tlvB.totalLen);

        if (pos != end) {
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
        out.bf23SignedStart = tlvA.valueOff;
        short iscTotalLen = tlvA.totalLen;
        decodeInitialiseSecureChannelRequest(data, tlvA.valueOff, (short) (tlvA.valueOff + tlvA.valueLen), out);
        pos = (short) (pos + iscTotalLen);

        // [0] SEQUENCE OF [7] OCTET STRING
        parseTlv(data, pos, end, tlvB);
        if (tlvB.tag != TAG_A0) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
        out.a0Off = pos;
        out.a0Len = tlvB.totalLen;
        validateSequenceOfTaggedOctets(data, tlvB.valueOff, (short) (tlvB.valueOff + tlvB.valueLen), TAG_87);
        pos = (short) (pos + tlvB.totalLen);

        // [1] SEQUENCE OF [8] OCTET STRING
        parseTlv(data, pos, end, tlvC);
        if (tlvC.tag != TAG_A1) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
        out.a1Off = pos;
        out.a1Len = tlvC.totalLen;
        short a1TotalLen = tlvC.totalLen;
        validateSequenceOfTaggedOctets(data, tlvC.valueOff, (short) (tlvC.valueOff + tlvC.valueLen), TAG_88);
        pos = (short) (pos + a1TotalLen);

        // Optional [2] SEQUENCE OF [7] OCTET STRING
        parseTlv(data, pos, end, tlvA);
        if (tlvA.tag == TAG_A2) {
            out.a2Off = pos;
            out.a2Len = tlvA.totalLen;
            validateSequenceOfTaggedOctets(data, tlvA.valueOff, (short) (tlvA.valueOff + tlvA.valueLen), TAG_87);
            pos = (short) (pos + tlvA.totalLen);
            parseTlv(data, pos, end, tlvA);
        }

        // [3] SEQUENCE OF [6] OCTET STRING
        if (tlvA.tag != TAG_A3) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
        out.a3Off = pos;
        out.a3Len = tlvA.totalLen;
        validateSequenceOfTaggedOctets(data, tlvA.valueOff, (short) (tlvA.valueOff + tlvA.valueLen), TAG_86);
        pos = (short) (pos + tlvA.totalLen);

        if (pos != end) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
    }

    private void decodeInitialiseSecureChannelRequest(byte[] data, short off, short end, DecodedMessage out) {
        short pos = off;

        // remoteOpId [2] INTEGER, expected installBoundProfilePackage(1)
        parseTlv(data, pos, end, tlvA);
        if (tlvA.tag != TAG_CTX_2 || tlvA.valueLen < 1 || tlvA.valueLen > 2) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
        if (!isIntegerValueOne(data, tlvA.valueOff, tlvA.valueLen)) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
        out.bf23SignedStart = pos;
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
        short crtTotalLen = tlvC.totalLen;
        out.bf23CrtOff = pos;
        out.bf23CrtLen = crtTotalLen;
        decodeControlRefTemplate(data, tlvC.valueOff, (short) (tlvC.valueOff + tlvC.valueLen), out);
        pos = (short) (pos + crtTotalLen);

        // smdpOtpk [APPLICATION 73]
        parseTlv(data, pos, end, tlvA);
        if (tlvA.tag != TAG_APP_73) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
        out.bf23SmdpOtpkOff = tlvA.valueOff;
        out.bf23SmdpOtpkLen = tlvA.valueLen;
        pos = (short) (pos + tlvA.totalLen);
        out.bf23SignedEnd = pos;

        // smdpSign [APPLICATION 55]
        parseTlv(data, pos, end, tlvB);
        if (tlvB.tag != TAG_APP_55) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
        out.bf23SmdpSignOff = tlvB.valueOff;
        out.bf23SmdpSignLen = tlvB.valueLen;
        pos = (short) (pos + tlvB.totalLen);

        if (pos != end) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
    }

    private void decodeControlRefTemplate(byte[] data, short off, short end, DecodedMessage out) {
        short pos = off;

        parseTlv(data, pos, end, tlvA);
        if (tlvA.tag != TAG_CTX_0 || tlvA.valueLen != 1) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
        pos = (short) (pos + tlvA.totalLen);

        parseTlv(data, pos, end, tlvB);
        if (tlvB.tag != TAG_CTX_1 || tlvB.valueLen != 1) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
        pos = (short) (pos + tlvB.totalLen);

        parseTlv(data, pos, end, tlvC);
        if (tlvC.tag != TAG_CTX_4 || tlvC.valueLen < 1 || tlvC.valueLen > 16) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
        out.hostIdOff = tlvC.valueOff;
        out.hostIdLen = tlvC.valueLen;
        pos = (short) (pos + tlvC.totalLen);

        if (pos != end) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
    }

    private void decodeCtxParams1(byte[] data, short off, short end) {
        short pos = off;

        if (pos >= end) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }

        parseTlv(data, pos, end, tlvA);
        if (tlvA.tag == TAG_CTX_0 || tlvA.tag == TAG_UTF8_STRING) {
            pos = (short) (pos + tlvA.totalLen);
            if (pos >= end) {
                ISOException.throwIt(SW_ASN1_INVALID);
            }
            parseTlv(data, pos, end, tlvA);
        }

        if (tlvA.tag != TAG_A1 && tlvA.tag != TAG_SEQUENCE) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
        short deviceInfoTotalLen = tlvA.totalLen;
        decodeDeviceInfo(data, tlvA.valueOff, (short) (tlvA.valueOff + tlvA.valueLen));
        pos = (short) (pos + deviceInfoTotalLen);

        if (pos != end) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
    }

    private void decodeDeviceInfo(byte[] data, short off, short end) {
        short pos = off;

        parseTlv(data, pos, end, tlvA);
        // In practice TAC/IMEI may be transported as packed BCD digits, so accept
        // the common 4-byte TAC form as well as the 8-byte raw-octet form.
        if ((tlvA.tag != TAG_CTX_0 && tlvA.tag != TAG_OCTET_STRING)
                || (tlvA.valueLen != 4 && tlvA.valueLen != 8)) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
        pos = (short) (pos + tlvA.totalLen);

        parseTlv(data, pos, end, tlvB);
        if (tlvB.tag != TAG_A1 && tlvB.tag != TAG_SEQUENCE) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
        validateDeviceCapabilities(data, tlvB.valueOff, (short) (tlvB.valueOff + tlvB.valueLen));
        pos = (short) (pos + tlvB.totalLen);

        if (pos < end) {
            parseTlv(data, pos, end, tlvC);
            if ((tlvC.tag != TAG_CTX_2 && tlvC.tag != TAG_OCTET_STRING)
                    || (tlvC.valueLen != 4 && tlvC.valueLen != 8)) {
                ISOException.throwIt(SW_ASN1_INVALID);
            }
            pos = (short) (pos + tlvC.totalLen);
        }

        if (pos != end) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
    }

    private void validateDeviceCapabilities(byte[] data, short off, short end) {
        short pos = off;
        short tag;

        while (pos < end) {
            parseTlv(data, pos, end, tlvC);
            tag = tlvC.tag;
            if (tag < (short) 0x0080 || tag > (short) 0x0088 || tlvC.valueLen != 3) {
                ISOException.throwIt(SW_ASN1_INVALID);
            }
            pos = (short) (pos + tlvC.totalLen);
        }

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

    private void decodeSetEligibilityDataRequest(byte[] data, short off, short end, DecodedMessage out) {
        short copyOff = off;
        short copyLen = (short) (end - off);

        // Store the encoded EligibilityData body as an opaque blob.  BF43 may
        // arrive as A0 { 80..85 } from AUTOMATIC TAGS or as 30 { 80..85 } in
        // tests/tools; BF38 later re-tags the same body as A5 without decoding
        // individual fields.
        if (copyLen > 0 && (data[off] == (byte) 0xA0 || data[off] == 0x30)) {
            parseTlv(data, off, end, tlvB);
            if (tlvB.totalLen != copyLen) {
                ISOException.throwIt(SW_ASN1_INVALID);
            }
            copyOff = tlvB.valueOff;
            copyLen = tlvB.valueLen;
        }
        if (copyLen > 0 && data[copyOff] == 0x30) {
            parseTlv(data, copyOff, (short) (copyOff + copyLen), tlvB);
            if (tlvB.totalLen == copyLen) {
                copyOff = tlvB.valueOff;
                copyLen = tlvB.valueLen;
            }
        }

        if (copyLen > (short) out.eligibilityData.length) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
        Util.arrayCopyNonAtomic(data, copyOff, out.eligibilityData, (short) 0, copyLen);
        out.eligibilityDataLen = copyLen;
    }

    private static void copyTxId(byte[] data, short off, short len, DecodedMessage out) {
        out.txIdLen = len;
        Util.arrayCopyNonAtomic(data, off, out.txId, (short) 0, len);
    }

    private static void copyBytes(byte[] data, short off, short len, byte[] out) {
        Util.arrayCopyNonAtomic(data, off, out, (short) 0, len);
    }

    private static boolean isIntegerValueOne(byte[] data, short off, short len) {
        return len == 1 && data[off] == 0x01;
    }

    /**
     * Decode a Phase 0 APDU value containing a single context-tag [0] field.
     * Used by BF44/BF45/BF46/BF47: each carries exactly one 80-tagged payload.
     */
    private void decodePhase0SingleField(byte[] data, short off, short end, DecodedMessage out) {
        short pos = off;
        parseTlv(data, pos, end, tlvA);
        if (tlvA.tag != TAG_CTX_0) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
        if (tlvA.valueLen > (short) out.phase0Data.length) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
        Util.arrayCopyNonAtomic(data, tlvA.valueOff, out.phase0Data, (short) 0, tlvA.valueLen);
        out.phase0DataLen = tlvA.valueLen;
        pos = (short) (pos + tlvA.totalLen);
        if (pos != end) {
            ISOException.throwIt(SW_ASN1_INVALID);
        }
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

            if ((second & 0x80) != 0) {
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
        if ((lenB & 0x80) == 0) {
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

            // DER canonical length checks:
            // - long form must not encode values < 128
            // - first long-form length octet must be non-zero
            if (numLenBytes == 1 && len < 128) {
                ISOException.throwIt(SW_ASN1_INVALID);
            }
            if (numLenBytes == 2 && data[pos] == 0) {
                ISOException.throwIt(SW_ASN1_INVALID);
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
