package zk.esim.applet;

import javacard.framework.*;
public final class ZkEsimApplet extends Applet {

    private static final byte INS_RSP = (byte) 0xE2;
    private static final byte INS_GET_RESPONSE = (byte) 0xC0;
    private static final byte INS_GET_DATA = (byte) 0xCA;

    // Keep this bounded for simulator/card memory constraints while still supporting APDU chaining.
    private static final short MAX_CHUNK_SIZE = (short) 256;
    // Persistent receive buffer for real BoundProfilePackage payloads (~12 KB plus headroom).
    private static final short BPP_BUFFER_LEN = (short) 16384;
    private static final short SW_INVALID_DATA_FIELD = (short) 0x6A80;
    private static final short SW_UNSUPPORTED_COMMAND_DATA = (short) 0x6A88;
    private static final short SW_CONDITIONS_NOT_SATISFIED = (short) 0x6985;
    private static final short SW_REFERENCE_DATA_NOT_FOUND = (short) 0x6A88;
    private static final short TAG_APP_55 = (short) 0x5F37;
    private static final short TAG_APP_73 = (short) 0x5F49;
    private static final short TAG_PERSISTED_BPP_INFO = (short) 0xDF36;
    private static final byte[] DEFAULT_SMDP_OID = {(byte) 0x88, 0x37, 0x0A}; // 2.999.10
    private static final byte[] DEFAULT_NOTIFICATION_ADDRESS = {
            (byte) 's', (byte) 'm', (byte) 'd', (byte) 'p', (byte) '.', (byte) 't',
            (byte) 'e', (byte) 's', (byte) 't', (byte) '.', (byte) 'c', (byte) 'o', (byte) 'm'
    };
    private static final byte[] INSTALL_NOTIFICATION_EVENT = {0x07, (byte) 0x80};
    private static final byte[] INSTALL_RESULT_OK = {0x01};
    private static final byte[] EID_VALUE = {
            (byte) 0x89, 0x04, (byte) 0x90, 0x32, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x12, 0x34, 0x56, 0x78, (byte) 0x90, 0x12
    };
    private static final byte[] DEFAULT_APPLET_AID = {
            (byte) 0xD0, 0x70, 0x02, (byte) 0xCA,
            0x44, (byte) 0x90, 0x01, 0x01
    };
    private static final byte[] CI_PKID_NIST = {
            (byte) 0xF5, 0x41, 0x72, (byte) 0xBD, (byte) 0xF9, (byte) 0x8A,
            (byte) 0x95, (byte) 0xD6, 0x5C, (byte) 0xBE, (byte) 0xB8, (byte) 0x8A,
            0x38, (byte) 0xA1, (byte) 0xC1, 0x1D, (byte) 0x80, 0x0A, (byte) 0x85, (byte) 0xC3
    };
    private static final byte[] SVN = {0x02, 0x04, 0x00};
    private static final byte[] PROFILE_VERSION = {0x02, 0x03, 0x01};
    private static final byte[] EUICC_FIRMWARE_VER = {0x23, 0x06, 0x23};
    private static final byte[] EXT_CARD_RESOURCE = {
        (byte) 0x81, 0x01, 0x00, (byte) 0x82, 0x04, 0x00, 0x04, (byte) 0x9C, 0x68, (byte) 0x83, 0x02, 0x22, 0x23
    };
    // BER BIT STRING payload: first byte is number of unused bits.
    private static final byte[] UICC_CAPABILITY_BITS = {0x00, 0x6B, 0x36, (byte) 0xD3, (byte) 0xC3};
    private static final byte[] JAVACARD_VERSION = {0x11, 0x02, 0x00};
    private static final byte[] GLOBALPLATFORM_VERSION = {0x02, 0x03, 0x00};
    private static final byte[] RSP_CAPABILITY_BITS = {0x02, (byte) 0x9C};
    private static final byte[] PP_VERSION = {0x01, 0x00, 0x00};
    private static final byte[] SAS_ACCREDITATION_NUMBER = {
        (byte) 'O', (byte) 'S', (byte) 'M', (byte) 'O', (byte) 'C', (byte) 'O', (byte) 'M', (byte) '-',
        (byte) 'T', (byte) 'E', (byte) 'S', (byte) 'T', (byte) '-', (byte) '1'
    };
    private static final byte[] DEFAULT_MATCHING_ID = {
        (byte) 'T', (byte) 'S', (byte) '4', (byte) '8', (byte) 'V', (byte) '1', (byte) '-', (byte) 'A', (byte) '-', (byte) 'U', (byte) 'N', (byte) 'I', (byte) 'Q', (byte) 'U', (byte) 'E'
    };
    private static final byte[] DEFAULT_TAC = {0x35, 0x29, 0x06, 0x11, 0x00, 0x00, 0x00, 0x00};
    // MNO identifier used when signing eligibility credentials. Must match
    // pysim/osmo-smdpp.py FIXED_MNOID.
    private static final byte[] MNO_ID = {
        (byte) 'M', (byte) 'N', (byte) 'O', (byte) '_', (byte) 'i', (byte) 'd'
    };
    // Fixed ASCII-encoded Unix timestamp for auth-token expiry.  Both sides
    // hardcode this so the deterministic T_i signature verifies.  Value is
    // 2100-01-01 00:00:00 UTC.
    private static final byte[] FIXED_EXPIRY = {
        (byte) '4', (byte) '1', (byte) '0', (byte) '2', (byte) '4', (byte) '4', (byte) '4', (byte) '8',
        (byte) '0', (byte) '0'
    };
    // Single-leaf accumulator proof is empty: the root equals H(leaf).
    private static final byte[] HARDCODED_ACC_PROOF = {};
    private static final byte BPP_CMD_INITIALISE_SECURE_CHANNEL = 0x00;
    private static final byte BPP_CMD_CONFIGURE_ISDP = 0x01;
    private static final byte BPP_CMD_STORE_METADATA = 0x02;
    private static final byte BPP_CMD_REPLACE_SESSION_KEYS = 0x04;
    private static final byte BPP_CMD_LOAD_PROFILE_ELEMENTS = 0x05;
    private static final byte BPP_ERR_INVALID_SIGNATURE = 0x02;
    private static final byte BPP_ERR_INVALID_TRANSACTION_ID = 0x03;
    private static final byte BPP_ERR_UNSUPPORTED_CRT_VALUES = 0x04;
    private static final byte BPP_ERR_SCP03T_SECURITY = 0x08;
    private static final byte BPP_ERR_UNKNOWN = 0x7F;
    private static final short VERIFY_SEQUENCE_OK = (short) 0x7FFF;
    private static final byte BPP_ASSEMBLY_IDLE = 0x00;
    private static final byte BPP_ASSEMBLY_EXPECT_A0 = 0x01;
    private static final byte BPP_ASSEMBLY_EXPECT_A0_CHILDREN = 0x02;
    private static final byte BPP_ASSEMBLY_EXPECT_A1 = 0x03;
    private static final byte BPP_ASSEMBLY_EXPECT_A1_CHILDREN = 0x04;
    private static final byte BPP_ASSEMBLY_EXPECT_A2_OR_A3 = 0x05;
    private static final byte BPP_ASSEMBLY_EXPECT_A2_CHILDREN = 0x06;
    private static final byte BPP_ASSEMBLY_EXPECT_A3 = 0x07;
    private static final byte BPP_ASSEMBLY_EXPECT_A3_CHILDREN = 0x08;
    private static final class DerTlv {
        short tag;
        short valueOff;
        short valueLen;
        short totalLen;
    }

    // UE attributes
    private static final byte[] EID = {
            (byte) '8', (byte) '9', (byte) '0', (byte) '4', (byte) '9', (byte) '0', (byte) '3', (byte) '2',
            (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0',
            (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '1', (byte) '2', (byte) '3', (byte) '4',
            (byte) '5', (byte) '6', (byte) '7', (byte) '8', (byte) '9', (byte) '0', (byte) '1', (byte) '2'
    };
    private byte[] pid;
    private Crypto crypto;

    private byte[] pubKeyBuf;
    private byte[] sigBuf;
    private byte[] parsedCertPublicKey;
    private final DerTlv derTlvA = new DerTlv();
    private final DerTlv derTlvB = new DerTlv();
    private final DerTlv derTlvC = new DerTlv();

    private Apdu apduHandler;
    private Asn1 asn1;
    private Asn1.DecodedMessage decodedMessage;
    private byte[] assembledApdu;
    private final byte[] euiccChallenge;
    private short euiccChallengeLen;
    private boolean euiccChallengeReady;
    private byte[] sessionTxId;
    private short sessionTxIdLen;
    private boolean sessionActive;
    private byte[] sessionEuiccSignature1;
    private short sessionEuiccSignature1Len;
    private byte[] sessionEuiccOtpk;
    private short sessionEuiccOtpkLen;
    private Apdu.PendingResponse pendingResponse;
    private byte[] euiccCertDer;
    private short euiccCertDerLen;
    private byte[] bppBuffer;
    private short bppLength;
    private boolean bppReceiving;
    private short currentBppPayloadLen;
    private short persistedBppLength;
    private short persistedBppTxIdLen;
    private byte[] persistedBppTxId;
    private byte bppAssemblyState;
    private short bppAssembledLen;
    private short bppExpectedTotalLen;
    private short bppOpenConstructedRemaining;
    private byte[] bspSharedSecret;
    private byte[] bspSEnc;
    private byte[] bspSMac;
    private byte[] bspMcv;
    private short bspBlockNr;
    private byte[] pppSEnc;
    private byte[] pppSMac;
    private byte[] pppMcv;
    private short pppBlockNr;
    private boolean pppKeysReady;

    // Eligibility credentials computed at install time from the real euiccCertificate.
    // Shapes: hpid 32B (SHA256(SHA256(EID))); accRoot 32B (== hpid for single-leaf);
    // sigCred / sigRoot / authToken are raw 64-byte ECDSA r||s.
    private byte[] hpidBuf;
    private byte[] accRootBuf;
    private byte[] sigCredBuf;
    private byte[] sigRootBuf;
    private byte[] authTokenBuf;
    private byte[] accProofBuf;
    private short accProofLen;
    private byte[] encEidBuf;
    private byte[] zkStatementBuf;

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new ZkEsimApplet(bArray, bOffset, bLength);
    }

    private ZkEsimApplet(byte[] bArray, short bOffset, byte bLength) {

        // euiccChallenge must be assigned before registerApplet().
        // Transient (CLEAR_ON_DESELECT): content cleared on deselect, slot persists.
        euiccChallenge = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);

        // Register immediately — nothing after this point may throw.
        registerApplet(bArray, bOffset, bLength);

        pubKeyBuf = JCSystem.makeTransientByteArray((short) 65, JCSystem.CLEAR_ON_DESELECT);
        sigBuf = JCSystem.makeTransientByteArray((short) 80, JCSystem.CLEAR_ON_DESELECT);
        parsedCertPublicKey = JCSystem.makeTransientByteArray((short) 65, JCSystem.CLEAR_ON_DESELECT);
        pid = JCSystem.makeTransientByteArray((short) 48, JCSystem.CLEAR_ON_DESELECT);
        apduHandler = new Apdu();
        assembledApdu = apduHandler.getBuffer();
        asn1 = new Asn1();
        decodedMessage = new Asn1.DecodedMessage();
        pendingResponse = new Apdu.PendingResponse(assembledApdu, MAX_CHUNK_SIZE);
        sessionTxId = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);
        // Keep euiccSignature1 across applet deselects so BF21 verification can
        // still validate SM-DP+ contextual signatures after channel/app reselection.
        sessionEuiccSignature1 = JCSystem.makeTransientByteArray((short) 64, JCSystem.CLEAR_ON_DESELECT);
        sessionEuiccSignature1Len = 0;
        sessionEuiccOtpk = JCSystem.makeTransientByteArray((short) 65, JCSystem.CLEAR_ON_DESELECT);
        sessionEuiccOtpkLen = 0;
        bppBuffer = new byte[BPP_BUFFER_LEN];
        bppLength = 0;
        bppReceiving = false;
        currentBppPayloadLen = 0;
        persistedBppLength = 0;
        persistedBppTxIdLen = 0;
        persistedBppTxId = new byte[16];
        bppAssemblyState = BPP_ASSEMBLY_IDLE;
        bppAssembledLen = 0;
        bppExpectedTotalLen = 0;
        bppOpenConstructedRemaining = 0;
        bspSharedSecret = JCSystem.makeTransientByteArray((short) 65, JCSystem.CLEAR_ON_DESELECT);
        bspSEnc = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);
        bspSMac = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);
        bspMcv = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);
        pppSEnc = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);
        pppSMac = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);
        pppMcv = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);
        crypto = new Crypto();
        crypto.hashEidToPid(EID, pid);

        // Build the self-signed eUICC certificate once at install time and keep it in EEPROM.
        // SM-DP+ (--zk mode) extracts the SPKI to verify euiccSignature1; chain is not walked.
        euiccCertDer = new byte[512];
        euiccCertDerLen = crypto.buildSelfSignedEuiccCert(euiccCertDer, (short) 0);

        // Compute eligibility credentials bound to the real h_cert.  These used to be
        // hardcoded against a stub h_cert = SHA256(30 00); now that we emit a real
        // cert, we sign them at install time with the applet-held MNO private key.
        hpidBuf = new byte[32];
        accRootBuf = new byte[32];
        sigCredBuf = new byte[64];
        sigRootBuf = new byte[64];
        authTokenBuf = new byte[64];
        accProofBuf = new byte[512];
        accProofLen = 0;
        encEidBuf = JCSystem.makeTransientByteArray((short) 81, JCSystem.CLEAR_ON_DESELECT);
        zkStatementBuf = JCSystem.makeTransientByteArray((short) 384, JCSystem.CLEAR_ON_DESELECT);
        computeEligibilityCredentials();
    }

    /**
     * Derive hpid = SHA256(SHA256(EID)) and sign sig_cred, sig_root, auth_tok using
     * the applet-held MNO private key over h_cert = SHA256(euiccCertDer).  All signed
     * payloads mirror Algorithm 5 lines 5, 15, 17, 18 and pysim/osmo-smdpp.py's
     * setupMNOValues so the SM-DP+ side verifies with pk_mno.
     */
    private void computeEligibilityCredentials() {
        // pid = SHA256(EID); hpid = SHA256(pid)
        byte[] pidTmp = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_RESET);
        crypto.sha256Digest(EID, (short) 0, (short) EID.length, pidTmp, (short) 0);
        crypto.sha256Digest(pidTmp, (short) 0, (short) 32, hpidBuf, (short) 0);

        // accRoot == hpid for a single-leaf accumulator (acc_proof is empty).
        Util.arrayCopyNonAtomic(hpidBuf, (short) 0, accRootBuf, (short) 0, (short) 32);
        accProofLen = 0;

        // h_cert = SHA256(euiccCertDer)
        byte[] hCertTmp = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_RESET);
        crypto.sha256Digest(euiccCertDer, (short) 0, euiccCertDerLen, hCertTmp, (short) 0);

        // sig_cred payload = hpid || h_cert || mnoId
        // sig_root payload = accRoot (32 bytes)
        // auth_tok payload = hpid || h_cert || mnoId || expiry
        short maxPayload = (short) (32 + 32 + MNO_ID.length + FIXED_EXPIRY.length);
        byte[] payload = JCSystem.makeTransientByteArray(maxPayload, JCSystem.CLEAR_ON_RESET);
        short pos;

        // sig_cred
        pos = 0;
        Util.arrayCopyNonAtomic(hpidBuf, (short) 0, payload, pos, (short) 32);
        pos = (short) (pos + 32);
        Util.arrayCopyNonAtomic(hCertTmp, (short) 0, payload, pos, (short) 32);
        pos = (short) (pos + 32);
        Util.arrayCopyNonAtomic(MNO_ID, (short) 0, payload, pos, (short) MNO_ID.length);
        pos = (short) (pos + MNO_ID.length);
        signMnoRaw(payload, (short) 0, pos, sigCredBuf, (short) 0);

        // sig_root
        signMnoRaw(accRootBuf, (short) 0, (short) 32, sigRootBuf, (short) 0);

        // auth_tok
        pos = 0;
        Util.arrayCopyNonAtomic(hpidBuf, (short) 0, payload, pos, (short) 32);
        pos = (short) (pos + 32);
        Util.arrayCopyNonAtomic(hCertTmp, (short) 0, payload, pos, (short) 32);
        pos = (short) (pos + 32);
        Util.arrayCopyNonAtomic(MNO_ID, (short) 0, payload, pos, (short) MNO_ID.length);
        pos = (short) (pos + MNO_ID.length);
        Util.arrayCopyNonAtomic(FIXED_EXPIRY, (short) 0, payload, pos, (short) FIXED_EXPIRY.length);
        pos = (short) (pos + FIXED_EXPIRY.length);
        signMnoRaw(payload, (short) 0, pos, authTokenBuf, (short) 0);
    }

    private void signMnoRaw(byte[] data, short off, short len, byte[] rawOut, short rawOff) {
        byte[] derTmp = JCSystem.makeTransientByteArray((short) 80, JCSystem.CLEAR_ON_RESET);
        short derLen = crypto.signWithMno(data, off, len, derTmp, (short) 0);
        derEcdsaToRaw(derTmp, (short) 0, derLen, rawOut, rawOff);
    }

    public boolean select() {
        return true;
    }

    private void registerApplet(byte[] bArray, short bOffset, byte bLength) {
        short totalLen = (short) (bLength & 0xFF);
        if (totalLen > 0 && bArray != null) {
            short aidLenOff = bOffset;
            short aidLen = (short) (bArray[aidLenOff] & 0xFF);
            short aidOff = (short) (aidLenOff + 1);
            short end = (short) (bOffset + totalLen);
            if (aidLen > 0 && (short) (aidOff + aidLen) <= end) {
                register(bArray, aidOff, (byte) aidLen);
                return;
            }
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        register(DEFAULT_APPLET_AID, (short) 0, (byte) DEFAULT_APPLET_AID.length);
    }

    public void process(APDU apdu) {

        if (selectingApplet()) return;

        byte[] buf = apdu.getBuffer();

        byte cla = buf[ISO7816.OFFSET_CLA];
        byte ins = buf[ISO7816.OFFSET_INS];
        byte claNoChain = cla;

        if (ins == INS_GET_RESPONSE) {
            if (!pendingResponse.isActive()) {
                ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
            }
            if (buf[ISO7816.OFFSET_P1] != 0x00 || buf[ISO7816.OFFSET_P2] != 0x00) {
                ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
            }
            pendingResponse.sendChunk(apdu);
            if (!pendingResponse.isActive()) {
                apduHandler.reset();
            }
            return;
        }

        // New command arriving: any un-drained pending response from the previous
        // exchange is abandoned. A compliant T=0 host drains via GET RESPONSE before
        // issuing a new command, but simulators (jCardSim) return 9000 from a partial
        // sendBytesLong and never chain — clearing here keeps the applet responsive.
        if (pendingResponse.isActive()) {
            pendingResponse.clear();
        }

        if (ins == INS_GET_DATA) {
            handleGetData(apdu);
            return;
        }

        if (ins != INS_RSP) {
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }

        // SGP.22 5.7.2 / ES10x Transport Command:
        // CLA SHALL be in range 0x80-0x83 or 0xC0-0xCF.
        if (!Apdu.isTransportCla(claNoChain)) {
            apduHandler.reset();
            resetBppReceiveState();
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        byte ingestResult;
        try {
            if (bppReceiving) {
                ingestResult = apduHandler.ingestInto(apdu, cla, ins, bppBuffer, (short) 0, BPP_BUFFER_LEN);
            } else {
                ingestResult = apduHandler.ingest(apdu, cla, ins);
                if (isBoundProfilePackagePrefix(assembledApdu, apduHandler.getLength())) {
                    copyAssembledBppToPersistentBuffer();
                    bppReceiving = ingestResult == Apdu.RESULT_MORE_SEGMENTS;
                }
            }
        } catch (ISOException e) {
            resetBppReceiveState();
            throw e;
        }

        if (ingestResult == Apdu.RESULT_MORE_SEGMENTS) {
            return;
        }

        byte[] payloadBuffer = assembledApdu;
        short payloadLen = apduHandler.getLength();
        currentBppPayloadLen = 0;
        if (bppReceiving || isBoundProfilePackagePrefix(assembledApdu, payloadLen)) {
            if (!bppReceiving) {
                copyAssembledBppToPersistentBuffer();
            }
            bppLength = payloadLen;
            payloadBuffer = bppBuffer;
            payloadLen = bppLength;
            currentBppPayloadLen = payloadLen;
        }
        if (handlePiecewiseBoundProfilePackage(apdu, payloadBuffer, payloadLen)) {
            apduHandler.reset();
            resetBppReceiveState();
            if (!pendingResponse.isActive()) {
                apduHandler.reset();
                resetBppReceiveState();
            }
            return;
        }

        short decodeReason = 0;
        boolean decodeFailed = false;
        try {
            asn1.decode(payloadBuffer, payloadLen, decodedMessage);
        } catch (ISOException ex) {
            decodeFailed = true;
            decodeReason = ex.getReason();
        } catch (Throwable t) {
            decodeFailed = true;
            decodeReason = SW_INVALID_DATA_FIELD;
        }
        apduHandler.reset();
        resetBppReceiveState();
        if (decodeFailed) {
            if (decodeReason == SW_UNSUPPORTED_COMMAND_DATA) {
                ISOException.throwIt(SW_UNSUPPORTED_COMMAND_DATA);
            }
            ISOException.throwIt(SW_INVALID_DATA_FIELD);
        }

        if (decodedMessage.type == Asn1.TYPE_GET_EUICC_CHALLENGE_REQUEST) {
            handleGetEuiccChallenge(apdu);
        } else if (decodedMessage.type == Asn1.TYPE_GET_EUICC_INFO1_REQUEST) {
            handleGetEuiccInfo1(apdu);
        } else if (decodedMessage.type == Asn1.TYPE_PREPARE_DOWNLOAD_REQUEST) {
            handlePrepareDownload(apdu);
        } else if (decodedMessage.type == Asn1.TYPE_AUTHENTICATE_SERVER_REQUEST) {
            handleAuthenticateServer(apdu);
        } else if (decodedMessage.type == Asn1.TYPE_CANCEL_SESSION_REQUEST) {
            handleCancelSession(apdu);
        } else if (decodedMessage.type == Asn1.TYPE_ZK_PROFILE_REQUEST) {
            handleZkProfileRequest(apdu);
        } else if (decodedMessage.type == Asn1.TYPE_SET_ELIGIBILITY_DATA_REQUEST) {
            handleSetEligibilityData(apdu, payloadBuffer);
        } else if (decodedMessage.type == Asn1.TYPE_BOUND_PROFILE_PACKAGE) {
            handleLoadBoundProfilePackage(apdu);
        } else {
            ISOException.throwIt(SW_UNSUPPORTED_COMMAND_DATA);
        }

        if (!pendingResponse.isActive()) {
            apduHandler.reset();
            resetBppReceiveState();
        }
    }

    private void stageAndSendResponse(APDU apdu, short len) {
        pendingResponse.stageAndSend(apdu, len);
    }

    private void handleGetData(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short p1p2 = Util.getShort(buf, ISO7816.OFFSET_P1);
        short responseLen = 0;

        if (p1p2 == TAG_PERSISTED_BPP_INFO) {
            if (persistedBppLength <= 0) {
                ISOException.throwIt(SW_REFERENCE_DATA_NOT_FOUND);
            }
            responseLen = buildPersistedBppInfoResponse(assembledApdu, (short) 0);
        } else {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }
        stageAndSendResponse(apdu, responseLen);
    }

    private void handleGetEuiccChallenge(APDU apdu) {
        crypto.fillRandom(euiccChallenge, (short) 0, (short) euiccChallenge.length);
        euiccChallengeLen = (short) euiccChallenge.length;
        euiccChallengeReady = true;

        short responseLen = buildGetEuiccChallengeResponse(assembledApdu, (short) 0);
        stageAndSendResponse(apdu, responseLen);
    }

    private void handleGetEuiccInfo1(APDU apdu) {
        short responseLen = buildGetEuiccInfo1Response(assembledApdu, (short) 0);
        stageAndSendResponse(apdu, responseLen);
    }

    private void handleZkProfileRequest(APDU apdu) {
        if (decodedMessage.mnoChallengeLen != 16) {
            sendZkProfileError(apdu, (byte) 0x01);
            return;
        }

        try {
            crypto.computePid(EID, (short) 0, (short) EID.length,
                    decodedMessage.mnoChallenge, (short) 0, pid, (short) 0);
            crypto.encryptEidEcies(Crypto.LEA_PUBLIC_KEY, (short) 0, EID_VALUE, (short) 0, encEidBuf, (short) 0);
            short responseLen = buildZkProfileResponse(assembledApdu, (short) 0);
            stageAndSendResponse(apdu, responseLen);
        } catch (CardRuntimeException e) {
            if (e instanceof ISOException) {
                throw (ISOException) e;
            }
            sendZkProfileError(apdu, (byte) 0x02);
        } catch (Throwable t) {
            sendZkProfileError(apdu, (byte) 0x02);
        }
    }

    private void handleSetEligibilityData(APDU apdu, byte[] requestBuf) {
        if (decodedMessage.accProofLen > (short) accProofBuf.length) {
            sendSetEligibilityError(apdu, (byte) 0x02);
            return;
        }

        Util.arrayCopyNonAtomic(requestBuf, decodedMessage.hpidOff, hpidBuf, (short) 0, (short) 32);
        Util.arrayCopyNonAtomic(requestBuf, decodedMessage.sigCredOff, sigCredBuf, (short) 0, (short) 64);
        Util.arrayCopyNonAtomic(requestBuf, decodedMessage.authTokenOff, authTokenBuf, (short) 0, (short) 64);
        Util.arrayCopyNonAtomic(requestBuf, decodedMessage.accRootOff, accRootBuf, (short) 0, (short) 32);
        Util.arrayCopyNonAtomic(requestBuf, decodedMessage.sigRootOff, sigRootBuf, (short) 0, (short) 64);
        Util.arrayCopyNonAtomic(requestBuf, decodedMessage.accProofOff, accProofBuf, (short) 0, decodedMessage.accProofLen);
        accProofLen = decodedMessage.accProofLen;

        short responseLen = buildSetEligibilityOk(assembledApdu, (short) 0);
        stageAndSendResponse(apdu, responseLen);
    }

    private void handlePrepareDownload(APDU apdu) {
        try {
            rememberSessionTxId(decodedMessage.txId, decodedMessage.txIdLen);
            if (!setSmdpPbPublicKeyFromCertificate(decodedMessage.smdpCertificate, decodedMessage.smdpCertificateLen)) {
                sendPrepareDownloadError(apdu, decodedMessage.txId, decodedMessage.txIdLen, (short) 0x01);
                return;
            }
            if (!verifyPrepareDownloadSignature()) {
                sendPrepareDownloadError(apdu, decodedMessage.txId, decodedMessage.txIdLen, (short) 0x02);
                return;
            }
            sessionEuiccOtpkLen = crypto.generateEuiccOtpk(sessionEuiccOtpk, (short) 0);
            short responseLen = buildPrepareDownloadResponse(assembledApdu, (short) 0, decodedMessage.txId, decodedMessage.txIdLen);
            stageAndSendResponse(apdu, responseLen);
        } catch (CardRuntimeException e) {
            if (e instanceof ISOException) {
                throw (ISOException) e;
            }
            sendPrepareDownloadError(apdu, decodedMessage.txId, decodedMessage.txIdLen, (short) 0x01);
        } catch (Throwable t) {
            sendPrepareDownloadError(apdu, decodedMessage.txId, decodedMessage.txIdLen, (short) 0x01);
        }
    }

    private void handleAuthenticateServer(APDU apdu) {
        if (!euiccChallengeReady || decodedMessage.euiccChallengeLen != euiccChallengeLen ||
            !ByteArrayUtil.equals(decodedMessage.euiccChallenge, (short) 0, euiccChallenge, (short) 0, euiccChallengeLen)) {
            sendAuthenticateServerError(apdu, decodedMessage.txId, decodedMessage.txIdLen, (short) 0x06);
            return;
        }

        if (!setSmdpAuthPublicKeyFromCertificate(decodedMessage.smdpCertificate, decodedMessage.smdpCertificateLen)) {
            sendAuthenticateServerError(apdu, decodedMessage.txId, decodedMessage.txIdLen, (short) 0x01);
            return;
        }

        if (!verifyAuthenticateServerSignature()) {
            sendAuthenticateServerError(apdu, decodedMessage.txId, decodedMessage.txIdLen, (short) 0x02);
            return;
        }

        Util.arrayCopyNonAtomic(decodedMessage.txId, (short) 0, sessionTxId, (short) 0, decodedMessage.txIdLen);
        sessionTxIdLen = decodedMessage.txIdLen;
        sessionActive = true;

        short responseLen = buildAuthenticateServerResponse(
            assembledApdu,
            (short) 0,
            decodedMessage.txId,
            decodedMessage.txIdLen,
            decodedMessage.serverAddress,
            decodedMessage.serverAddressLen,
            decodedMessage.serverChallenge,
            decodedMessage.serverChallengeLen
        );
        stageAndSendResponse(apdu, responseLen);
    }

    private void handleCancelSession(APDU apdu) {
        if (!sessionActive || decodedMessage.txIdLen != sessionTxIdLen ||
                !ByteArrayUtil.equals(decodedMessage.txId, (short) 0, sessionTxId, (short) 0, sessionTxIdLen)) {
            sendCancelSessionError(apdu, (byte) 0x05);
            return;
        }

        short responseLen = buildCancelSessionResponse(assembledApdu, (short) 0, decodedMessage.txId, decodedMessage.txIdLen,
                decodedMessage.cancelSessionReason);
        clearSessionState();
        stageAndSendResponse(apdu, responseLen);
    }

    private void handleLoadBoundProfilePackage(APDU apdu) {
        short responseLen;
        byte failedCommandId = BPP_CMD_INITIALISE_SECURE_CHANNEL;
        byte errorReason = BPP_ERR_UNKNOWN;
        short sharedSecretLen = 0;
        boolean terminateSession = false;

        try {
            if (!sessionActive || sessionEuiccOtpkLen <= 0
                    || decodedMessage.txIdLen != sessionTxIdLen
                    || !ByteArrayUtil.equals(decodedMessage.txId, (short) 0, sessionTxId, (short) 0, sessionTxIdLen)) {
                errorReason = BPP_ERR_INVALID_TRANSACTION_ID;
                responseLen = buildProfileInstallationError(assembledApdu, (short) 0,
                        decodedMessage.txId, decodedMessage.txIdLen, failedCommandId, errorReason);
            } else if (!verifyLoadBppSignature(bppBuffer)) {
                errorReason = BPP_ERR_INVALID_SIGNATURE;
                responseLen = buildProfileInstallationError(assembledApdu, (short) 0,
                        decodedMessage.txId, decodedMessage.txIdLen, failedCommandId, errorReason);
            } else {
                sharedSecretLen = crypto.computeBspSharedSecret(bppBuffer, decodedMessage.bf23SmdpOtpkOff,
                        decodedMessage.bf23SmdpOtpkLen, bspSharedSecret, (short) 0);
                if (!deriveLoadBppSessionKeys(bppBuffer, sharedSecretLen)) {
                    errorReason = BPP_ERR_UNSUPPORTED_CRT_VALUES;
                    responseLen = buildProfileInstallationError(assembledApdu, (short) 0,
                            decodedMessage.txId, decodedMessage.txIdLen, failedCommandId, errorReason);
                } else {
                    short verifyResult = verifyLoadBppProtectedSequences(bppBuffer);
                    if (verifyResult != VERIFY_SEQUENCE_OK) {
                        failedCommandId = (byte) verifyResult;
                        errorReason = BPP_ERR_SCP03T_SECURITY;
                        responseLen = buildProfileInstallationError(assembledApdu, (short) 0,
                                decodedMessage.txId, decodedMessage.txIdLen, failedCommandId, errorReason);
                    } else {
                        persistVerifiedBpp(decodedMessage.txId, decodedMessage.txIdLen);
                        responseLen = buildProfileInstallationResult(assembledApdu, (short) 0,
                                decodedMessage.txId, decodedMessage.txIdLen);
                        terminateSession = true;
                    }
                }
            }
        } catch (Throwable t) {
            responseLen = buildProfileInstallationError(assembledApdu, (short) 0,
                    decodedMessage.txId, decodedMessage.txIdLen, failedCommandId, BPP_ERR_UNKNOWN);
        }

        if (terminateSession) {
            clearSessionState();
        } else {
            clearLoadBoundProfilePackageState();
        }
        stageAndSendResponse(apdu, responseLen);
    }

    private void rememberSessionTxId(byte[] txId, short txIdLen) {
        if (txId == null || txIdLen <= 0) {
            return;
        }

        Util.arrayCopyNonAtomic(txId, (short) 0, sessionTxId, (short) 0, txIdLen);
        sessionTxIdLen = txIdLen;
        sessionActive = true;
    }

    private void clearSessionState() {
        clearLoadBoundProfilePackageState();
        euiccChallengeReady = false;
        euiccChallengeLen = 0;
        sessionTxIdLen = 0;
        sessionActive = false;
        sessionEuiccSignature1Len = 0;
        sessionEuiccOtpkLen = 0;
        crypto.resetEuiccOtpk();
        crypto.resetSmdpPbPublicKey();
        crypto.resetSmdpAuthPublicKey();
        Util.arrayFillNonAtomic(euiccChallenge, (short) 0, (short) euiccChallenge.length, (byte) 0x00);
        Util.arrayFillNonAtomic(sessionTxId, (short) 0, (short) sessionTxId.length, (byte) 0x00);
        Util.arrayFillNonAtomic(sessionEuiccSignature1, (short) 0, (short) sessionEuiccSignature1.length, (byte) 0x00);
        Util.arrayFillNonAtomic(sessionEuiccOtpk, (short) 0, (short) sessionEuiccOtpk.length, (byte) 0x00);
    }

    private void clearLoadBoundProfilePackageState() {
        Util.arrayFillNonAtomic(bspSharedSecret, (short) 0, (short) bspSharedSecret.length, (byte) 0x00);
        Util.arrayFillNonAtomic(bspSEnc, (short) 0, (short) bspSEnc.length, (byte) 0x00);
        Util.arrayFillNonAtomic(bspSMac, (short) 0, (short) bspSMac.length, (byte) 0x00);
        Util.arrayFillNonAtomic(bspMcv, (short) 0, (short) bspMcv.length, (byte) 0x00);
        Util.arrayFillNonAtomic(pppSEnc, (short) 0, (short) pppSEnc.length, (byte) 0x00);
        Util.arrayFillNonAtomic(pppSMac, (short) 0, (short) pppSMac.length, (byte) 0x00);
        Util.arrayFillNonAtomic(pppMcv, (short) 0, (short) pppMcv.length, (byte) 0x00);
        bspBlockNr = 0;
        pppBlockNr = 0;
        pppKeysReady = false;
        currentBppPayloadLen = 0;
        resetBppReceiveState();
        resetPiecewiseBppAssembly();
    }

    private void resetBppReceiveState() {
        bppLength = 0;
        bppReceiving = false;
    }

    private void persistVerifiedBpp(byte[] txId, short txIdLen) {
        persistedBppLength = currentBppPayloadLen;
        persistedBppTxIdLen = txIdLen;
        if (txIdLen > 0) {
            Util.arrayCopyNonAtomic(txId, (short) 0, persistedBppTxId, (short) 0, txIdLen);
        }
        if (txIdLen < persistedBppTxId.length) {
            Util.arrayFillNonAtomic(persistedBppTxId, txIdLen,
                    (short) (persistedBppTxId.length - txIdLen), (byte) 0x00);
        }
    }

    private void failBppAssembly() {
        resetPiecewiseBppAssembly();
        ISOException.throwIt(SW_INVALID_DATA_FIELD);
    }

    private boolean isBoundProfilePackagePrefix(byte[] data, short len) {
        return len >= 2 && data[0] == (byte) 0xBF && data[1] == 0x36;
    }

    private boolean handlePiecewiseBoundProfilePackage(APDU apdu, byte[] payload, short payloadLen) {
        short topLevelTag;

        if (payload == null || payloadLen <= 0) {
            return false;
        }

        topLevelTag = peekDerTag(payload, (short) 0, payloadLen);
        if (bppAssemblyState == BPP_ASSEMBLY_IDLE) {
            if (topLevelTag != (short) 0xBF36) {
                return false;
            }
            if (!parseDerHeader(payload, (short) 0, payloadLen, derTlvA)) {
                failBppAssembly();
            }
            if (payloadLen == derTlvA.totalLen) {
                return false;
            }
            if (!parseDerTlv(payload, derTlvA.valueOff, payloadLen, derTlvB)
                    || derTlvB.tag != (short) 0xBF23
                    || (short) (derTlvB.valueOff + derTlvB.valueLen) != payloadLen) {
                failBppAssembly();
            }

            resetPiecewiseBppAssembly();
            appendToPiecewiseBpp(payload, (short) 0, payloadLen);
            bppExpectedTotalLen = derTlvA.totalLen;
            bppAssemblyState = BPP_ASSEMBLY_EXPECT_A0;
            return true;
        }

        switch (bppAssemblyState) {
            case BPP_ASSEMBLY_EXPECT_A0:
                appendSequenceOf87Start(payload, payloadLen, (short) 0xA0,
                        BPP_ASSEMBLY_EXPECT_A1, BPP_ASSEMBLY_EXPECT_A0_CHILDREN);
                return true;
            case BPP_ASSEMBLY_EXPECT_A0_CHILDREN:
                appendProtectedChild(payload, payloadLen, (short) 0x87);
                if (bppOpenConstructedRemaining == 0) {
                    bppAssemblyState = BPP_ASSEMBLY_EXPECT_A1;
                }
                return true;
            case BPP_ASSEMBLY_EXPECT_A1:
                appendConstructedHeaderOnly(payload, payloadLen, (short) 0xA1,
                        BPP_ASSEMBLY_EXPECT_A2_OR_A3, BPP_ASSEMBLY_EXPECT_A1_CHILDREN);
                return true;
            case BPP_ASSEMBLY_EXPECT_A1_CHILDREN:
                appendProtectedChild(payload, payloadLen, (short) 0x88);
                if (bppOpenConstructedRemaining == 0) {
                    bppAssemblyState = BPP_ASSEMBLY_EXPECT_A2_OR_A3;
                }
                return true;
            case BPP_ASSEMBLY_EXPECT_A2_OR_A3:
                if (topLevelTag == (short) 0xA2) {
                    appendSequenceOf87Start(payload, payloadLen, (short) 0xA2,
                            BPP_ASSEMBLY_EXPECT_A3, BPP_ASSEMBLY_EXPECT_A2_CHILDREN);
                    return true;
                }
                if (topLevelTag == (short) 0xA3) {
                    appendConstructedHeaderOnly(payload, payloadLen, (short) 0xA3,
                            BPP_ASSEMBLY_IDLE, BPP_ASSEMBLY_EXPECT_A3_CHILDREN);
                    if (bppAssemblyState == BPP_ASSEMBLY_IDLE) {
                        finalizePiecewiseBoundProfilePackage(apdu);
                    }
                    return true;
                }
                resetPiecewiseBppAssembly();
                ISOException.throwIt(SW_INVALID_DATA_FIELD);
                return true;
            case BPP_ASSEMBLY_EXPECT_A2_CHILDREN:
                appendProtectedChild(payload, payloadLen, (short) 0x87);
                if (bppOpenConstructedRemaining == 0) {
                    bppAssemblyState = BPP_ASSEMBLY_EXPECT_A3;
                }
                return true;
            case BPP_ASSEMBLY_EXPECT_A3:
                appendConstructedHeaderOnly(payload, payloadLen, (short) 0xA3,
                        BPP_ASSEMBLY_IDLE, BPP_ASSEMBLY_EXPECT_A3_CHILDREN);
                if (bppAssemblyState == BPP_ASSEMBLY_IDLE) {
                    finalizePiecewiseBoundProfilePackage(apdu);
                }
                return true;
            case BPP_ASSEMBLY_EXPECT_A3_CHILDREN:
                appendProtectedChild(payload, payloadLen, (short) 0x86);
                if (bppOpenConstructedRemaining == 0) {
                    bppAssemblyState = BPP_ASSEMBLY_IDLE;
                    finalizePiecewiseBoundProfilePackage(apdu);
                }
                return true;
            default:
                resetPiecewiseBppAssembly();
                ISOException.throwIt(SW_INVALID_DATA_FIELD);
                return true;
        }
    }

    private void finalizePiecewiseBoundProfilePackage(APDU apdu) {
        short decodeReason = 0;
        boolean decodeFailed = false;

        if (bppExpectedTotalLen <= 0 || bppAssembledLen != bppExpectedTotalLen) {
            failBppAssembly();
        }

        currentBppPayloadLen = bppAssembledLen;
        bppLength = bppAssembledLen;
        try {
            asn1.decode(bppBuffer, bppAssembledLen, decodedMessage);
        } catch (ISOException ex) {
            decodeFailed = true;
            decodeReason = ex.getReason();
        } catch (Throwable t) {
            decodeFailed = true;
            decodeReason = SW_INVALID_DATA_FIELD;
        }
        resetPiecewiseBppAssembly();
        if (decodeFailed) {
            if (decodeReason == SW_UNSUPPORTED_COMMAND_DATA) {
                ISOException.throwIt(SW_UNSUPPORTED_COMMAND_DATA);
            }
            ISOException.throwIt(SW_INVALID_DATA_FIELD);
        }

        if (decodedMessage.type != Asn1.TYPE_BOUND_PROFILE_PACKAGE) {
            ISOException.throwIt(SW_INVALID_DATA_FIELD);
        }
        handleLoadBoundProfilePackage(apdu);
    }

    private void appendCompleteConstructed(byte[] payload, short payloadLen, short expectedTag) {
        if (!parseDerTlv(payload, (short) 0, payloadLen, derTlvA)
                || derTlvA.tag != expectedTag
                || derTlvA.totalLen != payloadLen) {
            failBppAssembly();
        }
        appendToPiecewiseBpp(payload, (short) 0, payloadLen);
    }

    private void appendSequenceOf87Start(byte[] payload, short payloadLen, short expectedTag,
                                         byte nextStateWhenDone, byte nextStateWhenChildren) {
        short firstChildTotalLen;
        short consumedChildrenLen;

        if (!parseDerHeader(payload, (short) 0, payloadLen, derTlvA) || derTlvA.tag != expectedTag) {
            failBppAssembly();
        }

        if (payloadLen <= derTlvA.valueOff) {
            failBppAssembly();
        }

        if (!parseDerTlv(payload, derTlvA.valueOff, payloadLen, derTlvB) || derTlvB.tag != (short) 0x87) {
            failBppAssembly();
        }

        firstChildTotalLen = derTlvB.totalLen;
        if (payloadLen != (short) (derTlvA.valueOff + firstChildTotalLen)) {
            failBppAssembly();
        }

        consumedChildrenLen = firstChildTotalLen;
        appendToPiecewiseBpp(payload, (short) 0, payloadLen);
        bppOpenConstructedRemaining = (short) (derTlvA.valueLen - consumedChildrenLen);
        if (bppOpenConstructedRemaining == 0) {
            bppAssemblyState = nextStateWhenDone;
        } else {
            bppAssemblyState = nextStateWhenChildren;
        }
    }

    private void appendConstructedHeaderOnly(byte[] payload, short payloadLen, short expectedTag,
                                             byte nextStateWhenEmpty, byte nextStateWhenChildren) {
        if (!parseDerHeader(payload, (short) 0, payloadLen, derTlvA) || derTlvA.tag != expectedTag) {
            failBppAssembly();
        }

        if (payloadLen != derTlvA.valueOff) {
            failBppAssembly();
        }

        appendToPiecewiseBpp(payload, (short) 0, payloadLen);
        bppOpenConstructedRemaining = derTlvA.valueLen;
        if (bppOpenConstructedRemaining == 0) {
            bppAssemblyState = nextStateWhenEmpty;
        } else {
            bppAssemblyState = nextStateWhenChildren;
        }
    }

    private void appendProtectedChild(byte[] payload, short payloadLen, short expectedChildTag) {
        if (bppOpenConstructedRemaining <= 0) {
            failBppAssembly();
        }

        if (!parseDerTlv(payload, (short) 0, payloadLen, derTlvA)
                || derTlvA.tag != expectedChildTag
                || derTlvA.totalLen != payloadLen
                || payloadLen > bppOpenConstructedRemaining) {
            failBppAssembly();
        }

        appendToPiecewiseBpp(payload, (short) 0, payloadLen);
        bppOpenConstructedRemaining = (short) (bppOpenConstructedRemaining - payloadLen);
    }

    private void appendToPiecewiseBpp(byte[] src, short off, short len) {
        if (len < 0 || (short) (bppAssembledLen + len) > BPP_BUFFER_LEN) {
            resetPiecewiseBppAssembly();
            ISOException.throwIt(ISO7816.SW_FILE_FULL);
        }
        Util.arrayCopyNonAtomic(src, off, bppBuffer, bppAssembledLen, len);
        bppAssembledLen = (short) (bppAssembledLen + len);
    }

    private void resetPiecewiseBppAssembly() {
        bppAssemblyState = BPP_ASSEMBLY_IDLE;
        bppAssembledLen = 0;
        bppExpectedTotalLen = 0;
        bppOpenConstructedRemaining = 0;
    }

    private void copyAssembledBppToPersistentBuffer() {
        short length = apduHandler.getLength();
        if (length > BPP_BUFFER_LEN) {
            ISOException.throwIt(ISO7816.SW_FILE_FULL);
        }
        Util.arrayCopyNonAtomic(assembledApdu, (short) 0, bppBuffer, (short) 0, length);
        bppLength = length;
    }

    private boolean verifyPrepareDownloadSignature() {
        if (!crypto.hasSmdpPbPublicKey()) {
            return false;
        }
        short pos = 0;
        assembledApdu[pos++] = 0x30;
        short lenPos = pos++;

        pos = TlvWriter.appendTlv(assembledApdu, pos, (short) 0x80, decodedMessage.txId, (short) 0, decodedMessage.txIdLen);
        assembledApdu[pos++] = 0x01;
        assembledApdu[pos++] = 0x01;
        assembledApdu[pos++] = decodedMessage.ccRequiredFlag ? (byte) 0xFF : 0x00;

        if (decodedMessage.bppEuiccOtpkLen > 0) {
            pos = TlvWriter.appendTlv(assembledApdu, pos, TAG_APP_73, decodedMessage.bppEuiccOtpk, (short) 0, decodedMessage.bppEuiccOtpkLen);
        }

        assembledApdu[lenPos] = (byte) (pos - lenPos - 1);

        // Live SM-DP+ signs smdpSigned2 along with the euiccSignature1 DO from BF38.
        assembledApdu[pos++] = 0x5F;
        assembledApdu[pos++] = 0x37;
        assembledApdu[pos++] = (byte) (sessionEuiccSignature1Len & 0xFF);
        Util.arrayCopyNonAtomic(sessionEuiccSignature1, (short) 0, assembledApdu, pos, sessionEuiccSignature1Len);
        pos = (short) (pos + sessionEuiccSignature1Len);
        return crypto.verifySignature(crypto.getSmdpPbPublicKey(), assembledApdu, (short) 0, pos,
                decodedMessage.smdpSignature2, (short) 0, decodedMessage.smdpSignature2Len);
    }

    private boolean verifyLoadBppSignature(byte[] bpp) {
        short signedPartLen;
        short pos;

        if (!crypto.hasSmdpPbPublicKey()) {
            return false;
        }
        if (sessionEuiccOtpkLen <= 0 || decodedMessage.bf23SignedEnd <= decodedMessage.bf23SignedStart) {
            return false;
        }

        signedPartLen = (short) (decodedMessage.bf23SignedEnd - decodedMessage.bf23SignedStart);
        Util.arrayCopyNonAtomic(bpp, decodedMessage.bf23SignedStart, assembledApdu, (short) 0, signedPartLen);
        pos = signedPartLen;
        pos = TlvWriter.appendTlv(assembledApdu, pos, TAG_APP_73, sessionEuiccOtpk, (short) 0, sessionEuiccOtpkLen);
        return crypto.verifySignature(crypto.getSmdpPbPublicKey(), assembledApdu, (short) 0, pos,
                bpp, decodedMessage.bf23SmdpSignOff, decodedMessage.bf23SmdpSignLen);
    }

    private boolean deriveLoadBppSessionKeys(byte[] bpp, short sharedSecretLen) {
        short crtEnd = (short) (decodedMessage.bf23CrtOff + decodedMessage.bf23CrtLen);
        short pos;
        short innerEnd;
        byte keyType;
        byte keyLen;
        short hostIdLen;

        if (!parseDerTlv(bpp, decodedMessage.bf23CrtOff, crtEnd, derTlvA)
                || derTlvA.tag != (short) 0xA6
                || derTlvA.totalLen != decodedMessage.bf23CrtLen) {
            return false;
        }

        pos = derTlvA.valueOff;
        innerEnd = (short) (derTlvA.valueOff + derTlvA.valueLen);

        if (!parseDerTlv(bpp, pos, innerEnd, derTlvB) || derTlvB.tag != (short) 0x80 || derTlvB.valueLen != 1) {
            return false;
        }
        keyType = bpp[derTlvB.valueOff];
        pos = (short) (pos + derTlvB.totalLen);

        if (!parseDerTlv(bpp, pos, innerEnd, derTlvC) || derTlvC.tag != (short) 0x81 || derTlvC.valueLen != 1) {
            return false;
        }
        keyLen = bpp[derTlvC.valueOff];
        pos = (short) (pos + derTlvC.totalLen);

        if (!parseDerTlv(bpp, pos, innerEnd, derTlvC) || derTlvC.tag != (short) 0x84 || derTlvC.valueLen <= 0) {
            return false;
        }
        hostIdLen = derTlvC.valueLen;
        pos = (short) (pos + derTlvC.totalLen);

        if (pos != innerEnd
                || keyType != (byte) 0x88
                || keyLen != 0x10
                || decodedMessage.hostIdLen <= 0
                || hostIdLen != decodedMessage.hostIdLen
                || !ByteArrayUtil.equals(bpp, derTlvC.valueOff, bpp, decodedMessage.hostIdOff, decodedMessage.hostIdLen)) {
            return false;
        }

        if (sharedSecretLen <= 0) {
            return false;
        }

        crypto.deriveBspKeys(bspSharedSecret, (short) 0, sharedSecretLen,
                keyType, keyLen,
                bpp, derTlvC.valueOff, hostIdLen,
                EID_VALUE, (short) 0, (short) EID_VALUE.length,
                bspSEnc, (short) 0,
                bspSMac, (short) 0,
                bspMcv, (short) 0);
        bspBlockNr = 1;
        pppBlockNr = 0;
        pppKeysReady = false;
        return true;
    }

    private short verifyLoadBppProtectedSequences(byte[] bpp) {
        short verifyResult = verifyProtectedSequence(bpp, decodedMessage.a0Off, decodedMessage.a0Len,
                (short) 0xA0, (short) 0x87, BPP_CMD_CONFIGURE_ISDP, bspSMac, bspMcv, false);
        if (verifyResult != VERIFY_SEQUENCE_OK) {
            return verifyResult;
        }

        verifyResult = verifyProtectedSequence(bpp, decodedMessage.a1Off, decodedMessage.a1Len,
                (short) 0xA1, (short) 0x88, BPP_CMD_STORE_METADATA, bspSMac, bspMcv, false);
        if (verifyResult != VERIFY_SEQUENCE_OK) {
            return verifyResult;
        }

        if (decodedMessage.a2Len > 0) {
            verifyResult = processReplaceSessionKeys(bpp, decodedMessage.a2Off, decodedMessage.a2Len);
            if (verifyResult != VERIFY_SEQUENCE_OK) {
                return verifyResult;
            }
        }

        if (pppKeysReady) {
            return verifyProtectedSequence(bpp, decodedMessage.a3Off, decodedMessage.a3Len,
                    (short) 0xA3, (short) 0x86, BPP_CMD_LOAD_PROFILE_ELEMENTS, pppSMac, pppMcv, true);
        }

        return verifyProtectedSequence(bpp, decodedMessage.a3Off, decodedMessage.a3Len,
                (short) 0xA3, (short) 0x86, BPP_CMD_LOAD_PROFILE_ELEMENTS, bspSMac, bspMcv, false);
    }

    private short verifyProtectedSequence(byte[] bpp, short seqOff, short seqLen,
                                          short expectedOuterTag, short expectedInnerTag,
                                          byte commandId, byte[] sMac, byte[] mcv, boolean usePppState) {
        short pos;
        short end;

        if (seqLen <= 0) {
            return VERIFY_SEQUENCE_OK;
        }

        if (!parseDerTlv(bpp, seqOff, (short) (seqOff + seqLen), derTlvA)
                || derTlvA.tag != expectedOuterTag
                || derTlvA.totalLen != seqLen) {
            return commandId;
        }

        pos = derTlvA.valueOff;
        end = (short) (derTlvA.valueOff + derTlvA.valueLen);
        while (pos < end) {
            if (!parseDerTlv(bpp, pos, end, derTlvB)
                    || derTlvB.tag != expectedInnerTag) {
                return commandId;
            }
            if (!crypto.verifyBspSegment(bpp, pos, derTlvB.totalLen, sMac, (short) 0, mcv, (short) 0)) {
                return commandId;
            }
            if (usePppState) {
                pppBlockNr++;
            } else {
                bspBlockNr++;
            }
            pos = (short) (pos + derTlvB.totalLen);
        }

        if (pos != end) {
            return commandId;
        }
        return VERIFY_SEQUENCE_OK;
    }

    private short processReplaceSessionKeys(byte[] bpp, short seqOff, short seqLen) {
        short pos;
        short end;
        short plaintextLen = 0;
        short childPlainLen;

        if (seqLen <= 0) {
            return VERIFY_SEQUENCE_OK;
        }

        if (!parseDerTlv(bpp, seqOff, (short) (seqOff + seqLen), derTlvA)
                || derTlvA.tag != (short) 0xA2
                || derTlvA.totalLen != seqLen) {
            return BPP_CMD_REPLACE_SESSION_KEYS;
        }

        pos = derTlvA.valueOff;
        end = (short) (derTlvA.valueOff + derTlvA.valueLen);
        while (pos < end) {
            if (!parseDerTlv(bpp, pos, end, derTlvB)
                    || derTlvB.tag != (short) 0x87
                    || derTlvB.valueLen < 8) {
                return BPP_CMD_REPLACE_SESSION_KEYS;
            }
            if (!crypto.verifyBspSegment(bpp, pos, derTlvB.totalLen, bspSMac, (short) 0, bspMcv, (short) 0)) {
                return BPP_CMD_REPLACE_SESSION_KEYS;
            }

            childPlainLen = crypto.decryptBspPayload(bspSEnc, (short) 0, bspBlockNr,
                    bpp, derTlvB.valueOff, (short) (derTlvB.valueLen - 8),
                    assembledApdu, plaintextLen);
            if (childPlainLen < 0) {
                return BPP_CMD_REPLACE_SESSION_KEYS;
            }

            plaintextLen = (short) (plaintextLen + childPlainLen);
            bspBlockNr++;
            pos = (short) (pos + derTlvB.totalLen);
        }

        if (pos != end) {
            return BPP_CMD_REPLACE_SESSION_KEYS;
        }

        if (!loadReplaceSessionKeys(assembledApdu, plaintextLen)) {
            return BPP_CMD_REPLACE_SESSION_KEYS;
        }
        return VERIFY_SEQUENCE_OK;
    }

    private boolean loadReplaceSessionKeys(byte[] plaintext, short plaintextLen) {
        short pos;
        short end;

        if (!parseDerTlv(plaintext, (short) 0, plaintextLen, derTlvA)
                || derTlvA.tag != (short) 0xBF26
                || derTlvA.totalLen != plaintextLen) {
            return false;
        }

        pos = derTlvA.valueOff;
        end = (short) (derTlvA.valueOff + derTlvA.valueLen);

        if (!parseDerTlv(plaintext, pos, end, derTlvB)
                || derTlvB.tag != (short) 0x80
                || derTlvB.valueLen != 16) {
            return false;
        }
        Util.arrayCopyNonAtomic(plaintext, derTlvB.valueOff, pppMcv, (short) 0, (short) 16);
        pos = (short) (pos + derTlvB.totalLen);

        if (!parseDerTlv(plaintext, pos, end, derTlvB)
                || derTlvB.tag != (short) 0x81
                || derTlvB.valueLen != 16) {
            return false;
        }
        Util.arrayCopyNonAtomic(plaintext, derTlvB.valueOff, pppSEnc, (short) 0, (short) 16);
        pos = (short) (pos + derTlvB.totalLen);

        if (!parseDerTlv(plaintext, pos, end, derTlvB)
                || derTlvB.tag != (short) 0x82
                || derTlvB.valueLen != 16) {
            return false;
        }
        Util.arrayCopyNonAtomic(plaintext, derTlvB.valueOff, pppSMac, (short) 0, (short) 16);
        pos = (short) (pos + derTlvB.totalLen);

        if (pos != end) {
            return false;
        }

        pppBlockNr = 1;
        pppKeysReady = true;
        return true;
    }

    private boolean setSmdpPublicKeyFromCertificate(byte[] certTlv, short certTlvLen, boolean bindingKey) {
        if (certTlv == null || certTlvLen <= 0) {
            return false;
        }

        short certEnd = certTlvLen;
        if (!parseDerTlv(certTlv, (short) 0, certEnd, derTlvA) || derTlvA.tag != (short) 0x30) {
            return false;
        }
        short certSeqEnd = (short) (derTlvA.valueOff + derTlvA.valueLen);
        if (certSeqEnd != certEnd) {
            return false;
        }

        if (!parseDerTlv(certTlv, derTlvA.valueOff, certSeqEnd, derTlvA) || derTlvA.tag != (short) 0x30) {
            return false;
        }

        short tbsPos = derTlvA.valueOff;
        short tbsEnd = (short) (derTlvA.valueOff + derTlvA.valueLen);

        if (!parseDerTlv(certTlv, tbsPos, tbsEnd, derTlvB)) {
            return false;
        }
        if (derTlvB.tag == (short) 0xA0) {
            tbsPos = (short) (tbsPos + derTlvB.totalLen);
        }

        // Skip serialNumber, signature, issuer, validity, subject.
        for (byte i = 0; i < 5; i++) {
            if (!parseDerTlv(certTlv, tbsPos, tbsEnd, derTlvB)) {
                return false;
            }
            tbsPos = (short) (tbsPos + derTlvB.totalLen);
        }

        // subjectPublicKeyInfo
        if (!parseDerTlv(certTlv, tbsPos, tbsEnd, derTlvB) || derTlvB.tag != (short) 0x30) {
            return false;
        }

        short spkiPos = derTlvB.valueOff;
        short spkiEnd = (short) (derTlvB.valueOff + derTlvB.valueLen);

        // algorithmIdentifier
        if (!parseDerTlv(certTlv, spkiPos, spkiEnd, derTlvC) || derTlvC.tag != (short) 0x30) {
            return false;
        }
        spkiPos = (short) (spkiPos + derTlvC.totalLen);

        // subjectPublicKey BIT STRING, expected: 00 || 04 || X || Y
        if (!parseDerTlv(certTlv, spkiPos, spkiEnd, derTlvC) || derTlvC.tag != (short) 0x03) {
            return false;
        }
        if (derTlvC.valueLen != (short) 66) {
            return false;
        }
        if (certTlv[derTlvC.valueOff] != 0x00 || certTlv[(short) (derTlvC.valueOff + 1)] != 0x04) {
            return false;
        }

        Util.arrayCopyNonAtomic(certTlv, (short) (derTlvC.valueOff + 1), parsedCertPublicKey, (short) 0, (short) 65);
        if (bindingKey) {
            crypto.setSmdpPbPublicKey(parsedCertPublicKey, (short) 0, (short) 65);
        } else {
            crypto.setSmdpAuthPublicKey(parsedCertPublicKey, (short) 0, (short) 65);
        }
        return true;
    }

    private boolean setSmdpPbPublicKeyFromCertificate(byte[] certTlv, short certTlvLen) {
        return setSmdpPublicKeyFromCertificate(certTlv, certTlvLen, true);
    }

    private boolean setSmdpAuthPublicKeyFromCertificate(byte[] certTlv, short certTlvLen) {
        return setSmdpPublicKeyFromCertificate(certTlv, certTlvLen, false);
    }

    private static boolean parseDerTlv(byte[] data, short off, short end, DerTlv out) {
        if (!parseDerHeader(data, off, end, out)) {
            return false;
        }
        return (short) (out.valueOff + out.valueLen) <= end;
    }

    private static boolean parseDerHeader(byte[] data, short off, short end, DerTlv out) {
        if (off >= end) {
            return false;
        }

        short pos = off;
        short tag;

        byte first = data[pos++];
        if ((short) (first & 0x1F) == 0x1F) {
            if (pos >= end) {
                return false;
            }
            byte second = data[pos++];
            if ((second & 0x80) != 0) {
                return false;
            }
            tag = (short) (((short) (first & 0xFF) << 8) | (short) (second & 0xFF));
        } else {
            tag = (short) (first & 0xFF);
        }

        if (pos >= end) {
            return false;
        }

        short len;
        short headerEnd;
        byte lenB = data[pos++];
        if ((lenB & 0x80) == 0) {
            len = (short) (lenB & 0x7F);
        } else {
            byte numLenBytes = (byte) (lenB & 0x7F);
            if (numLenBytes == 0 || numLenBytes > 2) {
                return false;
            }
            if ((short) (pos + numLenBytes) > end) {
                return false;
            }

            len = 0;
            for (byte i = 0; i < numLenBytes; i++) {
                len = (short) ((short) (len << 8) | (short) (data[pos++] & 0xFF));
            }
        }

        headerEnd = pos;

        out.tag = tag;
        out.valueOff = headerEnd;
        out.valueLen = len;
        out.totalLen = (short) (headerEnd + len - off);
        return true;
    }

    private static short peekDerTag(byte[] data, short off, short end) {
        DerTlv tlv = new DerTlv();
        if (!parseDerHeader(data, off, end, tlv)) {
            return 0;
        }
        return tlv.tag;
    }

    private boolean verifyAuthenticateServerSignature() {
        if (!crypto.hasSmdpAuthPublicKey()) {
            return false;
        }
        short pos = 0;
        assembledApdu[pos++] = 0x30;
        short lenPos = pos++;

        pos = TlvWriter.appendTlv(assembledApdu, pos, (short) 0x80, decodedMessage.txId, (short) 0, decodedMessage.txIdLen);
        pos = TlvWriter.appendTlv(assembledApdu, pos, (short) 0x81, decodedMessage.euiccChallenge, (short) 0, decodedMessage.euiccChallengeLen);
        pos = TlvWriter.appendTlv(assembledApdu, pos, (short) 0x83, decodedMessage.serverAddress, (short) 0, decodedMessage.serverAddressLen);
        pos = TlvWriter.appendTlv(assembledApdu, pos, (short) 0x84, decodedMessage.serverChallenge, (short) 0, decodedMessage.serverChallengeLen);

        assembledApdu[lenPos] = (byte) (pos - lenPos - 1);
        return crypto.verifySignature(crypto.getSmdpAuthPublicKey(), assembledApdu, (short) 0, pos,
                decodedMessage.serverSignature1, (short) 0, decodedMessage.serverSignature1Len);
    }

    private short buildGetEuiccChallengeResponse(byte[] out, short off) {
        short pos = off;
        out[pos++] = (byte) 0xBF;
        out[pos++] = 0x2E;
        short outerLenPos = pos++;

        out[pos++] = (byte) 0x80;
        pos = TlvWriter.writeLength(out, pos, euiccChallengeLen);
        Util.arrayCopyNonAtomic(euiccChallenge, (short) 0, out, pos, euiccChallengeLen);
        pos = (short) (pos + euiccChallengeLen);

        out[outerLenPos] = (byte) (pos - off - 3);
        return pos;
    }

    private short buildGetEuiccInfo1Response(byte[] out, short off) {
        short infoListLen = encodedTlvSize((short) 0x04, (short) CI_PKID_NIST.length);
        short bodyLen = encodedTlvSize((short) 0x82, (short) SVN.length);
        bodyLen = (short) (bodyLen + 1 + lengthFieldSize(infoListLen) + infoListLen);
        bodyLen = (short) (bodyLen + 1 + lengthFieldSize(infoListLen) + infoListLen);

        short pos = off;
        out[pos++] = (byte) 0xBF;
        out[pos++] = 0x20;
        pos = TlvWriter.writeLength(out, pos, bodyLen);

        pos = TlvWriter.appendTlv(out, pos, (short) 0x82, SVN, (short) 0, (short) SVN.length);

        out[pos++] = (byte) 0xA9;
        pos = TlvWriter.writeLength(out, pos, infoListLen);
        pos = TlvWriter.appendTlv(out, pos, (short) 0x04, CI_PKID_NIST, (short) 0, (short) CI_PKID_NIST.length);

        out[pos++] = (byte) 0xAA;
        pos = TlvWriter.writeLength(out, pos, infoListLen);
        pos = TlvWriter.appendTlv(out, pos, (short) 0x04, CI_PKID_NIST, (short) 0, (short) CI_PKID_NIST.length);

        return pos;
    }

    private short buildPrepareDownloadResponse(byte[] out, short off, byte[] txId, short txIdLen) {
        if (sessionEuiccOtpkLen <= 0) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        // Wire layout (SGP.22 5.7.5 with AUTOMATIC TAGS + IMPLICIT CHOICE tagging):
        //   BF 21 81 <L_outer>               -- PrepareDownloadResponse outer tag
        //     A0 81 <L_ok>                   -- [0] IMPLICIT PrepareDownloadResponseOk (replaces SEQ)
        //       30 <L_signed2>               -- EUICCSigned2 SEQUENCE
        //         80 <L> <txId>
        //         5F49 <L> <euiccOtpk>
        //       5F 37 40 <raw 64 B sig>      -- euiccSignature2 DO
        //
        // euiccSignature2 signs over: full EUICCSigned2 TLV || full smdpSignature2 DO (5F37 TLV).
        // Always use 81 LL length form for BF21 / A0 since the body is always >= 128 bytes here.
        short pos = off;

        // BF21 outer header placeholder: tag (2) + 81 + len (1) = 4 bytes
        out[pos++] = (byte) 0xBF;
        out[pos++] = 0x21;
        out[pos++] = (byte) 0x81;
        short outerLenPos = pos++;

        // A0 CHOICE wrapper placeholder: tag (1) + 81 + len (1) = 3 bytes
        out[pos++] = (byte) 0xA0;
        out[pos++] = (byte) 0x81;
        short a0LenPos = pos++;

        // EUICCSigned2 SEQUENCE
        short euiccSigned2Start = pos;
        out[pos++] = 0x30;
        short euiccSigned2LenPos = pos++;       // single-byte length (body < 128)
        short euiccSigned2BodyStart = pos;

        pos = TlvWriter.appendTlv(out, pos, (short) 0x80, txId, (short) 0, txIdLen);
        pos = TlvWriter.appendTlv(out, pos, TAG_APP_73, sessionEuiccOtpk, (short) 0, sessionEuiccOtpkLen);

        out[euiccSigned2LenPos] = (byte) (pos - euiccSigned2BodyStart);
        short euiccSigned2End = pos;
        short euiccSigned2TlvLen = (short) (euiccSigned2End - euiccSigned2Start);

        // Temporarily place the smdpSignature2 DO immediately after EUICCSigned2 TLV so we can
        // sign over the contiguous range with a single crypto.sign call.  The bytes will be
        // overwritten by the euiccSignature2 DO below.
        short smdpSig2DoStart = pos;
        short smdpSig2Len = decodedMessage.smdpSignature2Len;
        out[pos++] = 0x5F;
        out[pos++] = 0x37;
        out[pos++] = (byte) smdpSig2Len;
        Util.arrayCopyNonAtomic(decodedMessage.smdpSignature2, (short) 0, out, pos, smdpSig2Len);
        pos = (short) (pos + smdpSig2Len);

        short signRangeLen = (short) (pos - euiccSigned2Start);
        short derSigLen = crypto.sign(out, euiccSigned2Start, signRangeLen, sigBuf, (short) 0);
        short rawSigLen = derEcdsaToRaw(sigBuf, (short) 0, derSigLen, sigBuf, (short) 0);

        // Overwrite the smdpSig2 DO area with the real euiccSignature2 DO.
        pos = smdpSig2DoStart;
        pos = TlvWriter.appendTlv(out, pos, TAG_APP_55, sigBuf, (short) 0, rawSigLen);

        // Patch A0 and BF21 lengths.
        short a0BodyLen = (short) (pos - a0LenPos - 1);
        out[a0LenPos] = (byte) a0BodyLen;
        short bf21BodyLen = (short) (pos - outerLenPos - 1);
        out[outerLenPos] = (byte) bf21BodyLen;

        return pos;
    }

    private short buildProfileInstallationResult(byte[] out, short off, byte[] txId, short txIdLen) {
        short pos = off;
        short pirStart;
        short pirDataStart;
        short pirDataLenPos;
        short notificationStart;
        short notificationLenPos;
        short finalResultStart;
        short finalResultLenPos;
        short successStart;
        short successLenPos;
        short signedLen;
        short sigLen;

        out[pos++] = (byte) 0xBF;
        out[pos++] = 0x37;
        out[pos++] = (byte) 0x81;
        short outerLenPos = pos++;

        pirStart = pos;
        out[pos++] = (byte) 0xBF;
        out[pos++] = 0x27;
        pirDataLenPos = pos++;
        pirDataStart = pos;

        pos = TlvWriter.appendTlv(out, pos, (short) 0x80, txId, (short) 0, txIdLen);

        notificationStart = pos;
        out[pos++] = (byte) 0xBF;
        out[pos++] = 0x2F;
        notificationLenPos = pos++;
        pos = TlvWriter.appendTlv(out, pos, (short) 0x80, INSTALL_RESULT_OK, (short) 0, (short) INSTALL_RESULT_OK.length);
        pos = TlvWriter.appendTlv(out, pos, (short) 0x81, INSTALL_NOTIFICATION_EVENT, (short) 0,
                (short) INSTALL_NOTIFICATION_EVENT.length);
        pos = TlvWriter.appendTlv(out, pos, (short) 0x0C, DEFAULT_NOTIFICATION_ADDRESS, (short) 0,
                (short) DEFAULT_NOTIFICATION_ADDRESS.length);
        out[notificationLenPos] = (byte) (pos - notificationStart - 3);

        finalResultStart = pos;
        out[pos++] = (byte) 0xA2;
        finalResultLenPos = pos++;
        successStart = pos;
        out[pos++] = (byte) 0xA0;
        successLenPos = pos++;
        pos = TlvWriter.appendTlv(out, pos, (short) 0x4F, DEFAULT_APPLET_AID, (short) 0, (short) DEFAULT_APPLET_AID.length);
        pos = TlvWriter.appendTlv(out, pos, (short) 0x04, assembledApdu, (short) 0, (short) 0);
        out[successLenPos] = (byte) (pos - successStart - 2);
        out[finalResultLenPos] = (byte) (pos - finalResultStart - 2);

        out[pirDataLenPos] = (byte) (pos - pirDataStart);

        signedLen = (short) (pos - pirStart);
        sigLen = crypto.sign(out, pirStart, signedLen, sigBuf, (short) 0);
        sigLen = derEcdsaToRaw(sigBuf, (short) 0, sigLen, sigBuf, (short) 0);
        pos = TlvWriter.appendTlv(out, pos, TAG_APP_55, sigBuf, (short) 0, sigLen);

        out[outerLenPos] = (byte) (pos - off - 4);
        return pos;
    }

    private short buildPersistedBppInfoResponse(byte[] out, short off) {
        short pos = off;
        short bodyStart;
        short bodyLenPos;

        out[pos++] = (byte) (TAG_PERSISTED_BPP_INFO >> 8);
        out[pos++] = (byte) (TAG_PERSISTED_BPP_INFO & 0xFF);
        bodyLenPos = pos++;
        bodyStart = pos;

        out[pos++] = (byte) 0x80;
        out[pos++] = 0x02;
        Util.setShort(out, pos, persistedBppLength);
        pos += 2;

        if (persistedBppTxIdLen > 0) {
            pos = TlvWriter.appendTlv(out, pos, (short) 0x81, persistedBppTxId, (short) 0, persistedBppTxIdLen);
        }

        out[bodyLenPos] = (byte) (pos - bodyStart);
        return pos;
    }

    private short buildProfileInstallationError(byte[] out, short off, byte[] txId, short txIdLen,
                                                byte bppCommandId, byte errorReason) {
        short pos = off;
        short pirStart;
        short pirDataStart;
        short pirDataLenPos;
        short notificationStart;
        short notificationLenPos;
        short finalResultStart;
        short finalResultLenPos;
        short errorStart;
        short errorLenPos;
        short signedLen;
        short sigLen;

        out[pos++] = (byte) 0xBF;
        out[pos++] = 0x37;
        out[pos++] = (byte) 0x81;
        short outerLenPos = pos++;

        pirStart = pos;
        out[pos++] = (byte) 0xBF;
        out[pos++] = 0x27;
        pirDataLenPos = pos++;
        pirDataStart = pos;

        pos = TlvWriter.appendTlv(out, pos, (short) 0x80, txId, (short) 0, txIdLen);

        notificationStart = pos;
        out[pos++] = (byte) 0xBF;
        out[pos++] = 0x2F;
        notificationLenPos = pos++;
        pos = TlvWriter.appendTlv(out, pos, (short) 0x80, INSTALL_RESULT_OK, (short) 0, (short) INSTALL_RESULT_OK.length);
        pos = TlvWriter.appendTlv(out, pos, (short) 0x81, INSTALL_NOTIFICATION_EVENT, (short) 0,
                (short) INSTALL_NOTIFICATION_EVENT.length);
        pos = TlvWriter.appendTlv(out, pos, (short) 0x0C, DEFAULT_NOTIFICATION_ADDRESS, (short) 0,
                (short) DEFAULT_NOTIFICATION_ADDRESS.length);
        out[notificationLenPos] = (byte) (pos - notificationStart - 3);

        finalResultStart = pos;
        out[pos++] = (byte) 0xA2;
        finalResultLenPos = pos++;
        errorStart = pos;
        out[pos++] = (byte) 0xA1;
        errorLenPos = pos++;
        // LPAC expects AUTOMATIC TAGS-style field tags for ErrorResult.
        out[pos++] = (byte) 0x80;
        out[pos++] = 0x01;
        out[pos++] = bppCommandId;
        out[pos++] = (byte) 0x81;
        out[pos++] = 0x01;
        out[pos++] = errorReason;
        out[errorLenPos] = (byte) (pos - errorStart - 2);
        out[finalResultLenPos] = (byte) (pos - finalResultStart - 2);

        out[pirDataLenPos] = (byte) (pos - pirDataStart);

        signedLen = (short) (pos - pirStart);
        sigLen = crypto.sign(out, pirStart, signedLen, sigBuf, (short) 0);
        sigLen = derEcdsaToRaw(sigBuf, (short) 0, sigLen, sigBuf, (short) 0);
        pos = TlvWriter.appendTlv(out, pos, TAG_APP_55, sigBuf, (short) 0, sigLen);

        out[outerLenPos] = (byte) (pos - off - 4);
        return pos;
    }

    private short buildAuthenticateServerResponse(byte[] out, short off, byte[] txId, short txIdLen,
                                                  byte[] serverAddress, short serverAddressLen,
                                                  byte[] serverChallenge, short serverChallengeLen) {
        short ciEntryLen = encodedTlvSize((short) 0x04, (short) CI_PKID_NIST.length);
        short ciListLen = ciEntryLen;
        short euiccInfo2BodyLen = encodedTlvSize((short) 0x81, (short) PROFILE_VERSION.length);
        euiccInfo2BodyLen = (short) (euiccInfo2BodyLen + encodedTlvSize((short) 0x82, (short) SVN.length));
        euiccInfo2BodyLen = (short) (euiccInfo2BodyLen + encodedTlvSize((short) 0x83, (short) EUICC_FIRMWARE_VER.length));
        euiccInfo2BodyLen = (short) (euiccInfo2BodyLen + encodedTlvSize((short) 0x84, (short) EXT_CARD_RESOURCE.length));
        euiccInfo2BodyLen = (short) (euiccInfo2BodyLen + encodedTlvSize((short) 0x85, (short) UICC_CAPABILITY_BITS.length));
        euiccInfo2BodyLen = (short) (euiccInfo2BodyLen + encodedTlvSize((short) 0x86, (short) JAVACARD_VERSION.length));
        euiccInfo2BodyLen = (short) (euiccInfo2BodyLen + encodedTlvSize((short) 0x87, (short) GLOBALPLATFORM_VERSION.length));
        euiccInfo2BodyLen = (short) (euiccInfo2BodyLen + encodedTlvSize((short) 0x88, (short) RSP_CAPABILITY_BITS.length));
        euiccInfo2BodyLen = (short) (euiccInfo2BodyLen + 1 + lengthFieldSize(ciListLen) + ciListLen); // [9]
        euiccInfo2BodyLen = (short) (euiccInfo2BodyLen + 1 + lengthFieldSize(ciListLen) + ciListLen); // [10]
        euiccInfo2BodyLen = (short) (euiccInfo2BodyLen + encodedTlvSize((short) 0x04, (short) PP_VERSION.length));
        euiccInfo2BodyLen = (short) (euiccInfo2BodyLen + encodedTlvSize((short) 0x0C, (short) SAS_ACCREDITATION_NUMBER.length));
        short euiccInfo2TlvLen = (short) (2 + lengthFieldSize(euiccInfo2BodyLen) + euiccInfo2BodyLen);

        short deviceCapabilitiesTlvLen = (short) (1 + lengthFieldSize((short) 0) + 0); // A1 00
        short deviceInfoBodyLen = encodedTlvSize((short) 0x80, (short) DEFAULT_TAC.length);
        deviceInfoBodyLen = (short) (deviceInfoBodyLen + deviceCapabilitiesTlvLen);
        short deviceInfoTlvLen = (short) (1 + lengthFieldSize(deviceInfoBodyLen) + deviceInfoBodyLen); // A1

        short ctxParamsBodyLen = encodedTlvSize((short) 0x80, (short) DEFAULT_MATCHING_ID.length);
        ctxParamsBodyLen = (short) (ctxParamsBodyLen + deviceInfoTlvLen);
        short ctxParamsTlvLen = (short) (1 + lengthFieldSize(ctxParamsBodyLen) + ctxParamsBodyLen); // A0

        // eligibilityData [5] IMPLICIT SEQUENCE -> A5 { 80..85 } (ASN.1 AUTOMATIC TAGS)
        short eligBodyLen = encodedTlvSize((short) 0x80, (short) hpidBuf.length);
        eligBodyLen = (short) (eligBodyLen + encodedTlvSize((short) 0x81, (short) sigCredBuf.length));
        eligBodyLen = (short) (eligBodyLen + encodedTlvSize((short) 0x82, (short) authTokenBuf.length));
        eligBodyLen = (short) (eligBodyLen + encodedTlvSize((short) 0x83, (short) accRootBuf.length));
        eligBodyLen = (short) (eligBodyLen + encodedTlvSize((short) 0x84, (short) sigRootBuf.length));
        eligBodyLen = (short) (eligBodyLen + encodedTlvSize((short) 0x85, accProofLen));
        short eligTlvLen = (short) (1 + lengthFieldSize(eligBodyLen) + eligBodyLen);

        short euiccSigned1BodyLen = encodedTlvSize((short) 0x80, txIdLen);
        euiccSigned1BodyLen = (short) (euiccSigned1BodyLen + encodedTlvSize((short) 0x83, serverAddressLen));
        euiccSigned1BodyLen = (short) (euiccSigned1BodyLen + encodedTlvSize((short) 0x84, serverChallengeLen));
        euiccSigned1BodyLen = (short) (euiccSigned1BodyLen + euiccInfo2TlvLen);
        euiccSigned1BodyLen = (short) (euiccSigned1BodyLen + ctxParamsTlvLen);
        euiccSigned1BodyLen = (short) (euiccSigned1BodyLen + eligTlvLen);

        short euiccSigned1Len = (short) (1 + lengthFieldSize(euiccSigned1BodyLen) + euiccSigned1BodyLen);

        // Raw ECDSA (64 bytes) wrapped in [APPLICATION 55] = 2 tag + 1 len + 64 = 67
        short sigTlvLen = (short) (2 + 1 + 64);
        // With AUTOMATIC TAGS + IMPLICIT on the CHOICE alternative, the [0] tag (A0) REPLACES
        // the AuthenticateResponseOk SEQUENCE tag — so A0's body is directly the 4 fields:
        // euiccSigned1 + euiccSignature1 + euiccCertificate + eumCertificate.  No inner SEQUENCE.
        short euiccCertLen = euiccCertDerLen;
        short eumCertLen = euiccCertDerLen;
        short choiceLen = (short) (euiccSigned1Len + sigTlvLen + euiccCertLen + eumCertLen);
        short outerBodyLen = (short) (1 + lengthFieldSize(choiceLen) + choiceLen);

        short pos = off;
        out[pos++] = (byte) 0xBF;
        out[pos++] = 0x38;
        pos = TlvWriter.writeLength(out, pos, outerBodyLen);

        out[pos++] = (byte) 0xA0;
        pos = TlvWriter.writeLength(out, pos, choiceLen);

        short signedStart = pos;
        out[pos++] = 0x30;
        pos = TlvWriter.writeLength(out, pos, euiccSigned1BodyLen);

        pos = TlvWriter.appendTlv(out, pos, (short) 0x80, txId, (short) 0, txIdLen);
        pos = TlvWriter.appendTlv(out, pos, (short) 0x83, serverAddress, (short) 0, serverAddressLen);
        pos = TlvWriter.appendTlv(out, pos, (short) 0x84, serverChallenge, (short) 0, serverChallengeLen);

        out[pos++] = (byte) 0xBF;
        out[pos++] = 0x22;
        pos = TlvWriter.writeLength(out, pos, euiccInfo2BodyLen);
        pos = TlvWriter.appendTlv(out, pos, (short) 0x81, PROFILE_VERSION, (short) 0, (short) PROFILE_VERSION.length);
        pos = TlvWriter.appendTlv(out, pos, (short) 0x82, SVN, (short) 0, (short) SVN.length);
        pos = TlvWriter.appendTlv(out, pos, (short) 0x83, EUICC_FIRMWARE_VER, (short) 0, (short) EUICC_FIRMWARE_VER.length);
        pos = TlvWriter.appendTlv(out, pos, (short) 0x84, EXT_CARD_RESOURCE, (short) 0, (short) EXT_CARD_RESOURCE.length);
        pos = TlvWriter.appendTlv(out, pos, (short) 0x85, UICC_CAPABILITY_BITS, (short) 0, (short) UICC_CAPABILITY_BITS.length);
        pos = TlvWriter.appendTlv(out, pos, (short) 0x86, JAVACARD_VERSION, (short) 0, (short) JAVACARD_VERSION.length);
        pos = TlvWriter.appendTlv(out, pos, (short) 0x87, GLOBALPLATFORM_VERSION, (short) 0, (short) GLOBALPLATFORM_VERSION.length);
        pos = TlvWriter.appendTlv(out, pos, (short) 0x88, RSP_CAPABILITY_BITS, (short) 0, (short) RSP_CAPABILITY_BITS.length);

        out[pos++] = (byte) 0xA9;
        pos = TlvWriter.writeLength(out, pos, ciListLen);
        pos = TlvWriter.appendTlv(out, pos, (short) 0x04, CI_PKID_NIST, (short) 0, (short) CI_PKID_NIST.length);

        out[pos++] = (byte) 0xAA;
        pos = TlvWriter.writeLength(out, pos, ciListLen);
        pos = TlvWriter.appendTlv(out, pos, (short) 0x04, CI_PKID_NIST, (short) 0, (short) CI_PKID_NIST.length);

        pos = TlvWriter.appendTlv(out, pos, (short) 0x04, PP_VERSION, (short) 0, (short) PP_VERSION.length);
        pos = TlvWriter.appendTlv(out, pos, (short) 0x0C, SAS_ACCREDITATION_NUMBER, (short) 0,
            (short) SAS_ACCREDITATION_NUMBER.length);

        out[pos++] = (byte) 0xA0;
        pos = TlvWriter.writeLength(out, pos, ctxParamsBodyLen);
        pos = TlvWriter.appendTlv(out, pos, (short) 0x80, DEFAULT_MATCHING_ID, (short) 0, (short) DEFAULT_MATCHING_ID.length);
        out[pos++] = (byte) 0xA1;
        pos = TlvWriter.writeLength(out, pos, deviceInfoBodyLen);
        pos = TlvWriter.appendTlv(out, pos, (short) 0x80, DEFAULT_TAC, (short) 0, (short) DEFAULT_TAC.length);
        out[pos++] = (byte) 0xA1;
        out[pos++] = 0x00;

        out[pos++] = (byte) 0xA5;
        pos = TlvWriter.writeLength(out, pos, eligBodyLen);
        pos = TlvWriter.appendTlv(out, pos, (short) 0x80, hpidBuf, (short) 0, (short) hpidBuf.length);
        pos = TlvWriter.appendTlv(out, pos, (short) 0x81, sigCredBuf, (short) 0, (short) sigCredBuf.length);
        pos = TlvWriter.appendTlv(out, pos, (short) 0x82, authTokenBuf, (short) 0, (short) authTokenBuf.length);
        pos = TlvWriter.appendTlv(out, pos, (short) 0x83, accRootBuf, (short) 0, (short) accRootBuf.length);
        pos = TlvWriter.appendTlv(out, pos, (short) 0x84, sigRootBuf, (short) 0, (short) sigRootBuf.length);
        pos = TlvWriter.appendTlv(out, pos, (short) 0x85, accProofBuf, (short) 0, accProofLen);

        short sigLen = crypto.sign(out, signedStart, euiccSigned1Len, sigBuf, (short) 0);
        sigLen = derEcdsaToRaw(sigBuf, (short) 0, sigLen, sigBuf, (short) 0);

        if (sigLen == 64) {
            Util.arrayCopyNonAtomic(sigBuf, (short) 0, sessionEuiccSignature1, (short) 0, sigLen);
            sessionEuiccSignature1Len = sigLen;
        }

        pos = TlvWriter.appendTlv(out, pos, TAG_APP_55, sigBuf, (short) 0, sigLen);

        // Emit the same decodable certificate for both slots so the standard
        // AuthenticateServerResponse ASN.1 decoder can be used in zk mode too.
        Util.arrayCopyNonAtomic(euiccCertDer, (short) 0, out, pos, euiccCertDerLen);
        pos = (short) (pos + euiccCertDerLen);
        Util.arrayCopyNonAtomic(euiccCertDer, (short) 0, out, pos, euiccCertDerLen);
        pos = (short) (pos + euiccCertDerLen);
        return pos;
    }

    private short buildZkProfileResponse(byte[] out, short off) {
        short pkULen = crypto.exportPublicKey(pubKeyBuf, (short) 0);
        short statementLen = buildZkStatement(zkStatementBuf, (short) 0, pkULen);
        short sigLen = crypto.sign(zkStatementBuf, (short) 0, statementLen, sigBuf, (short) 0);

        short proofTlvLen = (short) (2 + lengthFieldSize(sigLen) + sigLen);
        short choiceLen = (short) (statementLen + euiccCertDerLen + proofTlvLen);
        short outerBodyLen = (short) (1 + lengthFieldSize(choiceLen) + choiceLen);
        short pos = off;

        out[pos++] = (byte) 0xBF;
        out[pos++] = 0x42;
        pos = TlvWriter.writeLength(out, pos, outerBodyLen);

        out[pos++] = (byte) 0xA0;
        pos = TlvWriter.writeLength(out, pos, choiceLen);

        Util.arrayCopyNonAtomic(zkStatementBuf, (short) 0, out, pos, statementLen);
        pos = (short) (pos + statementLen);
        Util.arrayCopyNonAtomic(euiccCertDer, (short) 0, out, pos, euiccCertDerLen);
        pos = (short) (pos + euiccCertDerLen);
        pos = TlvWriter.appendTlv(out, pos, TAG_APP_55, sigBuf, (short) 0, sigLen);
        return pos;
    }

    private short buildZkStatement(byte[] out, short off, short pkULen) {
        short bodyLen = 0;
        bodyLen = (short) (bodyLen + encodedTlvSize((short) 0x80, (short) Crypto.MNO_PUBLIC_KEY.length));
        bodyLen = (short) (bodyLen + encodedTlvSize((short) 0x81, (short) Crypto.LEA_PUBLIC_KEY.length));
        bodyLen = (short) (bodyLen + encodedTlvSize((short) 0x82, pkULen));
        bodyLen = (short) (bodyLen + encodedTlvSize((short) 0x83, (short) 16));
        bodyLen = (short) (bodyLen + encodedTlvSize((short) 0x84, (short) 32));
        bodyLen = (short) (bodyLen + encodedTlvSize((short) 0x85, (short) 81));

        short pos = off;
        out[pos++] = 0x30;
        pos = TlvWriter.writeLength(out, pos, bodyLen);
        pos = TlvWriter.appendTlv(out, pos, (short) 0x80, Crypto.MNO_PUBLIC_KEY, (short) 0, (short) Crypto.MNO_PUBLIC_KEY.length);
        pos = TlvWriter.appendTlv(out, pos, (short) 0x81, Crypto.LEA_PUBLIC_KEY, (short) 0, (short) Crypto.LEA_PUBLIC_KEY.length);
        pos = TlvWriter.appendTlv(out, pos, (short) 0x82, pubKeyBuf, (short) 0, pkULen);
        pos = TlvWriter.appendTlv(out, pos, (short) 0x83, decodedMessage.mnoChallenge, (short) 0, (short) 16);
        pos = TlvWriter.appendTlv(out, pos, (short) 0x84, pid, (short) 0, (short) 32);
        pos = TlvWriter.appendTlv(out, pos, (short) 0x85, encEidBuf, (short) 0, (short) 81);
        return (short) (pos - off);
    }

    private short buildSetEligibilityOk(byte[] out, short off) {
        short pos = off;
        out[pos++] = (byte) 0xBF;
        out[pos++] = 0x43;
        out[pos++] = 0x04;
        out[pos++] = (byte) 0xA0;
        out[pos++] = 0x02;
        out[pos++] = 0x30;
        out[pos++] = 0x00;
        return pos;
    }

    private static short lengthFieldSize(short len) {
        if (len < 0x80) {
            return 1;
        }
        if (len <= 0xFF) {
            return 2;
        }
        return 3;
    }

    private static short encodedTlvSize(short tag, short valueLen) {
        short tagSize = (short) (((tag & (short) 0xFF00) != 0) ? 2 : 1);
        return (short) (tagSize + lengthFieldSize(valueLen) + valueLen);
    }

    private static short derEcdsaToRaw(byte[] derSig, short derOff, short derSigLen, byte[] rawOut, short rawOff) {
        if (derSigLen < 8 || derSig[derOff] != 0x30) {
            ISOException.throwIt(SW_INVALID_DATA_FIELD);
        }

        short pos = (short) (derOff + 1);
        short seqLen = (short) (derSig[pos] & 0xFF);
        pos++;
        if ((seqLen & (short) 0x80) != 0) {
            short lenBytes = (short) (seqLen & 0x7F);
            if (lenBytes != 1 || (short) (pos + lenBytes) > (short) (derOff + derSigLen)) {
                ISOException.throwIt(SW_INVALID_DATA_FIELD);
            }
            seqLen = (short) (derSig[pos] & 0xFF);
            pos++;
        }

        if (derSig[pos++] != 0x02) {
            ISOException.throwIt(SW_INVALID_DATA_FIELD);
        }
        short rLen = (short) (derSig[pos] & 0xFF);
        pos++;
        short rStart = pos;
        pos = (short) (pos + rLen);

        if (derSig[pos++] != 0x02) {
            ISOException.throwIt(SW_INVALID_DATA_FIELD);
        }
        short sLen = (short) (derSig[pos] & 0xFF);
        pos++;
        short sStart = pos;

        writeDerIntegerToRaw(derSig, rStart, rLen, rawOut, rawOff);
        writeDerIntegerToRaw(derSig, sStart, sLen, rawOut, (short) (rawOff + 32));
        return 64;
    }

    private static void writeDerIntegerToRaw(byte[] derSig, short derOff, short derLen, byte[] rawOut, short rawOff) {
        short start = derOff;
        short end = (short) (derOff + derLen);

        while (start < (short) (end - 1) && derSig[start] == 0x00) {
            start++;
        }

        short valueLen = (short) (end - start);
        if (valueLen > 32) {
            ISOException.throwIt(SW_INVALID_DATA_FIELD);
        }

        short pad = (short) (32 - valueLen);
        Util.arrayFillNonAtomic(rawOut, rawOff, pad, (byte) 0x00);
        Util.arrayCopyNonAtomic(derSig, start, rawOut, (short) (rawOff + pad), valueLen);
    }

    private short buildCancelSessionResponse(byte[] out, short off, byte[] txId, short txIdLen, byte reason) {
        short pos = off;
        short signedStart;
        short signedLenPos;
        short signedValueStart;
        short sigLen;
        out[pos++] = (byte) 0xBF;
        out[pos++] = 0x41;
        short outerLenPos = pos++;

        // [0] CHOICE for cancelSessionResponseOk
        out[pos++] = (byte) 0xA0;
        short choiceLenPos = pos++;

        signedStart = pos;
        out[pos++] = 0x30;
        signedLenPos = pos++;
        signedValueStart = pos;
        // With AUTOMATIC TAGS, fields get implicit [0], [1], [2] tags
        pos = TlvWriter.appendTlv(out, pos, (short) 0x80, txId, (short) 0, txIdLen);
        pos = TlvWriter.appendTlv(out, pos, (short) 0x81, DEFAULT_SMDP_OID, (short) 0, (short) DEFAULT_SMDP_OID.length);
        out[pos++] = (byte) 0x82;  // [2] IMPLICIT INTEGER
        out[pos++] = 0x01;
        out[pos++] = reason;
        out[signedLenPos] = (byte) (pos - signedValueStart);

        sigLen = crypto.sign(out, signedStart, (short) (pos - signedStart), sigBuf, (short) 0);
        sigLen = derEcdsaToRaw(sigBuf, (short) 0, sigLen, sigBuf, (short) 0);
        pos = TlvWriter.appendTlv(out, pos, TAG_APP_55, sigBuf, (short) 0, sigLen);

        out[choiceLenPos] = (byte) (pos - choiceLenPos - 1);
        out[outerLenPos] = (byte) (pos - off - 3);
        return pos;
    }

    private void sendPrepareDownloadError(APDU apdu, byte[] txId, short txIdLen, short errCode) {
        // PrepareDownloadResponse ::= [33] CHOICE {
        //     downloadResponseOk [0] IMPLICIT PrepareDownloadResponseOk,
        //     downloadResponseError [1] IMPLICIT PrepareDownloadResponseError }
        // AUTOMATIC TAGS + IMPLICIT: A1 REPLACES the SEQUENCE tag of PrepareDownloadResponseError.
        byte[] out = assembledApdu;
        short pos = 0;

        out[pos++] = (byte) 0xBF;
        out[pos++] = 0x21;
        short lenPos = pos++;

        short choiceStart = pos;
        out[pos++] = (byte) 0xA1;          // [1] IMPLICIT replaces the inner SEQUENCE 0x30 tag
        short choiceLenPos = pos++;

        out[pos++] = (byte) 0x80;
        out[pos++] = (byte) txIdLen;
        Util.arrayCopyNonAtomic(txId, (short) 0, out, pos, txIdLen);
        pos = (short) (pos + txIdLen);

        out[pos++] = 0x02;
        out[pos++] = 0x01;
        out[pos++] = (byte) errCode;

        out[choiceLenPos] = (byte) (pos - choiceStart - 2);
        out[lenPos] = (byte) (pos - 3);

        stageAndSendResponse(apdu, pos);
    }

    private void sendZkProfileError(APDU apdu, byte errCode) {
        byte[] out = assembledApdu;
        short pos = 0;
        out[pos++] = (byte) 0xBF;
        out[pos++] = 0x42;
        out[pos++] = 0x05;
        out[pos++] = (byte) 0xA1;
        out[pos++] = 0x03;
        out[pos++] = 0x02;
        out[pos++] = 0x01;
        out[pos++] = errCode;
        stageAndSendResponse(apdu, pos);
    }

    private void sendSetEligibilityError(APDU apdu, byte errCode) {
        byte[] out = assembledApdu;
        short pos = 0;
        out[pos++] = (byte) 0xBF;
        out[pos++] = 0x43;
        out[pos++] = 0x05;
        out[pos++] = (byte) 0xA1;
        out[pos++] = 0x03;
        out[pos++] = 0x02;
        out[pos++] = 0x01;
        out[pos++] = errCode;
        stageAndSendResponse(apdu, pos);
    }

    private void sendAuthenticateServerError(APDU apdu, byte[] txId, short txIdLen, short errCode) {
        // AuthenticateServerResponse ::= [56] CHOICE { authenticateResponseError SEQUENCE { transactionId [0], authenticateErrorCode } }
        byte[] out = assembledApdu;
        short pos = 0;

        out[pos++] = (byte) 0xBF;
        out[pos++] = 0x38;
        short lenPos = pos++;

        out[pos++] = (byte) 0xA1;
        short choiceLenPos = pos++;

        out[pos++] = (byte) 0x80;
        out[pos++] = (byte) txIdLen;
        Util.arrayCopyNonAtomic(txId, (short) 0, out, pos, txIdLen);
        pos = (short) (pos + txIdLen);

        out[pos++] = 0x02;
        out[pos++] = 0x01;
        out[pos++] = (byte) errCode;

        out[choiceLenPos] = (byte) (pos - choiceLenPos - 1);
        out[lenPos] = (byte) (pos - lenPos - 1);

        stageAndSendResponse(apdu, pos);
    }

    private void sendCancelSessionError(APDU apdu, byte errCode) {
        byte[] out = assembledApdu;
        short pos = 0;

        out[pos++] = (byte) 0xBF;
        out[pos++] = 0x41;
        // CancelSessionResponse ::= [65] CHOICE { ..., cancelSessionResponseError INTEGER }
        // With AUTOMATIC TAGS, the error alternative is context tag [1] IMPLICIT INTEGER.
        out[pos++] = 0x03;
        out[pos++] = (byte) 0x81;
        out[pos++] = 0x01;
        out[pos++] = errCode;

        stageAndSendResponse(apdu, pos);
    }

}
