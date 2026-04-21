package zk.esim.applet;

import javacard.framework.*;
public final class ZkEsimApplet extends Applet {

    private static final byte INS_RSP = (byte) 0xE2;
    private static final byte INS_GET_RESPONSE = (byte) 0xC0;

    // Keep this bounded for simulator/card memory constraints while still supporting APDU chaining.
    private static final short MAX_CHUNK_SIZE = (short) 256;
    private static final short SW_INVALID_DATA_FIELD = (short) 0x6A80;
    private static final short SW_UNSUPPORTED_COMMAND_DATA = (short) 0x6A88;
    private static final short SW_CONDITIONS_NOT_SATISFIED = (short) 0x6985;
    private static final short TAG_APP_55 = (short) 0x5F37;
    private static final short TAG_APP_73 = (short) 0x5F49;
    private static final byte[] DEFAULT_SMDP_OID = {(byte) 0x88, 0x37, 0x0A}; // 2.999.10
    private static final byte[] DEFAULT_NOTIFICATION_ADDRESS = {
            (byte) 's', (byte) 'm', (byte) 'd', (byte) 'p', (byte) '.', (byte) 't',
            (byte) 'e', (byte) 's', (byte) 't', (byte) '.', (byte) 'c', (byte) 'o', (byte) 'm'
    };
    private static final byte[] INSTALL_NOTIFICATION_EVENT = {0x07, (byte) 0x80};
    private static final byte[] INSTALL_RESULT_OK = {0x01};
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
        (byte) 'e', (byte) 's', (byte) 'i', (byte) 'm', (byte) 'T', (byte) 'e', (byte) 's', (byte) 't'
    };
    private static final byte[] DEFAULT_TAC = {0x35, 0x29, 0x06, 0x11, 0x00, 0x00, 0x00, 0x00};
    private static final byte[] HARDCODED_HPID = {
        0x41, 0x26, 0x5F, (byte) 0x84, 0x03, 0x18, (byte) 0xFD, 0x01,
        0x6C, (byte) 0xC2, (byte) 0xFD, (byte) 0xD7, (byte) 0xC2, 0x16, 0x47, 0x58,
        (byte) 0xB9, 0x4E, 0x66, (byte) 0xB6, 0x06, 0x4F, (byte) 0xCA, 0x0D,
        (byte) 0xAA, (byte) 0x84, 0x7B, 0x3E, (byte) 0x8E, (byte) 0xA3, (byte) 0x81, 0x24
    };
    private static final byte[] HARDCODED_SIG_CRED = {
        0x38, 0x35, 0x5B, 0x01, (byte) 0xE2, (byte) 0xF8, (byte) 0xA4, (byte) 0xC8,
        0x24, (byte) 0xCE, 0x0A, (byte) 0xDF, (byte) 0x86, (byte) 0x88, 0x0C, 0x73,
        0x38, (byte) 0xAC, 0x44, (byte) 0xF7, (byte) 0xD7, (byte) 0x93, (byte) 0xD5, 0x36,
        (byte) 0xBF, 0x47, 0x61, (byte) 0xDA, (byte) 0xF9, (byte) 0x99, 0x6A, (byte) 0xC5,
        (byte) 0xC2, 0x6F, 0x10, (byte) 0xE9, (byte) 0xE0, 0x25, (byte) 0xBC, 0x04,
        0x41, 0x51, 0x55, (byte) 0xC6, 0x25, (byte) 0xF3, (byte) 0xEF, 0x39,
        (byte) 0xEA, 0x0C, (byte) 0xEA, 0x04, (byte) 0xE6, (byte) 0xAC, 0x6E, (byte) 0xC7,
        (byte) 0xE7, (byte) 0xC6, 0x51, (byte) 0xB9, (byte) 0xED, 0x21, 0x4D, (byte) 0xC3
    };
    private static final byte[] HARDCODED_AUTH_TOKEN = {
        (byte) 0xD2, 0x01, 0x26, 0x33, 0x0A, (byte) 0xC8, 0x3B, (byte) 0x91,
        (byte) 0xE8, 0x37, (byte) 0x8F, (byte) 0xEB, (byte) 0xCE, (byte) 0xE7, (byte) 0xB3, 0x4D,
        0x15, 0x23, 0x51, 0x1D, (byte) 0x8B, (byte) 0xF0, (byte) 0x8D, (byte) 0xF9,
        (byte) 0xB5, (byte) 0xA6, (byte) 0xB5, 0x73, (byte) 0xC0, 0x2B, 0x5E, (byte) 0xFA,
        0x75, 0x1E, (byte) 0xAE, 0x48, 0x3F, 0x22, (byte) 0xBB, (byte) 0xA7,
        (byte) 0xEA, (byte) 0xA8, (byte) 0xAF, (byte) 0x9B, (byte) 0xA5, 0x6A, 0x6A, (byte) 0xD9,
        0x5C, (byte) 0x95, 0x01, (byte) 0xD3, 0x1C, (byte) 0x8F, 0x45, (byte) 0xA4,
        (byte) 0x96, 0x54, (byte) 0x95, (byte) 0xFF, (byte) 0xB9, (byte) 0xDC, 0x24, 0x61
    };
    private static final byte[] HARDCODED_ACC_ROOT = {
        0x25, 0x4F, 0x12, 0x3F, 0x03, 0x19, 0x25, (byte) 0xD0,
        0x05, (byte) 0xFC, (byte) 0xB9, 0x6A, 0x19, (byte) 0xFD, (byte) 0xBB, 0x56,
        (byte) 0xF7, (byte) 0xC8, 0x5A, 0x1F, 0x4D, (byte) 0xE3, (byte) 0xA3, (byte) 0xAB,
        0x08, (byte) 0xF3, 0x6C, (byte) 0xB2, (byte) 0x96, 0x67, (byte) 0xF0, 0x13
    };
    private static final byte[] HARDCODED_SIG_ROOT = {
        0x0C, 0x43, (byte) 0x8E, 0x7A, (byte) 0xE5, 0x16, 0x7D, (byte) 0xC3,
        0x03, (byte) 0xCE, (byte) 0xF8, 0x7A, (byte) 0xEB, 0x5F, 0x44, 0x22,
        (byte) 0x9A, (byte) 0xEE, (byte) 0xD1, 0x26, 0x06, (byte) 0x8F, (byte) 0x87, (byte) 0x80,
        (byte) 0x81, 0x55, (byte) 0xC5, (byte) 0xDA, 0x2A, 0x70, (byte) 0xAD, (byte) 0xBF,
        0x13, 0x46, 0x74, (byte) 0xB8, 0x6F, 0x3A, (byte) 0xE2, (byte) 0xFE,
        (byte) 0xF6, 0x04, 0x2F, 0x30, 0x37, 0x62, 0x71, (byte) 0xD7,
        (byte) 0xD2, 0x54, 0x4D, (byte) 0xEA, 0x5C, 0x5E, (byte) 0x88, 0x46,
        0x71, 0x72, 0x31, (byte) 0x92, (byte) 0xFB, (byte) 0xFC, 0x20, 0x58
    };
    // Single-leaf accumulator proof is empty: the root equals H(leaf).
    private static final byte[] HARDCODED_ACC_PROOF = {};
    private static final byte[] TEST_SMDP_PUBLIC_KEY = {
        0x04, 0x4D, (byte) 0xFE, (byte) 0xD4, (byte) 0xF4, 0x69, 0x47, (byte) 0x91,
        (byte) 0xBF, 0x16, (byte) 0x95, (byte) 0xCE, (byte) 0xA0, 0x30, 0x7A, 0x35,
        (byte) 0xB4, 0x18, 0x01, (byte) 0x96, (byte) 0x95, 0x38, 0x7B, (byte) 0xB7,
        0x5B, 0x7D, 0x24, 0x47, (byte) 0xB6, (byte) 0xB5, 0x20, (byte) 0x9F,
        0x04, 0x45, (byte) 0xAE, 0x4E, 0x5E, 0x52, 0x1C, (byte) 0xD1,
        0x38, (byte) 0x88, (byte) 0xD7, 0x5F, (byte) 0xE0, 0x7C, (byte) 0x85, (byte) 0x80,
        0x22, 0x2A, (byte) 0xE2, 0x0D, (byte) 0xBA, (byte) 0xAC, 0x1D, 0x77,
        (byte) 0xCD, 0x76, 0x30, 0x49, (byte) 0x93, 0x42, 0x1B, (byte) 0xD7,
        0x39
    };

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
    private Apdu.PendingResponse pendingResponse;

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
        pid = JCSystem.makeTransientByteArray((short) 48, JCSystem.CLEAR_ON_DESELECT);
        apduHandler = new Apdu();
        assembledApdu = apduHandler.getBuffer();
        asn1 = new Asn1();
        decodedMessage = new Asn1.DecodedMessage();
        pendingResponse = new Apdu.PendingResponse(assembledApdu, MAX_CHUNK_SIZE);
        sessionTxId = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);

        crypto = new Crypto();
        crypto.hashEidToPid(EID, pid);
        crypto.setSmdpPublicKey(TEST_SMDP_PUBLIC_KEY, (short) 0, (short) TEST_SMDP_PUBLIC_KEY.length);
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

        if (ins != INS_RSP) {
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }

        // SGP.22 5.7.2 / ES10x Transport Command:
        // CLA SHALL be in range 0x80-0x83 or 0xC0-0xCF.
        if (!Apdu.isTransportCla(claNoChain)) {
            apduHandler.reset();
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        byte ingestResult = apduHandler.ingest(apdu, cla, ins);
        if (ingestResult == Apdu.RESULT_MORE_SEGMENTS) {
            return;
        }

        short payloadLen = apduHandler.getLength();
        short decodeReason = 0;
        boolean decodeFailed = false;
        try {
            asn1.decode(apduHandler.getBuffer(), payloadLen, decodedMessage);
        } catch (ISOException ex) {
            decodeFailed = true;
            decodeReason = ex.getReason();
        } catch (Throwable t) {
            decodeFailed = true;
            decodeReason = SW_INVALID_DATA_FIELD;
        }
        apduHandler.reset();
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
        } else if (decodedMessage.type == Asn1.TYPE_BOUND_PROFILE_PACKAGE) {
            handleLoadBoundProfilePackage(apdu);
        } else {
            ISOException.throwIt(SW_UNSUPPORTED_COMMAND_DATA);
        }

        if (!pendingResponse.isActive()) {
            apduHandler.reset();
        }
    }

    private void stageAndSendResponse(APDU apdu, short len) {
        pendingResponse.stageAndSend(apdu, len);
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

    private void handlePrepareDownload(APDU apdu) {
        try {
            rememberSessionTxId(decodedMessage.txId, decodedMessage.txIdLen);
            if (!verifyPrepareDownloadSignature()) {
                sendPrepareDownloadError(apdu, decodedMessage.txId, decodedMessage.txIdLen, (short) 0x02);
                return;
            }
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
        rememberSessionTxId(decodedMessage.txId, decodedMessage.txIdLen);
        short responseLen = buildProfileInstallationResult(assembledApdu, (short) 0, decodedMessage.txId, decodedMessage.txIdLen);
        clearSessionState();
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
        euiccChallengeReady = false;
        euiccChallengeLen = 0;
        sessionTxIdLen = 0;
        sessionActive = false;
        Util.arrayFillNonAtomic(euiccChallenge, (short) 0, (short) euiccChallenge.length, (byte) 0x00);
        Util.arrayFillNonAtomic(sessionTxId, (short) 0, (short) sessionTxId.length, (byte) 0x00);
    }

    private boolean verifyPrepareDownloadSignature() {
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
        return crypto.verifySignature(crypto.getSmdpPublicKey(), assembledApdu, (short) 0, pos,
                decodedMessage.smdpSignature2, (short) 0, decodedMessage.smdpSignature2Len);
    }

    private boolean verifyAuthenticateServerSignature() {
        short pos = 0;
        assembledApdu[pos++] = 0x30;
        short lenPos = pos++;

        pos = TlvWriter.appendTlv(assembledApdu, pos, (short) 0x80, decodedMessage.txId, (short) 0, decodedMessage.txIdLen);
        pos = TlvWriter.appendTlv(assembledApdu, pos, (short) 0x81, decodedMessage.euiccChallenge, (short) 0, decodedMessage.euiccChallengeLen);
        pos = TlvWriter.appendTlv(assembledApdu, pos, (short) 0x83, decodedMessage.serverAddress, (short) 0, decodedMessage.serverAddressLen);
        pos = TlvWriter.appendTlv(assembledApdu, pos, (short) 0x84, decodedMessage.serverChallenge, (short) 0, decodedMessage.serverChallengeLen);

        assembledApdu[lenPos] = (byte) (pos - lenPos - 1);
        return crypto.verifySignature(crypto.getSmdpPublicKey(), assembledApdu, (short) 0, pos,
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
        short pos = off;
        byte[] publicKey = pubKeyBuf;
        short publicKeyLen = crypto.exportPublicKey(publicKey, (short) 0);

        short signedLen = 0;
        signedLen = TlvWriter.appendTlv(assembledApdu, signedLen, (short) 0x80, txId, (short) 0, txIdLen);
        signedLen = TlvWriter.appendTlv(assembledApdu, signedLen, TAG_APP_73, publicKey, (short) 0, publicKeyLen);

        short sigLen = crypto.sign(assembledApdu, (short) 0, signedLen, sigBuf, (short) 0);
        sigLen = derEcdsaToRaw(sigBuf, (short) 0, sigLen, sigBuf, (short) 0);

        out[pos++] = (byte) 0xBF;
        out[pos++] = 0x21;
        out[pos++] = (byte) 0x81;
        short outerLenPos = pos++;

        short seqStart = pos;
        out[pos++] = 0x30;
        short seqLenPos = pos++;
        short seqValueStart = pos;

        pos = TlvWriter.appendTlv(out, pos, (short) 0x80, txId, (short) 0, txIdLen);
        pos = TlvWriter.appendTlv(out, pos, TAG_APP_73, publicKey, (short) 0, publicKeyLen);

        out[seqLenPos] = (byte) (pos - seqValueStart);

        pos = TlvWriter.appendTlv(out, pos, TAG_APP_55, sigBuf, (short) 0, sigLen);
        out[outerLenPos] = (byte) (pos - off - 4);
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
        short eligBodyLen = encodedTlvSize((short) 0x80, (short) HARDCODED_HPID.length);
        eligBodyLen = (short) (eligBodyLen + encodedTlvSize((short) 0x81, (short) HARDCODED_SIG_CRED.length));
        eligBodyLen = (short) (eligBodyLen + encodedTlvSize((short) 0x82, (short) HARDCODED_AUTH_TOKEN.length));
        eligBodyLen = (short) (eligBodyLen + encodedTlvSize((short) 0x83, (short) HARDCODED_ACC_ROOT.length));
        eligBodyLen = (short) (eligBodyLen + encodedTlvSize((short) 0x84, (short) HARDCODED_SIG_ROOT.length));
        eligBodyLen = (short) (eligBodyLen + encodedTlvSize((short) 0x85, (short) HARDCODED_ACC_PROOF.length));
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
        short choiceLen = (short) (euiccSigned1Len + sigTlvLen + 2 + 2);
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
        pos = TlvWriter.appendTlv(out, pos, (short) 0x80, HARDCODED_HPID, (short) 0, (short) HARDCODED_HPID.length);
        pos = TlvWriter.appendTlv(out, pos, (short) 0x81, HARDCODED_SIG_CRED, (short) 0, (short) HARDCODED_SIG_CRED.length);
        pos = TlvWriter.appendTlv(out, pos, (short) 0x82, HARDCODED_AUTH_TOKEN, (short) 0, (short) HARDCODED_AUTH_TOKEN.length);
        pos = TlvWriter.appendTlv(out, pos, (short) 0x83, HARDCODED_ACC_ROOT, (short) 0, (short) HARDCODED_ACC_ROOT.length);
        pos = TlvWriter.appendTlv(out, pos, (short) 0x84, HARDCODED_SIG_ROOT, (short) 0, (short) HARDCODED_SIG_ROOT.length);
        pos = TlvWriter.appendTlv(out, pos, (short) 0x85, HARDCODED_ACC_PROOF, (short) 0, (short) HARDCODED_ACC_PROOF.length);

        short sigLen = crypto.sign(out, signedStart, euiccSigned1Len, sigBuf, (short) 0);
        sigLen = derEcdsaToRaw(sigBuf, (short) 0, sigLen, sigBuf, (short) 0);

        pos = TlvWriter.appendTlv(out, pos, TAG_APP_55, sigBuf, (short) 0, sigLen);
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
        // PrepareDownloadResponse ::= [33] CHOICE { downloadResponseError SEQUENCE { transactionId [0], downloadErrorCode } }
        byte[] out = assembledApdu;
        short pos = 0;

        out[pos++] = (byte) 0xBF;
        out[pos++] = 0x21;
        short lenPos = pos++;

        short seqStart = pos;
        out[pos++] = 0x30;
        short seqLenPos = pos++;

        out[pos++] = (byte) 0x80;
        out[pos++] = (byte) txIdLen;
        Util.arrayCopyNonAtomic(txId, (short) 0, out, pos, txIdLen);
        pos = (short) (pos + txIdLen);

        out[pos++] = 0x02;
        out[pos++] = 0x01;
        out[pos++] = (byte) errCode;

        out[seqLenPos] = (byte) (pos - seqStart - 2);
        out[lenPos] = (byte) (pos - 3);

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
        out[pos++] = 0x03;
        out[pos++] = 0x02;
        out[pos++] = 0x01;
        out[pos++] = errCode;

        stageAndSendResponse(apdu, pos);
    }

}
