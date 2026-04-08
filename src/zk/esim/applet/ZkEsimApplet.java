package zk.esim.applet;

import javacard.framework.*;

public final class ZkEsimApplet extends Applet {

    private static final byte INS_RSP = (byte) 0xE2;
    private static final byte INS_GET_RESPONSE = (byte) 0xC0;

    // Keep this bounded for simulator/card memory constraints while still supporting APDU chaining.
    private static final short MAX_REASSEMBLED_APDU = (short) 2048;
    private static final short MAX_CHUNK_SIZE = (short) 256;
    private static final short SW_INVALID_DATA_FIELD = (short) 0x6A80;
    private static final short SW_UNSUPPORTED_COMMAND_DATA = (short) 0x6A88;
    private static final short SW_CONDITIONS_NOT_SATISFIED = (short) 0x6985;
    private static final short TAG_APP_55 = (short) 0x5F37;
    private static final short TAG_APP_73 = (short) 0x5F49;
        private static final byte[] DEFAULT_APPLET_AID = {
            (byte) 0xD0, (byte) 0x70, (byte) 0x02, (byte) 0xCA,
            (byte) 0x44, (byte) 0x90, (byte) 0x01, (byte) 0x01
        };

    // UE attributes
        private final byte[] EID = {
            (byte) '8', (byte) '9', (byte) '0', (byte) '4', (byte) '9', (byte) '0', (byte) '3', (byte) '2',
            (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0',
            (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '1', (byte) '2', (byte) '3', (byte) '4',
            (byte) '5', (byte) '6', (byte) '7', (byte) '8', (byte) '9', (byte) '0', (byte) '1', (byte) '2'
        };
    private byte[] pid;

    private Crypto crypto;

    private byte[] pubKeyBuf;
    private byte[] msgBuf;
    private byte[] sigBuf;

    private byte[] reassembledApdu;
    private Apdu apduHandler;
    private Asn1 asn1;
    private Asn1.DecodedMessage decodedMessage;
    private final byte[] euiccChallenge;
    private short euiccChallengeLen;
    private boolean euiccChallengeReady;
    private Apdu.PendingResponse pendingResponse;

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new ZkEsimApplet(bArray, bOffset, bLength);
    }

    private ZkEsimApplet(byte[] bArray, short bOffset, byte bLength) {

        pubKeyBuf = new byte[65];
        msgBuf = new byte[256];
        sigBuf = new byte[80];

        pid = new byte[48];

        reassembledApdu = new byte[MAX_REASSEMBLED_APDU];
        apduHandler = new Apdu(reassembledApdu);
        asn1 = new Asn1();
        decodedMessage = new Asn1.DecodedMessage();
        euiccChallenge = new byte[16];
        euiccChallengeLen = 0;
        euiccChallengeReady = false;
        pendingResponse = new Apdu.PendingResponse(MAX_REASSEMBLED_APDU, MAX_CHUNK_SIZE);

        crypto = new Crypto();
        crypto.hashEidToPid(EID, pid);

        registerApplet(bArray, bOffset, bLength);
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

        if (pendingResponse.isActive()) {
            if (ins != INS_GET_RESPONSE) {
                ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
            }
            if (buf[ISO7816.OFFSET_P1] != (byte) 0x00 || buf[ISO7816.OFFSET_P2] != (byte) 0x00) {
                ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
            }
            pendingResponse.sendChunk(apdu, true);
            return;
        }

        if (ins == INS_GET_RESPONSE) {
            ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
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
        } else if (decodedMessage.type == Asn1.TYPE_PREPARE_DOWNLOAD_REQUEST) {
            handlePrepareDownload(apdu);
        } else if (decodedMessage.type == Asn1.TYPE_AUTHENTICATE_SERVER_REQUEST) {
            handleAuthenticateServer(apdu);
        } else if (decodedMessage.type == Asn1.TYPE_BOUND_PROFILE_PACKAGE) {
            handleLoadBoundProfilePackage(apdu);
        } else {
            ISOException.throwIt(SW_UNSUPPORTED_COMMAND_DATA);
        }

        apduHandler.reset();
    }

    private void stageAndSendResponse(APDU apdu, byte[] src, short len) {
        pendingResponse.stageAndSend(apdu, src, len);
    }

    private void handleGetEuiccChallenge(APDU apdu) {
        crypto.fillRandom(euiccChallenge, (short) 0, (short) euiccChallenge.length);
        euiccChallengeLen = (short) euiccChallenge.length;
        euiccChallengeReady = true;

        short responseLen = buildGetEuiccChallengeResponse(msgBuf, (short) 0);
        stageAndSendResponse(apdu, msgBuf, responseLen);
    }

    private void handlePrepareDownload(APDU apdu) {
        short responseLen = buildPrepareDownloadResponse(msgBuf, (short) 0, decodedMessage.txId, decodedMessage.txIdLen);
        stageAndSendResponse(apdu, msgBuf, responseLen);
    }

    private void handleAuthenticateServer(APDU apdu) {
        if (!euiccChallengeReady || decodedMessage.euiccChallengeLen != euiccChallengeLen ||
                !ByteArrayUtil.equals(decodedMessage.euiccChallenge, (short) 0, euiccChallenge, (short) 0, euiccChallengeLen)) {
            sendAuthenticateServerError(apdu, decodedMessage.txId, decodedMessage.txIdLen, (short) 0x06);
            return;
        }

        short responseLen = buildAuthenticateServerResponse(
                msgBuf,
                (short) 0,
                decodedMessage.txId,
                decodedMessage.txIdLen,
                decodedMessage.serverAddress,
                decodedMessage.serverAddressLen,
                decodedMessage.serverChallenge,
                decodedMessage.serverChallengeLen
        );
        stageAndSendResponse(apdu, msgBuf, responseLen);
    }

    private void handleLoadBoundProfilePackage(APDU apdu) {
        euiccChallengeReady = false;
        euiccChallengeLen = 0;
        Util.arrayFillNonAtomic(euiccChallenge, (short) 0, (short) euiccChallenge.length, (byte) 0x00);
        // No response payload is defined for the local load step.
    }

    private short buildGetEuiccChallengeResponse(byte[] out, short off) {
        short pos = 0;
        out[pos++] = (byte) 0xBF;
        out[pos++] = (byte) 0x2E;
        short outerLenPos = pos++;

        short seqStart = pos;
        out[pos++] = (byte) 0x30;
        short seqLenPos = pos++;
        short seqValueStart = pos;
        out[pos++] = (byte) 0x04;
        pos = TlvWriter.writeLength(out, pos, euiccChallengeLen);
        Util.arrayCopyNonAtomic(euiccChallenge, (short) 0, out, pos, euiccChallengeLen);
        pos = (short) (pos + euiccChallengeLen);

        out[seqLenPos] = (byte) (pos - seqValueStart);
        out[outerLenPos] = (byte) (pos - seqStart);
        return pos;
    }

    private short buildPrepareDownloadResponse(byte[] out, short off, byte[] txId, short txIdLen) {
        short pos = off;
        byte[] publicKey = pubKeyBuf;
        short publicKeyLen = crypto.exportPublicKey(publicKey, (short) 0);

        short signedLen = 0;
        signedLen = TlvWriter.appendTlv(msgBuf, signedLen, (short) 0x80, txId, (short) 0, txIdLen);
        signedLen = TlvWriter.appendTlv(msgBuf, signedLen, TAG_APP_73, publicKey, (short) 0, publicKeyLen);

        short sigLen = crypto.sign(msgBuf, (short) 0, signedLen, sigBuf, (short) 0);

        out[pos++] = (byte) 0xBF;
        out[pos++] = (byte) 0x21;
        short outerLenPos = pos++;

        short seqStart = pos;
        out[pos++] = (byte) 0x30;
        short seqLenPos = pos++;
        short seqValueStart = pos;

        pos = TlvWriter.appendTlv(out, pos, (short) 0x80, txId, (short) 0, txIdLen);
        pos = TlvWriter.appendTlv(out, pos, TAG_APP_73, publicKey, (short) 0, publicKeyLen);

        out[seqLenPos] = (byte) (pos - seqValueStart);

        pos = TlvWriter.appendTlv(out, pos, TAG_APP_55, sigBuf, (short) 0, sigLen);
        out[outerLenPos] = (byte) (pos - seqStart);
        return pos;
    }

    private short buildAuthenticateServerResponse(byte[] out, short off, byte[] txId, short txIdLen,
                                                  byte[] serverAddress, short serverAddressLen,
                                                  byte[] serverChallenge, short serverChallengeLen) {
        short pos = off;

        short signedLen = 0;
        signedLen = TlvWriter.appendTlv(msgBuf, signedLen, (short) 0x80, txId, (short) 0, txIdLen);
        signedLen = TlvWriter.appendTlv(msgBuf, signedLen, (short) 0x83, serverAddress, (short) 0, serverAddressLen);
        signedLen = TlvWriter.appendTlv(msgBuf, signedLen, (short) 0x84, serverChallenge, (short) 0, serverChallengeLen);
        signedLen = TlvWriter.appendEmptySequence(msgBuf, signedLen);
        signedLen = TlvWriter.appendEmptySequence(msgBuf, signedLen);

        short sigLen = crypto.sign(msgBuf, (short) 0, signedLen, sigBuf, (short) 0);

        out[pos++] = (byte) 0xBF;
        out[pos++] = (byte) 0x38;
        short outerLenPos = pos++;

        short seqStart = pos;
        out[pos++] = (byte) 0x30;
        short seqLenPos = pos++;
        short seqValueStart = pos;

        pos = TlvWriter.appendTlv(out, pos, (short) 0x80, txId, (short) 0, txIdLen);
        pos = TlvWriter.appendTlv(out, pos, (short) 0x83, serverAddress, (short) 0, serverAddressLen);
        pos = TlvWriter.appendTlv(out, pos, (short) 0x84, serverChallenge, (short) 0, serverChallengeLen);
        pos = TlvWriter.appendEmptySequence(out, pos);
        pos = TlvWriter.appendEmptySequence(out, pos);

        out[seqLenPos] = (byte) (pos - seqValueStart);

        pos = TlvWriter.appendTlv(out, pos, TAG_APP_55, sigBuf, (short) 0, sigLen);
        pos = TlvWriter.appendEmptySequence(out, pos);
        pos = TlvWriter.appendEmptySequence(out, pos);

        out[outerLenPos] = (byte) (pos - seqStart);
        return pos;
    }

    private void sendPrepareDownloadError(APDU apdu, byte[] txId, short txIdLen, short errCode) {
        // PrepareDownloadResponse ::= [33] CHOICE { downloadResponseError SEQUENCE { transactionId [0], downloadErrorCode } }
        byte[] out = msgBuf;
        short pos = 0;

        out[pos++] = (byte) 0xBF;
        out[pos++] = (byte) 0x21;
        short lenPos = pos++;

        short seqStart = pos;
        out[pos++] = (byte) 0x30;
        short seqLenPos = pos++;

        out[pos++] = (byte) 0x80;
        out[pos++] = (byte) txIdLen;
        Util.arrayCopyNonAtomic(txId, (short) 0, out, pos, txIdLen);
        pos = (short) (pos + txIdLen);

        out[pos++] = (byte) 0x02;
        out[pos++] = (byte) 0x01;
        out[pos++] = (byte) errCode;

        out[seqLenPos] = (byte) (pos - seqStart - 2);
        out[lenPos] = (byte) (pos - 3);

        stageAndSendResponse(apdu, out, pos);
    }

    private void sendAuthenticateServerError(APDU apdu, byte[] txId, short txIdLen, short errCode) {
        // AuthenticateServerResponse ::= [56] CHOICE { authenticateResponseError SEQUENCE { transactionId [0], authenticateErrorCode } }
        byte[] out = msgBuf;
        short pos = 0;

        out[pos++] = (byte) 0xBF;
        out[pos++] = (byte) 0x38;
        short lenPos = pos++;

        short seqStart = pos;
        out[pos++] = (byte) 0x30;
        short seqLenPos = pos++;

        out[pos++] = (byte) 0x80;
        out[pos++] = (byte) txIdLen;
        Util.arrayCopyNonAtomic(txId, (short) 0, out, pos, txIdLen);
        pos = (short) (pos + txIdLen);

        out[pos++] = (byte) 0x02;
        out[pos++] = (byte) 0x01;
        out[pos++] = (byte) errCode;

        out[seqLenPos] = (byte) (pos - seqStart - 2);
        out[lenPos] = (byte) (pos - 3);

        stageAndSendResponse(apdu, out, pos);
    }

}