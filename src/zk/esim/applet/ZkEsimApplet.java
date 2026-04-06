package zk.esim.applet;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;

public final class ZkEsimApplet extends Applet {

    private static final byte INS_RSP = (byte) 0xE2;
    private static final byte INS_GET_RESPONSE = (byte) 0xC0;

    // Keep this bounded for simulator/card memory constraints while still supporting APDU chaining.
    private static final short MAX_REASSEMBLED_APDU = (short) 2048;
    private static final short MAX_CHUNK_SIZE = (short) 256;
    private static final short SW_UNDEFINED_ERROR = (short) 127;
    private static final short SW_INVALID_DATA_FIELD = (short) 0x6A80;
    private static final short SW_UNSUPPORTED_COMMAND_DATA = (short) 0x6A88;
    private static final short SW_CONDITIONS_NOT_SATISFIED = (short) 0x6985;
    private static final short TAG_APP_55 = (short) 0x5F37;
    private static final short TAG_APP_73 = (short) 0x5F49;
        private static final byte[] DEFAULT_APPLET_AID = {
            (byte) 0xD0, (byte) 0x70, (byte) 0x02, (byte) 0xCA,
            (byte) 0x44, (byte) 0x90, (byte) 0x01, (byte) 0x01
        };

    // Random attributes (used for randomness)
    private RandomData rnd;
    private byte[] rSeedBuf;
    private byte[] rBuf;


    // UE keys
    private KeyPair kp;
    private PublicKey uPk;
    private PrivateKey uSk;

    // UE attributes
        private final byte[] EID = {
            (byte) '8', (byte) '9', (byte) '0', (byte) '4', (byte) '9', (byte) '0', (byte) '3', (byte) '2',
            (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0',
            (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '1', (byte) '2', (byte) '3', (byte) '4',
            (byte) '5', (byte) '6', (byte) '7', (byte) '8', (byte) '9', (byte) '0', (byte) '1', (byte) '2'
        };
    private byte[] pid;

    // Key variables for ECIES (ie encrypting the EID)
     private KeyAgreement ka;
     private KeyBuilder aesKeyBuilder;

    // Other entity keys
    private ECPublicKey smdpPk;

    // Key Agreement and Derivation variables
    private byte[] sharedSecret;
    private byte[] sessionKey;


    // Signature verification values
    private Signature signature;
    private byte[] pubKeyBuf;
    private byte[] msgBuf;
    private byte[] sigBuf;
    private short pubKeyLen;
    private short msgLen;
    private short sigLen;

    // Certificate buffer variables
    // TODO - update buffer sizes if needed - depends on size of values sent
    // TODO - length values are set through the receive function - needs to be done through instructions?
    private byte[] serialBuf = new byte[32];
    private short serialLen;
    private byte[] sigAlgBuf = new byte[32];
    private short sigAlgLen;
    private byte[] issuerBuf = new byte[128];
    private short issuerLen;
    private byte[] validityBuf = new byte[64];
    private short validityLen;
    private byte[] subjectBuf = new byte[128];
    private short subjectLen;
    private byte[] spkiBuf = new byte[128];
    private short spkiLen;
    private byte[] certSigBuf = new byte[80];
    private short certSigLen;

    private byte[] reassembledApdu;
    private Apdu apduHandler;
    private Asn1 asn1;
    private Asn1.DecodedMessage decodedMessage;
    private final byte[] euiccChallenge;
    private short euiccChallengeLen;
    private boolean euiccChallengeReady;
    private Apdu.PendingResponse pendingResponse;
    private boolean cryptoReady;

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new ZkEsimApplet(bArray, bOffset, bLength);
    }

    private ZkEsimApplet(byte[] bArray, short bOffset, byte bLength) {

        pubKeyBuf = new byte[65];
        msgBuf = new byte[256];
        sigBuf = new byte[80];

        rBuf = new byte[32];
        pid = new byte[48];

        reassembledApdu = new byte[MAX_REASSEMBLED_APDU];
        apduHandler = new Apdu(reassembledApdu);
        asn1 = new Asn1();
        decodedMessage = new Asn1.DecodedMessage();
        euiccChallenge = new byte[16];
        euiccChallengeLen = 0;
        euiccChallengeReady = false;
        pendingResponse = new Apdu.PendingResponse(MAX_REASSEMBLED_APDU, MAX_CHUNK_SIZE);
        cryptoReady = false;

        rnd = RandomDataUtil.createRandom();

        MessageDigest hash = MessageDigest.getInstance(MessageDigest.ALG_SHA_384, false);
        hash.doFinal(EID, (short) 0, (short) EID.length, pid, (short) 0);

        // Defer optional crypto primitive initialization for simulator compatibility.
        cryptoReady = false;

        registerApplet(bArray, bOffset, bLength);
    }

    private void registerApplet(byte[] bArray, short bOffset, byte bLength) {
        short totalLen = (short) (bLength & 0xFF);
        if (totalLen > 0 && bArray != null) {
            try {
                short aidLenOff = bOffset;
                if (aidLenOff >= 0) {
                    short aidLen = (short) (bArray[aidLenOff] & 0xFF);
                    short aidOff = (short) (aidLenOff + 1);
                    short end = (short) (bOffset + totalLen);
                    if (aidLen > 0 && (short) (aidOff + aidLen) <= end) {
                        register(bArray, aidOff, (byte) aidLen);
                        return;
                    }
                }
            } catch (Exception e) {
                // fall through to deterministic fallback registration
            }
        }

        try {
            register(DEFAULT_APPLET_AID, (short) 0, (byte) DEFAULT_APPLET_AID.length);
        } catch (Exception e) {
            register();
        }
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
            ISOException.throwIt(decodeReason);
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
        if (rnd != null) {
            RandomDataUtil.fillRandom(rnd, euiccChallenge, (short) 0, (short) euiccChallenge.length);
        } else {
            short i = 0;
            while (i < (short) euiccChallenge.length) {
                euiccChallenge[i] = (byte) (0xA0 + i);
                i++;
            }
        }
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
        short publicKeyLen = 1;
        publicKey[0] = (byte) 0x00;
        if (cryptoReady && uPk != null) {
            publicKeyLen = ((ECPublicKey) uPk).getW(publicKey, (short) 0);
        }

        short signedLen = 0;
        signedLen = TlvWriter.appendTlv(msgBuf, signedLen, (short) 0x80, txId, (short) 0, txIdLen);
        signedLen = TlvWriter.appendTlv(msgBuf, signedLen, TAG_APP_73, publicKey, (short) 0, publicKeyLen);

        short sigLen = 1;
        sigBuf[0] = (byte) 0x00;
        if (cryptoReady && signature != null && uSk != null) {
            signature.init(uSk, Signature.MODE_SIGN);
            sigLen = signature.sign(msgBuf, (short) 0, signedLen, sigBuf, (short) 0);
        }

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

        short sigLen = 1;
        sigBuf[0] = (byte) 0x00;
        if (cryptoReady && signature != null && uSk != null) {
            signature.init(uSk, Signature.MODE_SIGN);
            sigLen = signature.sign(msgBuf, (short) 0, signedLen, sigBuf, (short) 0);
        }

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

    /***
     * Used to generate random values
     *
     * @param seedBytes The seed for randomness (for repeatability - remove for more security)
     * @param out       The buffer to output the data to
     */
    private void generateRandom(byte[] seedBytes, byte[] out) {
        if (rnd == null) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        rnd.setSeed(seedBytes, (short) 0, (short) seedBytes.length);
        RandomDataUtil.fillRandom(rnd, out, (short) 0, (short) out.length);
    }

    /***
     * Used to setup UE-based variables and components
     */
    private void setupUE() {

        rSeedBuf = new byte[] {
            (byte) 'T', (byte) 'h', (byte) 'i', (byte) 's', (byte) ' ', (byte) 'i', (byte) 's', (byte) ' ',
            (byte) 'a', (byte) ' ', (byte) 's', (byte) 'e', (byte) 'e', (byte) 'd'
        };

        signature = Signature.getInstance(Signature.ALG_ECDSA_SHA, false);

        kp = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
        kp.genKeyPair();

        uSk = kp.getPrivate();
        uPk = kp.getPublic();
    }

    /***
     *
     * @return
     */
    private byte[] encryptEID() {
        AESKey aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
        RandomData rand = rnd != null ? rnd : RandomDataUtil.createRandom();
        if (rand == null) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        byte[] keyBytes = new byte[16];

        RandomDataUtil.fillRandom(rand, keyBytes, (short) 0, (short) keyBytes.length);
        aesKey.setKey(keyBytes, (short) 0);

        Cipher cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        cipher.init(aesKey, Cipher.MODE_ENCRYPT);
        cipher.doFinal(EID, (short) 0, (short) EID.length, keyBytes, (short) 0);
        return keyBytes;
    }

    /**
     * Key agreement function used between the SM-DP and EUICC for the session key for profile
     * delivery
     */
    private void keyAgreement() {
        ka.init(uSk);
        byte[] smdpBytes = new byte[smdpPk.getSize()];
        smdpPk.getW(smdpBytes,  (short) 0);
        ka.generateSecret(smdpBytes, (short) 0, smdpPk.getSize(), sharedSecret, (short) 0);

        MessageDigest hash = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        hash.doFinal(sharedSecret, (short) 0, (short) sharedSecret.length, sessionKey, (short) 0);

    }

    /***
     * Used to verify a signature received from an APDU packet
     *
     * @param apdu  The packet containing the data
     * @return      The output of the verification (protocol should be cancelled on a fail)
     */
    private boolean verifySignature(APDU apdu) {

        byte[] buf = apdu.getBuffer();
        apdu.setIncomingAndReceive();
        short offset = ISO7816.OFFSET_CDATA;

        // Extract public key
        pubKeyLen = (short) (buf[offset] & 0xFF);
        offset++;
        Util.arrayCopy(buf, offset, pubKeyBuf, (short) 0, pubKeyLen);
        smdpPk.setW(pubKeyBuf, (short) 0, pubKeyLen);
        offset += pubKeyLen;

        // Extract message
        msgLen = Util.getShort(buf, offset);
        offset += 2;
        Util.arrayCopy(buf, offset, msgBuf, (short) 0, msgLen);
        offset += msgLen;

        // Extract signature
        sigLen = (short) (buf[offset] & 0xFF);
        offset++;
        Util.arrayCopy(buf, offset, sigBuf, (short) 0, sigLen);
        signature.init(smdpPk, Signature.MODE_VERIFY);

        return signature.verify(
                msgBuf, (short) 0, msgLen,
                sigBuf, (short) 0, sigLen
        );
    }

    /***
     * Used to "build" the certificate - assigns the values in the buffer
     *
     * @param out       The output buffer for the built certificate
     * @param offset    Offset needed for the packet data
     * @return          returns the length of the certificate (wrapped sequence)
     */
    private short buildCertificate(byte[] out, short offset) {

        byte[] temp = new byte[512];
        short off = 0;

        Util.arrayCopy(serialBuf, (short) 0, temp, off, serialLen);
        off += serialLen;

        Util.arrayCopy(sigAlgBuf, (short) 0, temp, off, sigAlgLen);
        off += sigAlgLen;

        Util.arrayCopy(issuerBuf, (short) 0, temp, off, issuerLen);
        off += issuerLen;

        Util.arrayCopy(validityBuf, (short) 0, temp, off, validityLen);
        off += validityLen;

        Util.arrayCopy(subjectBuf, (short) 0, temp, off, subjectLen);
        off += subjectLen;

        Util.arrayCopy(spkiBuf, (short) 0, temp, off, spkiLen);
        off += spkiLen;

        return wrapSequence(temp, off, out, offset);
    }

    /***
     * Verifies the certificate information through verifying the signature
     * @param apdu
     */
    private void verifyCertificate(APDU apdu) {

        byte[] cert = new byte[512];
        short tbsLen = buildCertificate(cert, (short)0);

        signature.init(smdpPk, Signature.MODE_VERIFY);

        boolean valid = signature.verify(
                cert, (short)0, tbsLen,
                certSigBuf, (short)0, certSigLen
        );

        byte[] buf = apdu.getBuffer();
        buf[0] = (byte)(valid ? 1 : 0);
        apdu.setOutgoingAndSend((short)0, (short)1);
    }

    /***
     *
     */
    private void generateZKP() {
        byte[] x; byte[] w = generateWitness();
    }

    /***
     *
     * @return
     */
    private byte[] generateWitness() {
        return null;
    }

    /***
     * Wraps APDU certificate information into a separate buffer containing allof the information
     * @param data
     * @param len
     * @param out
     * @param off
     * @return
     */
    private short wrapSequence(byte[] data, short len, byte[] out, short off) {
        out[off++] = 0x30;

        if (len < 128) {
            out[off++] = (byte)len;
        } else {
            out[off++] = (byte)0x81;
            out[off++] = (byte)len;
        }

        Util.arrayCopy(data, (short)0, out, off, len);
        return (short)(off + len);
    }
}