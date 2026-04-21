package zk.esim.applet;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.ECKey;
import javacard.security.Key;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.PrivateKey;
import javacard.security.PublicKey;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

/**
 * Shared cryptographic service for the applet.
 */
public final class Crypto {

    private static final short SCALAR_LEN = (short) 32;
    private static final short POINT_LEN = (short) 65;
    private static final short SW_CRYPTO_UNAVAILABLE = ISO7816.SW_CONDITIONS_NOT_SATISFIED;

    private static final byte[] DEFAULT_RANDOM_SEED = {
            (byte) 'T', (byte) 'h', (byte) 'i', (byte) 's', (byte) ' ', (byte) 'i', (byte) 's', (byte) ' ',
            (byte) 'a', (byte) ' ', (byte) 's', (byte) 'e', (byte) 'e', (byte) 'd'
    };


    private jcmathlib.ResourceManager rm;
    private jcmathlib.ECCurve curve;
    private final RandomData rnd;
    private MessageDigest sha256;
    private Signature signature;
    private KeyAgreement ka;

    private KeyPair kp;
    private PublicKey uPk;
    private PrivateKey uSk;

    private ECPublicKey smdpPk;
    private ECPublicKey mnoPk;
    private ECPublicKey leakPk;

    private byte[] rSeedBuf;
    private byte[] rBuf;
    private byte[] sharedSecret;
    private byte[] sessionKey;
    private byte[] sigEIDBuf;

    // Scratch buffers (transient RAM). Every method that formerly did `new byte[N]`
    // on JavaCard allocated persistent EEPROM that is never reclaimed — repeated
    // calls fragmented and exhausted EEPROM, surfacing as "insufficient memory"
    // during profile download. Reusing these shared transient buffers keeps the
    // hot paths allocation-free.
    private byte[] scratchAes16;      // AES key material in encryptEid
    private byte[] scratchScalar1;    // 32-byte scalar (digest / hash / tmp)
    private byte[] scratchScalar2;    // 32-byte scalar (xBuf in generateZkp, lives across generateX)
    private byte[] scratchPoint1;     // 65-byte point
    private byte[] scratchPoint2;     // 65-byte point (coexists with point1 in generateX)
    private byte[] scratchPoint3;     // 65-byte point (coexists with point1+point2 in generateX)
    private byte[] scratchCert;       // 512-byte buffer for verifyCertificate
    private byte[] scratchInput;      // 300-byte buffer for witness/x/input concatenations

    private static final short SCRATCH_CERT_LEN = (short) 512;
    private static final short SCRATCH_INPUT_LEN = (short) 300;

    public Crypto() {
        rnd = createRandom();
        if (rnd == null) {
            ISOException.throwIt(SW_CRYPTO_UNAVAILABLE);
        }

        try {
            sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        } catch (Throwable t) {
            ISOException.throwIt(SW_CRYPTO_UNAVAILABLE);
        }

        // Working buffers: session-scoped, no need to persist across deselect.
        rSeedBuf = JCSystem.makeTransientByteArray((short) DEFAULT_RANDOM_SEED.length, JCSystem.CLEAR_ON_DESELECT);
        Util.arrayCopyNonAtomic(DEFAULT_RANDOM_SEED, (short) 0, rSeedBuf, (short) 0, (short) DEFAULT_RANDOM_SEED.length);
        rBuf = JCSystem.makeTransientByteArray(SCALAR_LEN, JCSystem.CLEAR_ON_DESELECT);
        sharedSecret = JCSystem.makeTransientByteArray(POINT_LEN, JCSystem.CLEAR_ON_DESELECT);
        sessionKey = JCSystem.makeTransientByteArray(SCALAR_LEN, JCSystem.CLEAR_ON_DESELECT);
        sigEIDBuf = JCSystem.makeTransientByteArray((short) 80, JCSystem.CLEAR_ON_DESELECT);

        scratchAes16 = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);
        scratchScalar1 = JCSystem.makeTransientByteArray(SCALAR_LEN, JCSystem.CLEAR_ON_DESELECT);
        scratchScalar2 = JCSystem.makeTransientByteArray(SCALAR_LEN, JCSystem.CLEAR_ON_DESELECT);
        scratchPoint1 = JCSystem.makeTransientByteArray(POINT_LEN, JCSystem.CLEAR_ON_DESELECT);
        scratchPoint2 = JCSystem.makeTransientByteArray(POINT_LEN, JCSystem.CLEAR_ON_DESELECT);
        scratchPoint3 = JCSystem.makeTransientByteArray(POINT_LEN, JCSystem.CLEAR_ON_DESELECT);
        scratchCert = JCSystem.makeTransientByteArray(SCRATCH_CERT_LEN, JCSystem.CLEAR_ON_DESELECT);
        scratchInput = JCSystem.makeTransientByteArray(SCRATCH_INPUT_LEN, JCSystem.CLEAR_ON_DESELECT);

        initAsymmetric();
    }

    public void hashEidToPid(byte[] eid, byte[] pidOut) {
        sha256.reset();
        sha256.doFinal(eid, (short) 0, (short) eid.length, pidOut, (short) 0);
    }

    public void fillRandom(byte[] out, short off, short len) {
        fillRandomData(rnd, out, off, len);
    }

    public void generateRandom(byte[] seedBytes, byte[] out) {
        rnd.setSeed(seedBytes, (short) 0, (short) seedBytes.length);
        fillRandomData(rnd, out, (short) 0, (short) out.length);
    }

    public short exportPublicKey(byte[] out, short off) {
        return ((ECPublicKey) uPk).getW(out, off);
    }

    public short sign(byte[] msg, short msgOff, short msgLen, byte[] sigOut, short sigOff) {
        signature.init(uSk, Signature.MODE_SIGN);
        return signature.sign(msg, msgOff, msgLen, sigOut, sigOff);
    }

    public boolean verifySignature(ECPublicKey signerPk, byte[] msg, short msgOff, short msgLen,
                                   byte[] sigBuf, short sigOff, short sigLen) {
        signature.init(signerPk, Signature.MODE_VERIFY);
        if (sigLen != 64) {
            return false;
        }
        // Reuse sigEIDBuf as scratch for DER conversion — it is only used by
        // generateZkp() which is never called during the ES10b BF38 flow.
        // Reset byte 0 afterwards so generateWitness() cache check stays valid.
        short derSigLen = ecdsaRawToDer(sigBuf, sigOff, sigLen, sigEIDBuf, (short) 0);
        if (derSigLen < 0) {
            return false;
        }
        boolean result = signature.verify(msg, msgOff, msgLen, sigEIDBuf, (short) 0, derSigLen);
        sigEIDBuf[0] = 0x00;
        return result;
    }

    private short ecdsaRawToDer(byte[] rawSig, short rawOff, short rawLen, byte[] derOut, short derOff) {
        if (rawLen != 64) {
            return (short) -1;
        }

        short rLen = derIntegerLength(rawSig, rawOff, (short) 32);
        short sLen = derIntegerLength(rawSig, (short) (rawOff + 32), (short) 32);
        short seqLen = (short) (rLen + sLen);
        short pos = derOff;

        derOut[pos++] = 0x30;
        derOut[pos++] = (byte) seqLen;
        pos = writeDerInteger(rawSig, rawOff, (short) 32, derOut, pos);
        pos = writeDerInteger(rawSig, (short) (rawOff + 32), (short) 32, derOut, pos);
        return (short) (pos - derOff);
    }

    private short derIntegerLength(byte[] value, short valueOff, short valueLen) {
        short start = valueOff;
        short end = (short) (valueOff + valueLen);

        while (start < (short) (end - 1) && value[start] == 0x00) {
            start++;
        }

        short len = (short) (end - start);
        if ((value[start] & 0x80) != 0) {
            len++;
        }
        return (short) (2 + len);
    }

    private short writeDerInteger(byte[] value, short valueOff, short valueLen, byte[] out, short outOff) {
        short start = valueOff;
        short end = (short) (valueOff + valueLen);

        while (start < (short) (end - 1) && value[start] == 0x00) {
            start++;
        }

        short len = (short) (end - start);
        short pos = outOff;

        out[pos++] = 0x02;
        if ((value[start] & 0x80) != 0) {
            out[pos++] = (byte) (len + 1);
            out[pos++] = 0x00;
        } else {
            out[pos++] = (byte) len;
        }

        Util.arrayCopyNonAtomic(value, start, out, pos, len);
        pos = (short) (pos + len);
        return pos;
    }

    // public boolean verifySignature(APDU apdu, byte[] pubKeyBuf, byte[] msgBuf, byte[] sigBuf) {
    //     byte[] buf = apdu.getBuffer();
    //     apdu.setIncomingAndReceive();
    //     short offset = ISO7816.OFFSET_CDATA;

    //     short pubKeyLen = (short) (buf[offset] & 0xFF);
    //     offset++;
    //     Util.arrayCopy(buf, offset, pubKeyBuf, (short) 0, pubKeyLen);
    //     smdpPk.setW(pubKeyBuf, (short) 0, pubKeyLen);
    //     offset += pubKeyLen;

    //     short msgLen = Util.getShort(buf, offset);
    //     offset += 2;
    //     Util.arrayCopy(buf, offset, msgBuf, (short) 0, msgLen);
    //     offset += msgLen;

    //     short sigLen = (short) (buf[offset] & 0xFF);
    //     offset++;
    //     Util.arrayCopy(buf, offset, sigBuf, (short) 0, sigLen);

    //     signature.init(smdpPk, Signature.MODE_VERIFY);
    //     return signature.verify(msgBuf, (short) 0, msgLen, sigBuf, (short) 0, sigLen);
    // }

    public byte[] encryptEid(byte[] eid) {
        AESKey aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);

        fillRandomData(rnd, scratchAes16, (short) 0, (short) 16);
        aesKey.setKey(scratchAes16, (short) 0);

        Cipher cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        cipher.init(aesKey, Cipher.MODE_ENCRYPT);
        cipher.doFinal(eid, (short) 0, (short) eid.length, scratchAes16, (short) 0);

        // Returned buffer must be distinct from the shared scratch so callers can
        // compare successive ciphertexts — make a snapshot.
        byte[] out = new byte[16];
        Util.arrayCopyNonAtomic(scratchAes16, (short) 0, out, (short) 0, (short) 16);
        return out;
    }

    public short deriveSessionKey(ECPublicKey peerPk, byte[] sharedOut, short sharedOff, byte[] sessionOut, short sessionOff) {
        ka.init(uSk);
        short peerLen = peerPk.getW(scratchPoint1, (short) 0);
        short sharedLen = ka.generateSecret(scratchPoint1, (short) 0, peerLen, sharedOut, sharedOff);

        sha256.reset();
        sha256.doFinal(sharedOut, sharedOff, sharedLen, sessionOut, sessionOff);
        return sharedLen;
    }

    public short buildCertificate(byte[] serialBuf, short serialLen,
                                  byte[] sigAlgBuf, short sigAlgLen,
                                  byte[] issuerBuf, short issuerLen,
                                  byte[] validityBuf, short validityLen,
                                  byte[] subjectBuf, short subjectLen,
                                  byte[] spkiBuf, short spkiLen,
                                  byte[] out, short offset) {
        // Write the SEQUENCE header with length known up-front, then concatenate
        // fields directly into `out`. No staging buffer needed.
        short totalLen = (short) (serialLen + sigAlgLen + issuerLen + validityLen + subjectLen + spkiLen);
        short pos = offset;
        out[pos++] = 0x30;
        if (totalLen < 128) {
            out[pos++] = (byte) totalLen;
        } else {
            out[pos++] = (byte) 0x81;
            out[pos++] = (byte) totalLen;
        }

        Util.arrayCopy(serialBuf, (short) 0, out, pos, serialLen);
        pos += serialLen;
        Util.arrayCopy(sigAlgBuf, (short) 0, out, pos, sigAlgLen);
        pos += sigAlgLen;
        Util.arrayCopy(issuerBuf, (short) 0, out, pos, issuerLen);
        pos += issuerLen;
        Util.arrayCopy(validityBuf, (short) 0, out, pos, validityLen);
        pos += validityLen;
        Util.arrayCopy(subjectBuf, (short) 0, out, pos, subjectLen);
        pos += subjectLen;
        Util.arrayCopy(spkiBuf, (short) 0, out, pos, spkiLen);
        pos += spkiLen;
        return pos;
    }

    public boolean verifyCertificate(ECPublicKey signerPk,
                                     byte[] serialBuf, short serialLen,
                                     byte[] sigAlgBuf, short sigAlgLen,
                                     byte[] issuerBuf, short issuerLen,
                                     byte[] validityBuf, short validityLen,
                                     byte[] subjectBuf, short subjectLen,
                                     byte[] spkiBuf, short spkiLen,
                                     byte[] certSigBuf, short certSigLen) {
        short tbsLen = buildCertificate(
                serialBuf, serialLen,
                sigAlgBuf, sigAlgLen,
                issuerBuf, issuerLen,
                validityBuf, validityLen,
                subjectBuf, subjectLen,
                spkiBuf, spkiLen,
                scratchCert, (short) 0);

        signature.init(signerPk, Signature.MODE_VERIFY);
        return signature.verify(scratchCert, (short) 0, tbsLen, certSigBuf, (short) 0, certSigLen);
    }

    public short generateSigEid(byte[] eid, byte[] outSig, short outOff) {
        signature.init(uSk, Signature.MODE_SIGN);

        sha256.reset();
        sha256.doFinal(eid, (short) 0, (short) eid.length, scratchScalar1, (short) 0);

        short sigLen = signature.sign(scratchScalar1, (short) 0, SCALAR_LEN, outSig, outOff);
        Util.arrayCopyNonAtomic(outSig, outOff, sigEIDBuf, (short) 0, sigLen);
        return sigLen;
    }

    public short generateZkp(byte[] eid,
                             byte[] pid,
                             byte[] nonce,
                             byte[] outS, short outOff,
                             byte[] outT, short outTOff) {
        ensureZkInitialized();
        jcmathlib.BigNat wScalar = new jcmathlib.BigNat(SCALAR_LEN, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);
        jcmathlib.BigNat xScalar = new jcmathlib.BigNat(SCALAR_LEN, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);
        generateWitness(eid, wScalar);
        generateX(pid, nonce, xScalar);

        jcmathlib.BigNat r = new jcmathlib.BigNat(SCALAR_LEN, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);
        generateRandomScalar(r);

        jcmathlib.ECPoint tPoint = new jcmathlib.ECPoint(curve);
        tPoint.setW(jcmathlib.SecP256r1.G, (short) 0, (short) jcmathlib.SecP256r1.G.length);
        tPoint.multiplication(r);
        short tLen = tPoint.getW(outT, outTOff);

        // scratchScalar2 holds xBuf across computeChallenge; scratchPoint1 holds tBuf.
        xScalar.copyToByteArray(scratchScalar2, (short) 0);
        Util.arrayCopyNonAtomic(outT, outTOff, scratchPoint1, (short) 0, tLen);

        jcmathlib.BigNat c = new jcmathlib.BigNat(SCALAR_LEN, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);
        computeChallenge(scratchScalar2, SCALAR_LEN, scratchPoint1, tLen, c);

        jcmathlib.BigNat s = new jcmathlib.BigNat(SCALAR_LEN, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);
        computeResponse(r, c, wScalar, s);
        s.copyToByteArray(outS, outOff);
        return tLen;
    }

    public void setSmdpPublicKey(byte[] w, short off, short len) {
        smdpPk.setW(w, off, len);
    }

    public ECPublicKey getSmdpPublicKey() {
        return smdpPk;
    }

    public ECPublicKey getDevicePublicKey() {
        return (ECPublicKey) uPk;
    }

    public PrivateKey getDevicePrivateKey() {
        return uSk;
    }

    public byte[] getSharedSecretBuffer() {
        return sharedSecret;
    }

    public byte[] getSessionKeyBuffer() {
        return sessionKey;
    }

    public byte[] getSeedBuffer() {
        return rSeedBuf;
    }

    public byte[] getRandomBuffer() {
        return rBuf;
    }

    private void generateWitness(byte[] eid, jcmathlib.BigNat outWitness) {
        short privLen = (short) (((ECPrivateKey) uSk).getSize() / 8);
        byte[] uSkBuf = new byte[privLen];
        ((ECPrivateKey) uSk).getS(uSkBuf, (short) 0);

        if (sigEIDBuf[0] == 0x00) {
            generateSigEid(eid, sigEIDBuf, (short) 0);
        }

        generateRandom(rSeedBuf, rBuf);

        byte[] witnessInput = new byte[(short) (eid.length + uSkBuf.length + rSeedBuf.length + sigEIDBuf.length + rBuf.length)];
        short idx = 0;
        Util.arrayCopy(eid, (short) 0, witnessInput, idx, (short) eid.length);
        idx += (short) eid.length;
        Util.arrayCopy(uSkBuf, (short) 0, witnessInput, idx, (short) uSkBuf.length);
        idx += (short) uSkBuf.length;
        Util.arrayCopy(rSeedBuf, (short) 0, witnessInput, idx, (short) rSeedBuf.length);
        idx += (short) rSeedBuf.length;
        Util.arrayCopy(sigEIDBuf, (short) 0, witnessInput, idx, (short) sigEIDBuf.length);
        idx += (short) sigEIDBuf.length;
        Util.arrayCopy(rBuf, (short) 0, witnessInput, idx, (short) rBuf.length);

        hashToScalar(witnessInput, outWitness);
    }

    private void generateX(byte[] pid, byte[] nonce, jcmathlib.BigNat outX) {
        byte[] mnoBuf = new byte[POINT_LEN];
        short mnoLen = mnoPk.getW(mnoBuf, (short) 0);

        byte[] leakBuf = new byte[POINT_LEN];
        short leakLen = leakPk.getW(leakBuf, (short) 0);

        byte[] uBuf = new byte[POINT_LEN];
        short uLen = ((ECPublicKey) uPk).getW(uBuf, (short) 0);

        byte[] xInput = new byte[(short) (mnoLen + leakLen + uLen + nonce.length + pid.length)];
        short idx = 0;
        Util.arrayCopy(mnoBuf, (short) 0, xInput, idx, mnoLen);
        idx += mnoLen;
        Util.arrayCopy(leakBuf, (short) 0, xInput, idx, leakLen);
        idx += leakLen;
        Util.arrayCopy(uBuf, (short) 0, xInput, idx, uLen);
        idx += uLen;
        Util.arrayCopy(nonce, (short) 0, xInput, idx, (short) nonce.length);
        idx += (short) nonce.length;
        Util.arrayCopy(pid, (short) 0, xInput, idx, (short) pid.length);

        hashToScalar(xInput, outX);
    }

    private void hashToScalar(byte[] data, jcmathlib.BigNat out) {
        byte[] hashBuf = new byte[SCALAR_LEN];
        sha256.reset();
        sha256.doFinal(data, (short) 0, (short) data.length, hashBuf, (short) 0);

        out.fromByteArray(hashBuf, (short) 0, SCALAR_LEN);
        out.mod(curve.rBN);
    }

    private void generateRandomScalar(jcmathlib.BigNat r) {
        byte[] tmp = new byte[SCALAR_LEN];
        fillRandomData(rnd, tmp, (short) 0, SCALAR_LEN);

        r.fromByteArray(tmp, (short) 0, SCALAR_LEN);
        r.mod(curve.rBN);
    }

    @SuppressWarnings("deprecation")
    private static RandomData createRandom() {
        try {
            return RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        } catch (Throwable ignored) {
            return null;
        }
    }

    @SuppressWarnings("deprecation")
    private static void fillRandomData(RandomData random, byte[] out, short off, short len) {
        random.generateData(out, off, len);
    }

    private void computeChallenge(byte[] xBuf, short xLen, byte[] wBuf, short wLen, jcmathlib.BigNat c) {
        byte[] hashBuf = new byte[SCALAR_LEN];
        byte[] input = new byte[(short) (xLen + wLen)];

        Util.arrayCopy(xBuf, (short) 0, input, (short) 0, xLen);
        Util.arrayCopy(wBuf, (short) 0, input, xLen, wLen);

        sha256.reset();
        sha256.doFinal(input, (short) 0, (short) input.length, hashBuf, (short) 0);

        c.fromByteArray(hashBuf, (short) 0, SCALAR_LEN);
        c.mod(curve.rBN);
    }

    private void computeResponse(jcmathlib.BigNat r, jcmathlib.BigNat c, jcmathlib.BigNat w, jcmathlib.BigNat s) {
        jcmathlib.BigNat tmp = new jcmathlib.BigNat(SCALAR_LEN, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);
        tmp.copy(c);
        tmp.modMult(w, curve.rBN);

        s.copy(r);
        s.modAdd(tmp, curve.rBN);
    }

    private short wrapSequence(byte[] data, short len, byte[] out, short off) {
        out[off++] = 0x30;

        if (len < 128) {
            out[off++] = (byte) len;
        } else {
            out[off++] = (byte) 0x81;
            out[off++] = (byte) len;
        }

        Util.arrayCopy(data, (short) 0, out, off, len);
        return (short) (off + len);
    }

    private static void setP256Params(Key key) {
        ECKey ecKey = (ECKey) key;
        ecKey.setFieldFP(jcmathlib.SecP256r1.p, (short) 0, (short) jcmathlib.SecP256r1.p.length);
        ecKey.setA(jcmathlib.SecP256r1.a, (short) 0, (short) jcmathlib.SecP256r1.a.length);
        ecKey.setB(jcmathlib.SecP256r1.b, (short) 0, (short) jcmathlib.SecP256r1.b.length);
        ecKey.setG(jcmathlib.SecP256r1.G, (short) 0, (short) jcmathlib.SecP256r1.G.length);
        ecKey.setR(jcmathlib.SecP256r1.r, (short) 0, (short) jcmathlib.SecP256r1.r.length);
        ecKey.setK(jcmathlib.SecP256r1.k);
    }

    private void initAsymmetric() {
        try {
            signature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
            ka = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);

            kp = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
            setP256Params(kp.getPrivate());
            setP256Params(kp.getPublic());
            kp.genKeyPair();
            uSk = kp.getPrivate();
            uPk = kp.getPublic();

            smdpPk = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);
            setP256Params(smdpPk);
            mnoPk = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);
            setP256Params(mnoPk);
            leakPk = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);
            setP256Params(leakPk);
        } catch (Throwable t) {
            ISOException.throwIt(SW_CRYPTO_UNAVAILABLE);
        }
    }

    /**
     * Initialise the JCMathLib ResourceManager and ECCurve.
     * Called lazily only when ZK primitives are needed.
     * Idempotent: subsequent calls after success are no-ops.
     */
    public void initZk() {
        if (rm != null && curve != null) {
            return;
        }
        try {
            // This profile keeps hardware-backed X-only EC multiplication enabled while
            // disabling the RSA-backed helpers that are absent on the sysmocom eUICC.
            jcmathlib.OperationSupport.getInstance().setCard(jcmathlib.OperationSupport.SYSMO_EUICC1_C2T);
            rm = new jcmathlib.ResourceManager((short) 16);
            curve = new jcmathlib.ECCurve(
                    jcmathlib.SecP256r1.p,
                    jcmathlib.SecP256r1.a,
                    jcmathlib.SecP256r1.b,
                    jcmathlib.SecP256r1.G,
                    jcmathlib.SecP256r1.r,
                    jcmathlib.SecP256r1.k,
                    rm);
        } catch (Throwable t) {
            ISOException.throwIt(SW_CRYPTO_UNAVAILABLE);
        }
    }

    private void ensureZkInitialized() {
        if (rm == null || curve == null) {
            initZk();
        }
    }
}
