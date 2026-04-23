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
    // MNO private key — the applet test-mode keeps this alongside pk_MNO so it can
    // sign (sig_cred, sig_root, auth_tok) at install time bound to the real h_cert.
    // In a production deployment these would be issued by an enrolment service.
    private ECPrivateKey mnoSk;

    // Fixed device keypair: scalar + corresponding secp256r1 point W = d*G.
    // Pinning the device key makes the applet's self-signed euiccCertificate SPKI
    // deterministic across installs, which matters because MNO-signed values
    // (sig_cred, auth_tok) are bound to h_cert = SHA256(euiccCertificate).
    private static final byte[] FIXED_DEVICE_SCALAR = {
            (byte) 0x4D, (byte) 0x3C, (byte) 0x2B, (byte) 0x1A, (byte) 0x0F, (byte) 0xFE, (byte) 0xDC, (byte) 0xBA,
            (byte) 0x98, (byte) 0x76, (byte) 0x54, (byte) 0x32, (byte) 0x10, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF,
            (byte) 0x01, (byte) 0x23, (byte) 0x45, (byte) 0x67, (byte) 0x89, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF,
            (byte) 0x00, (byte) 0x11, (byte) 0x22, (byte) 0x33, (byte) 0x44, (byte) 0x55, (byte) 0x66, (byte) 0xFF
    };
    private static final byte[] FIXED_DEVICE_W = {
            (byte) 0x04, (byte) 0x1D, (byte) 0xD0, (byte) 0x96, (byte) 0xDE, (byte) 0x35, (byte) 0x6A, (byte) 0x2F,
            (byte) 0x4F, (byte) 0xEC, (byte) 0xC2, (byte) 0x41, (byte) 0x1F, (byte) 0x0C, (byte) 0xD0, (byte) 0x60,
            (byte) 0x37, (byte) 0x53, (byte) 0xED, (byte) 0x27, (byte) 0x2E, (byte) 0x41, (byte) 0xCC, (byte) 0x2A,
            (byte) 0xDD, (byte) 0x4A, (byte) 0x45, (byte) 0x71, (byte) 0x35, (byte) 0x28, (byte) 0xC2, (byte) 0x50,
            (byte) 0xFE, (byte) 0xFF, (byte) 0x72, (byte) 0x4F, (byte) 0x2D, (byte) 0xAA, (byte) 0xC5, (byte) 0x70,
            (byte) 0xCE, (byte) 0x7F, (byte) 0x71, (byte) 0xE7, (byte) 0x51, (byte) 0x01, (byte) 0x46, (byte) 0x8D,
            (byte) 0xBC, (byte) 0xD5, (byte) 0xAE, (byte) 0xD6, (byte) 0xBB, (byte) 0xB8, (byte) 0xA3, (byte) 0xAC,
            (byte) 0x3C, (byte) 0x1C, (byte) 0x36, (byte) 0xEE, (byte) 0x6D, (byte) 0xEA, (byte) 0xAF, (byte) 0x4D,
            (byte) 0xC1
    };
    // Must match FIXED_MNO_PRIVATE_SCALAR in pysim/osmo-smdpp.py.
    private static final byte[] FIXED_MNO_SCALAR = {
            (byte) 0x1F, (byte) 0x1E, (byte) 0x1D, (byte) 0x1C, (byte) 0x1B, (byte) 0x1A, (byte) 0x19, (byte) 0x18,
            (byte) 0x17, (byte) 0x16, (byte) 0x15, (byte) 0x14, (byte) 0x13, (byte) 0x12, (byte) 0x11, (byte) 0x10,
            (byte) 0xFF, (byte) 0xEE, (byte) 0xDD, (byte) 0xCC, (byte) 0xBB, (byte) 0xAA, (byte) 0x99, (byte) 0x88,
            (byte) 0x77, (byte) 0x66, (byte) 0x55, (byte) 0x44, (byte) 0x33, (byte) 0x22, (byte) 0x11, (byte) 0x00
    };

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

    /**
     * ECDSA-SHA256 sign `msg` with the applet-held MNO private key. Returns the
     * DER-encoded signature length. Used at install time to bind eligibility
     * credentials (sig_cred, sig_root, auth_tok) to the session-specific h_cert.
     */
    public short signWithMno(byte[] msg, short msgOff, short msgLen, byte[] sigOut, short sigOff) {
        signature.init(mnoSk, Signature.MODE_SIGN);
        return signature.sign(msg, msgOff, msgLen, sigOut, sigOff);
    }

    /** Public SHA-256 over an arbitrary input. Returns 32. */
    public short sha256Digest(byte[] in, short inOff, short inLen, byte[] out, short outOff) {
        sha256.reset();
        return sha256.doFinal(in, inOff, inLen, out, outOff);
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

    // DER constants for the self-signed eUICC cert.
    // signatureAlgorithm = ecdsa-with-SHA256 (1.2.840.10045.4.3.2).
    private static final byte[] CERT_SIG_ALG_DER = {
            0x30, 0x0A,
            0x06, 0x08, 0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D, 0x04, 0x03, 0x02
    };
    // Name = SEQUENCE {
    //   SET { SEQUENCE { OID 2.5.4.3 commonName, UTF8String "eUICC" } },
    //   SET { SEQUENCE { OID 2.5.4.5 serialNumber, PrintableString <EID> } }
    // }
    // SGP.22 requires subject.serialNumber to hold the 32-digit EID — osmo-smdpp
    // extracts it directly for session tracking. Matches Crypto.getEidString().
    private static final byte[] CERT_NAME_DER = {
            0x30, 0x3B,
            0x31, 0x0E,
            0x30, 0x0C,
            0x06, 0x03, 0x55, 0x04, 0x03,
            0x0C, 0x05, (byte) 'e', (byte) 'U', (byte) 'I', (byte) 'C', (byte) 'C',
            0x31, 0x29,
            0x30, 0x27,
            0x06, 0x03, 0x55, 0x04, 0x05,
            0x13, 0x20,
            (byte) '8', (byte) '9', (byte) '0', (byte) '4', (byte) '9', (byte) '0', (byte) '3', (byte) '2',
            (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0',
            (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '1', (byte) '2', (byte) '3', (byte) '4',
            (byte) '5', (byte) '6', (byte) '7', (byte) '8', (byte) '9', (byte) '0', (byte) '1', (byte) '2'
    };
    // Validity = SEQUENCE { UTCTime "240101000000Z", UTCTime "391231235959Z" }
    private static final byte[] CERT_VALIDITY_DER = {
            0x30, 0x1E,
            0x17, 0x0D,
            (byte) '2', (byte) '4', (byte) '0', (byte) '1', (byte) '0', (byte) '1',
            (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) 'Z',
            0x17, 0x0D,
            (byte) '3', (byte) '9', (byte) '1', (byte) '2', (byte) '3', (byte) '1',
            (byte) '2', (byte) '3', (byte) '5', (byte) '9', (byte) '5', (byte) '9', (byte) 'Z'
    };
    // SPKI header: SEQUENCE(L=89) { AlgId(ecPublicKey + secp256r1), BIT STRING header }.
    // Caller appends the 65-byte uncompressed P-256 point immediately after these 26 bytes.
    private static final byte[] CERT_SPKI_HEADER = {
            0x30, 0x59,
            0x30, 0x13,
            0x06, 0x07, 0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D, 0x02, 0x01,
            0x06, 0x08, 0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D, 0x03, 0x01, 0x07,
            0x03, 0x42, 0x00
    };
    // TBS body = version(5) + serial(3) + sigAlg(12) + issuer(61) + validity(32) + subject(61) + SPKI(91)
    private static final short CERT_TBS_BODY_LEN = (short) 265;
    private static final short CERT_TBS_HEADER_LEN = (short) 4;

    /**
     * Emits a self-signed X.509 v3 certificate whose SPKI carries the device public key.
     * Used as eUICC certificate in AuthenticateResponseOk — SM-DP+ in --zk mode skips the
     * full chain validation but extracts this SPKI to verify euiccSignature1.
     */
    public short buildSelfSignedEuiccCert(byte[] out, short off) {
        // Reserve 4 bytes at `off` for outer Certificate SEQUENCE header "30 82 LL LL".
        short tbsStart = (short) (off + 4);
        short pos = tbsStart;

        // TBSCertificate SEQUENCE header: 30 82 <hi> <lo>  (2-byte length form, body > 255)
        out[pos++] = 0x30;
        out[pos++] = (byte) 0x82;
        out[pos++] = (byte) ((CERT_TBS_BODY_LEN >> 8) & 0xFF);
        out[pos++] = (byte) (CERT_TBS_BODY_LEN & 0xFF);

        // version [0] EXPLICIT INTEGER 2 (v3)
        out[pos++] = (byte) 0xA0;
        out[pos++] = 0x03;
        out[pos++] = 0x02;
        out[pos++] = 0x01;
        out[pos++] = 0x02;

        // serialNumber INTEGER 1
        out[pos++] = 0x02;
        out[pos++] = 0x01;
        out[pos++] = 0x01;

        // signature AlgorithmIdentifier (inside TBS)
        Util.arrayCopyNonAtomic(CERT_SIG_ALG_DER, (short) 0, out, pos, (short) CERT_SIG_ALG_DER.length);
        pos = (short) (pos + CERT_SIG_ALG_DER.length);

        // issuer Name
        Util.arrayCopyNonAtomic(CERT_NAME_DER, (short) 0, out, pos, (short) CERT_NAME_DER.length);
        pos = (short) (pos + CERT_NAME_DER.length);

        // validity
        Util.arrayCopyNonAtomic(CERT_VALIDITY_DER, (short) 0, out, pos, (short) CERT_VALIDITY_DER.length);
        pos = (short) (pos + CERT_VALIDITY_DER.length);

        // subject Name (self-signed: same as issuer)
        Util.arrayCopyNonAtomic(CERT_NAME_DER, (short) 0, out, pos, (short) CERT_NAME_DER.length);
        pos = (short) (pos + CERT_NAME_DER.length);

        // SubjectPublicKeyInfo: algorithm header + 65-byte uncompressed P-256 point
        Util.arrayCopyNonAtomic(CERT_SPKI_HEADER, (short) 0, out, pos, (short) CERT_SPKI_HEADER.length);
        pos = (short) (pos + CERT_SPKI_HEADER.length);
        short keyLen = ((ECPublicKey) uPk).getW(out, pos);
        pos = (short) (pos + keyLen);

        short tbsEnd = pos;
        short tbsTotal = (short) (tbsEnd - tbsStart);

        // signatureAlgorithm (outer)
        Util.arrayCopyNonAtomic(CERT_SIG_ALG_DER, (short) 0, out, pos, (short) CERT_SIG_ALG_DER.length);
        pos = (short) (pos + CERT_SIG_ALG_DER.length);

        // Sign the entire TBS sequence (header + body) into scratchCert, then wrap as BIT STRING
        signature.init(uSk, Signature.MODE_SIGN);
        short derSigLen = signature.sign(out, tbsStart, tbsTotal, scratchCert, (short) 0);

        out[pos++] = 0x03;
        out[pos++] = (byte) (derSigLen + 1);
        out[pos++] = 0x00;
        Util.arrayCopyNonAtomic(scratchCert, (short) 0, out, pos, derSigLen);
        pos = (short) (pos + derSigLen);

        // Outer SEQUENCE header "30 82 LL LL"
        short outerContentLen = (short) (pos - off - 4);
        out[off] = 0x30;
        out[(short) (off + 1)] = (byte) 0x82;
        out[(short) (off + 2)] = (byte) ((outerContentLen >> 8) & 0xFF);
        out[(short) (off + 3)] = (byte) (outerContentLen & 0xFF);

        return (short) (pos - off);
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
            // Pin device keypair to fixed (scalar, W) so the euiccCertificate SPKI is
            // deterministic across installs. This lets MNO-signed credentials bound
            // to h_cert = SHA256(euiccCertificate) stay valid regardless of install.
            ((ECPrivateKey) kp.getPrivate()).setS(FIXED_DEVICE_SCALAR, (short) 0, (short) FIXED_DEVICE_SCALAR.length);
            ((ECPublicKey) kp.getPublic()).setW(FIXED_DEVICE_W, (short) 0, (short) FIXED_DEVICE_W.length);
            uSk = kp.getPrivate();
            uPk = kp.getPublic();

            smdpPk = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);
            setP256Params(smdpPk);
            mnoPk = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);
            setP256Params(mnoPk);
            leakPk = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);
            setP256Params(leakPk);

            // Applet-held MNO private key for signing eligibility credentials at
            // install time. In the real protocol the MNO enrolment service would
            // deliver these signatures out-of-band; we co-locate for test mode.
            mnoSk = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
            setP256Params(mnoSk);
            mnoSk.setS(FIXED_MNO_SCALAR, (short) 0, (short) FIXED_MNO_SCALAR.length);
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
