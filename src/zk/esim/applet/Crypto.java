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

    private static final short AES_BLOCK_LEN = (short) 16;
    private static final short SCALAR_LEN = (short) 32;
    private static final short POINT_LEN = (short) 65;
    private static final short SW_CRYPTO_UNAVAILABLE = ISO7816.SW_CONDITIONS_NOT_SATISFIED;

    private static final byte[] DEFAULT_RANDOM_SEED = {
            (byte) 'T', (byte) 'h', (byte) 'i', (byte) 's', (byte) ' ', (byte) 'i', (byte) 's', (byte) ' ',
            (byte) 'a', (byte) ' ', (byte) 's', (byte) 'e', (byte) 'e', (byte) 'd'
    };

    // Phase-0 registration seed for pid KDF: K_pid = SHA256(SK_B_SEED || mnoChallenge).
    private static final byte[] SK_B_SEED = {
            (byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF, (byte) 0xCA, (byte) 0xFE, (byte) 0xBA, (byte) 0xBE,
            (byte) 0x01, (byte) 0x23, (byte) 0x45, (byte) 0x67, (byte) 0x89, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF,
            (byte) 0xFE, (byte) 0xDC, (byte) 0xBA, (byte) 0x98, (byte) 0x76, (byte) 0x54, (byte) 0x32, (byte) 0x10,
            (byte) 0x11, (byte) 0x22, (byte) 0x33, (byte) 0x44, (byte) 0x55, (byte) 0x66, (byte) 0x77, (byte) 0x88
    };

    // Uncompressed P-256 public key derived from FIXED_MNO_SCALAR (= FIXED_MNO_PRIVATE_SCALAR in osmo-smdpp.py).
    private static final byte[] MNO_PUBLIC_W = {
            (byte) 0x04, (byte) 0x0E, (byte) 0x04, (byte) 0x2F, (byte) 0x54, (byte) 0xB8, (byte) 0x68, (byte) 0x7E,
            (byte) 0x47, (byte) 0x9C, (byte) 0x41, (byte) 0xA8, (byte) 0x4C, (byte) 0xD0, (byte) 0x07, (byte) 0xB1,
            (byte) 0x3A, (byte) 0x5F, (byte) 0x7D, (byte) 0x5F, (byte) 0x6A, (byte) 0xCD, (byte) 0x8E, (byte) 0x90,
            (byte) 0xAF, (byte) 0x58, (byte) 0xF0, (byte) 0xC8, (byte) 0x5E, (byte) 0xAD, (byte) 0xCB, (byte) 0x67,
            (byte) 0xF6, (byte) 0x13, (byte) 0xD1, (byte) 0x25, (byte) 0xA6, (byte) 0x40, (byte) 0x97, (byte) 0x03,
            (byte) 0x25, (byte) 0x4A, (byte) 0xDC, (byte) 0x1C, (byte) 0x7B, (byte) 0xC4, (byte) 0x23, (byte) 0x57,
            (byte) 0x1C, (byte) 0x99, (byte) 0x14, (byte) 0xA5, (byte) 0xA4, (byte) 0x5F, (byte) 0x61, (byte) 0x24,
            (byte) 0x1C, (byte) 0x0E, (byte) 0x73, (byte) 0x43, (byte) 0x16, (byte) 0x54, (byte) 0xBD, (byte) 0x4C,
            (byte) 0x75
    };

    // Uncompressed P-256 public key for the test LEA (scalar = 0xAABBCCDD...).
    private static final byte[] LEA_PUBLIC_W = {
            (byte) 0x04, (byte) 0x21, (byte) 0x90, (byte) 0x2A, (byte) 0x33, (byte) 0xC0, (byte) 0x72, (byte) 0xD4,
            (byte) 0x67, (byte) 0xB0, (byte) 0xC5, (byte) 0x81, (byte) 0xBA, (byte) 0x68, (byte) 0x25, (byte) 0xA2,
            (byte) 0x44, (byte) 0x0E, (byte) 0xC4, (byte) 0x04, (byte) 0xF2, (byte) 0xED, (byte) 0xCF, (byte) 0x3C,
            (byte) 0x0D, (byte) 0x8A, (byte) 0xAF, (byte) 0x92, (byte) 0xF4, (byte) 0xEF, (byte) 0xCF, (byte) 0x4D,
            (byte) 0x45, (byte) 0xBF, (byte) 0x51, (byte) 0x42, (byte) 0xCA, (byte) 0xF9, (byte) 0xF5, (byte) 0x59,
            (byte) 0xE6, (byte) 0x94, (byte) 0xAD, (byte) 0x89, (byte) 0x1D, (byte) 0xF0, (byte) 0x98, (byte) 0xD3,
            (byte) 0xE2, (byte) 0xAA, (byte) 0xF8, (byte) 0xA2, (byte) 0xD9, (byte) 0x01, (byte) 0x8B, (byte) 0xB2,
            (byte) 0x0D, (byte) 0x40, (byte) 0x38, (byte) 0x3C, (byte) 0x55, (byte) 0x02, (byte) 0x97, (byte) 0x23,
            (byte) 0x2C
    };


    private jcmathlib.ResourceManager rm;
    private jcmathlib.ECCurve curve;
    private final RandomData rnd;
    private MessageDigest sha256;
    private Signature signature;
    private KeyAgreement ka;
    private Cipher aesEcb;
    private Cipher aesCbc;
    private AESKey workAesKey;

    private KeyPair kp;
    private PublicKey uPk;
    private PrivateKey uSk;
    private KeyPair otkp;
    private ECPublicKey euiccOtpk;
    private ECPrivateKey euiccOtsk;
    private ECPublicKey smdpPbPk;
    private ECPublicKey smdpAuthPk;
    private ECPublicKey mnoPk;
    private ECPublicKey leakPk;
    // Ephemeral keypair used exclusively for ECIES encryption in encryptEidEcies().
    private KeyPair eciesKp;
    private ECPrivateKey eciesEtsk;
    private ECPublicKey eciesEtpk;
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

    // Phase 0.a blind-Schnorr state: persisted between BF44 (blind) and BF45 (unblind).
    private byte[] phase0AlphaBuf;   // blinding factor α (32 B, CLEAR_ON_DESELECT)
    private byte[] phase0RPrimeBuf;  // blinded nonce R' (65 B, CLEAR_ON_DESELECT)

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
    private byte[] scratchCmacInput;  // 1100-byte buffer for BSP MAC input (MCV + protected TLV sans MAC)
    private byte[] scratchCmacState;  // 16-byte CMAC chaining state
    private byte[] scratchCmacBlock;  // 16-byte CMAC work block / L
    private byte[] scratchCmacSubkey1;// 16-byte CMAC K1
    private byte[] scratchCmacSubkey2;// 16-byte CMAC K2

    private static final short SCRATCH_CERT_LEN = (short) 512;
    private static final short SCRATCH_INPUT_LEN = (short) 300;
    private static final short SCRATCH_CMAC_INPUT_LEN = (short) 1100;

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
        scratchCmacInput = JCSystem.makeTransientByteArray(SCRATCH_CMAC_INPUT_LEN, JCSystem.CLEAR_ON_DESELECT);
        scratchCmacState = JCSystem.makeTransientByteArray(AES_BLOCK_LEN, JCSystem.CLEAR_ON_DESELECT);
        scratchCmacBlock = JCSystem.makeTransientByteArray(AES_BLOCK_LEN, JCSystem.CLEAR_ON_DESELECT);
        scratchCmacSubkey1 = JCSystem.makeTransientByteArray(AES_BLOCK_LEN, JCSystem.CLEAR_ON_DESELECT);
        scratchCmacSubkey2 = JCSystem.makeTransientByteArray(AES_BLOCK_LEN, JCSystem.CLEAR_ON_DESELECT);

        phase0AlphaBuf  = JCSystem.makeTransientByteArray(SCALAR_LEN, JCSystem.CLEAR_ON_DESELECT);
        phase0RPrimeBuf = JCSystem.makeTransientByteArray(POINT_LEN,  JCSystem.CLEAR_ON_DESELECT);

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

    public short exportMnoPk(byte[] out, short off) {
        return mnoPk.getW(out, off);
    }

    public short exportLeaPk(byte[] out, short off) {
        return leakPk.getW(out, off);
    }

    public short sign(byte[] msg, short msgOff, short msgLen, byte[] sigOut, short sigOff) {
        signature.init(uSk, Signature.MODE_SIGN);
        return signature.sign(msg, msgOff, msgLen, sigOut, sigOff);
    }

    /**
     * ECDSA-SHA256 over the concatenation of two byte ranges, signed with the device
     * private key.  Used by BF21 PrepareDownloadResponse, which signs over
     * euiccSigned2_tlv || smdpSignature2_do per SGP.22 5.7.5.
     */
    public short signTwoPart(byte[] a, short aOff, short aLen,
                             byte[] b, short bOff, short bLen,
                             byte[] sigOut, short sigOff) {
        signature.init(uSk, Signature.MODE_SIGN);
        signature.update(a, aOff, aLen);
        return signature.sign(b, bOff, bLen, sigOut, sigOff);
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

    // -----------------------------------------------------------------------
    // Phase 0 crypto primitives
    // -----------------------------------------------------------------------

    /**
     * Phase 0.a registration: reg_req = SHA256(SHA256(eid || SK_B_SEED) || nonce).
     * The inner hash binds the EID to SK_B_SEED without revealing either to the MNO;
     * the outer hash mixes in the MNO nonce so the same reg_req can't be replayed.
     */
    public void computeRegReq(byte[] eid, short eidOff, short eidLen,
                               byte[] nonce, short nonceOff, short nonceLen,
                               byte[] out, short outOff) {
        sha256.reset();
        sha256.update(eid, eidOff, eidLen);
        sha256.doFinal(SK_B_SEED, (short) 0, (short) SK_B_SEED.length, scratchScalar2, (short) 0);
        sha256.reset();
        sha256.update(scratchScalar2, (short) 0, SCALAR_LEN);
        sha256.doFinal(nonce, nonceOff, nonceLen, out, outOff);
    }

    /**
     * Phase 0.a blind registration — step 1 (BF44).
     * Receives R_MNO = r_MNO·G from the MNO, computes the blinded Schnorr challenge:
     *   α, β  ← random scalars
     *   R'    = R_MNO + α·G + β·pk_MNO
     *   m     = SHA256(EID || SK_B_SEED)
     *   c     = SHA256(R' || m) mod n
     *   e     = (c − β) mod n   ← sent to MNO
     * Stores α in phase0AlphaBuf and R' in phase0RPrimeBuf for the unblinding step.
     * Returns e (32 B) into eOut[eOff].
     */
    public void blindRegisterRequest(byte[] rMnoBuf, short rMnoOff,
                                     byte[] eid, short eidOff, short eidLen,
                                     byte[] eOut, short eOff) {
        ensureZkInitialized();

        // Zero-blinding (α = β = 0): R' = R_MNO, avoids EC scalar multiplication on hardware.
        // Breaks blind Schnorr privacy but preserves end-to-end protocol correctness for testing.
        Util.arrayCopyNonAtomic(rMnoBuf, rMnoOff, phase0RPrimeBuf, (short) 0, POINT_LEN);

        // m = SHA256(EID || SK_B_SEED)
        sha256.reset();
        sha256.update(eid, eidOff, eidLen);
        sha256.doFinal(SK_B_SEED, (short) 0, (short) SK_B_SEED.length, scratchScalar1, (short) 0);

        // e = SHA256(R' || m) mod n
        sha256.reset();
        sha256.update(phase0RPrimeBuf, (short) 0, POINT_LEN);
        sha256.doFinal(scratchScalar1, (short) 0, SCALAR_LEN, scratchScalar2, (short) 0);
        jcmathlib.BigNat c = new jcmathlib.BigNat(SCALAR_LEN, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);
        c.fromByteArray(scratchScalar2, (short) 0, SCALAR_LEN);
        c.mod(curve.rBN);
        c.copyToByteArray(eOut, eOff);
    }

    /**
     * Phase 0.a blind registration — step 2 (BF45).
     * Receives the MNO partial signature s and unblinds it:
     *   s' = (s + α) mod n
     *   σ_EID = R' || s'   (97 bytes)
     * Writes σ_EID into sigEidOut[sigEidOff].
     */
    public void blindRegisterUnblind(byte[] sBuf, short sOff,
                                     byte[] sigEidOut, short sigEidOff) {
        // Zero-blinding: s' = s (α = 0), σ_EID = R_MNO || s
        Util.arrayCopyNonAtomic(phase0RPrimeBuf, (short) 0, sigEidOut, sigEidOff, POINT_LEN);
        Util.arrayCopyNonAtomic(sBuf, sOff, sigEidOut, (short) (sigEidOff + POINT_LEN), SCALAR_LEN);
    }

    /**
     * Phase 0.b CertInit: session scalar = SHA256(SK_B_SEED || r_seed).
     * Each fresh r_seed produces a unique (sk_U, pk_U) keypair, achieving unlinkability.
     */
    public void deriveSessionScalar(byte[] rSeed, short off, short len, byte[] out, short outOff) {
        sha256.reset();
        sha256.update(SK_B_SEED, (short) 0, (short) SK_B_SEED.length);
        sha256.doFinal(rSeed, off, len, out, outOff);
    }

    /**
     * Load a derived session scalar as the device keypair (sk_U, pk_U = sk_U·G).
     * After this call, exportPublicKey / sign / generateSchnorrProof all use the session key.
     */
    public void loadSessionKey(byte[] scalar, short off) {
        ensureZkInitialized();
        // EC_HW_XY=false on SYSMO_EUICC1_C2T: jcmathlib pt.multiplication() triggers
        // modExpSoftware which throws an unhandled exception (SW=6F00). Use JavaCard
        // native genKeyPair() instead — sk_U is random rather than derived from rSeed.
        kp.genKeyPair();
    }

    /**
     * Verify a DER-encoded ECDSA-SHA256 signature against the applet-held MNO public key.
     * Used in Phase 0.a to authenticate the MNO blind credential (σ̃).
     */
    public boolean verifyWithMnoPk(byte[] msg, short msgOff, short msgLen,
                                    byte[] sigDer, short sigOff, short sigLen) {
        try {
            signature.init(mnoPk, Signature.MODE_VERIFY);
            return signature.verify(msg, msgOff, msgLen, sigDer, sigOff, sigLen);
        } catch (Throwable t) {
            return false;
        }
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

    public short generateEuiccOtpk(byte[] out, short off) {
        otkp.genKeyPair();
        return euiccOtpk.getW(out, off);
    }

    public short computeBspSharedSecret(byte[] smdpOtpkBuf, short off, short len, byte[] out, short outOff) {
        ka.init(euiccOtsk);
        return ka.generateSecret(smdpOtpkBuf, off, len, out, outOff);
    }

    public void deriveBspKeys(byte[] sharedSecretBuf, short sharedSecretOff, short sharedSecretLen,
                              byte keyType, byte keyLen,
                              byte[] hostId, short hostIdOff, short hostIdLen,
                              byte[] eid, short eidOff, short eidLen,
                              byte[] sEnc, short sEncOff,
                              byte[] sMac, short sMacOff,
                              byte[] initialMcv, short initialMcvOff) {
        short normalizedSharedSecretOff = sharedSecretOff;
        short normalizedSharedSecretLen = sharedSecretLen;
        short sharedInfoLen;
        short digestInputLen;
        short outLen = 0;
        byte counter = 1;

        if (sharedSecretLen == POINT_LEN && sharedSecretBuf[sharedSecretOff] == 0x04) {
            normalizedSharedSecretOff = (short) (sharedSecretOff + 1);
            normalizedSharedSecretLen = SCALAR_LEN;
        }

        sharedInfoLen = 0;
        scratchInput[sharedInfoLen++] = keyType;
        scratchInput[sharedInfoLen++] = keyLen;
        sharedInfoLen = TlvWriter.writeLength(scratchInput, sharedInfoLen, hostIdLen);
        Util.arrayCopyNonAtomic(hostId, hostIdOff, scratchInput, sharedInfoLen, hostIdLen);
        sharedInfoLen = (short) (sharedInfoLen + hostIdLen);
        sharedInfoLen = TlvWriter.writeLength(scratchInput, sharedInfoLen, eidLen);
        Util.arrayCopyNonAtomic(eid, eidOff, scratchInput, sharedInfoLen, eidLen);
        sharedInfoLen = (short) (sharedInfoLen + eidLen);

        while (outLen < 48) {
            // ANSI X9.63 KDF hash input: sharedSecret || counter (4-byte BE) || sharedInfo.
            // Must match pysim X963KDF (cryptography.hazmat) — counter comes AFTER Z, not before.
            digestInputLen = 0;
            Util.arrayCopyNonAtomic(sharedSecretBuf, normalizedSharedSecretOff,
                    scratchCert, digestInputLen, normalizedSharedSecretLen);
            digestInputLen = (short) (digestInputLen + normalizedSharedSecretLen);
            scratchCert[digestInputLen++] = 0x00;
            scratchCert[digestInputLen++] = 0x00;
            scratchCert[digestInputLen++] = 0x00;
            scratchCert[digestInputLen++] = counter;
            Util.arrayCopyNonAtomic(scratchInput, (short) 0, scratchCert, digestInputLen, sharedInfoLen);
            digestInputLen = (short) (digestInputLen + sharedInfoLen);
            sha256.reset();
            sha256.doFinal(scratchCert, (short) 0, digestInputLen, scratchPoint1, (short) 0);

            if ((short) (48 - outLen) >= SCALAR_LEN) {
                Util.arrayCopyNonAtomic(scratchPoint1, (short) 0, scratchPoint2, outLen, SCALAR_LEN);
                outLen = (short) (outLen + SCALAR_LEN);
            } else {
                short remaining = (short) (48 - outLen);
                Util.arrayCopyNonAtomic(scratchPoint1, (short) 0, scratchPoint2, outLen, remaining);
                outLen = 48;
            }
            counter++;
        }

        Util.arrayCopyNonAtomic(scratchPoint2, (short) 0, initialMcv, initialMcvOff, AES_BLOCK_LEN);
        Util.arrayCopyNonAtomic(scratchPoint2, AES_BLOCK_LEN, sEnc, sEncOff, AES_BLOCK_LEN);
        Util.arrayCopyNonAtomic(scratchPoint2, (short) (AES_BLOCK_LEN * 2), sMac, sMacOff, AES_BLOCK_LEN);
    }

    public boolean verifyBspSegment(byte[] buf, short segOff, short segLen,
                                    byte[] sMac, short sMacOff,
                                    byte[] mcv, short mcvOff) {
        short pos = segOff;
        short segmentEnd = (short) (segOff + segLen);
        short valueLen;
        short lengthFieldLen;
        short bodyLenWithoutMac;
        short macOff;
        short cmacInputLen;

        if (segLen < (short) 10) {
            return false;
        }

        pos++;
        if ((buf[segOff] & 0x1F) == 0x1F) {
            if (segLen < (short) 11) {
                return false;
            }
            pos++;
        }

        if (pos >= segmentEnd) {
            return false;
        }

        valueLen = (short) (buf[pos] & 0xFF);
        pos++;
        if ((valueLen & (short) 0x80) != 0) {
            byte numLenBytes = (byte) (valueLen & 0x7F);
            if (numLenBytes == 0 || numLenBytes > 2 || (short) (pos + numLenBytes) > segmentEnd) {
                return false;
            }
            valueLen = 0;
            while (numLenBytes > 0) {
                valueLen = (short) ((short) (valueLen << 8) | (short) (buf[pos++] & 0xFF));
                numLenBytes--;
            }
        }

        lengthFieldLen = (short) (pos - segOff - (((buf[segOff] & 0x1F) == 0x1F) ? 2 : 1));
        if ((short) (pos + valueLen) != segmentEnd || valueLen < 8) {
            return false;
        }

        bodyLenWithoutMac = (short) (valueLen - 8);
        macOff = (short) (segmentEnd - 8);
        cmacInputLen = (short) (AES_BLOCK_LEN + (((buf[segOff] & 0x1F) == 0x1F) ? 2 : 1) + lengthFieldLen + bodyLenWithoutMac);
        if (cmacInputLen > SCRATCH_CMAC_INPUT_LEN) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        Util.arrayCopyNonAtomic(mcv, mcvOff, scratchCmacInput, (short) 0, AES_BLOCK_LEN);
        Util.arrayCopyNonAtomic(buf, segOff, scratchCmacInput, AES_BLOCK_LEN, (short) (segLen - 8));
        computeAesCmac(sMac, sMacOff, scratchCmacInput, (short) 0, cmacInputLen, scratchCmacState, (short) 0);
        if (!ByteArrayUtil.equals(scratchCmacState, (short) 0, buf, macOff, (short) 8)) {
            return false;
        }

        Util.arrayCopyNonAtomic(scratchCmacState, (short) 0, mcv, mcvOff, AES_BLOCK_LEN);
        return true;
    }

    public short decryptBspPayload(byte[] sEnc, short sEncOff, short blockNr,
                                   byte[] ciphertext, short ctOff, short ctLen,
                                   byte[] out, short outOff) {
        short pos = 0;
        short outLen = ctLen;
        short i;

        if (ctLen <= 0 || (short) (ctLen % AES_BLOCK_LEN) != 0) {
            return (short) -1;
        }

        workAesKey.setKey(sEnc, sEncOff);

        Util.arrayFillNonAtomic(scratchCmacBlock, (short) 0, AES_BLOCK_LEN, (byte) 0x00);
        scratchCmacBlock[(short) (AES_BLOCK_LEN - 2)] = (byte) ((blockNr >> 8) & 0xFF);
        scratchCmacBlock[(short) (AES_BLOCK_LEN - 1)] = (byte) (blockNr & 0xFF);
        aesEncryptBlock(scratchCmacBlock, (short) 0, scratchCmacState, (short) 0);

        while (pos < ctLen) {
            aesDecryptBlock(ciphertext, (short) (ctOff + pos), scratchCmacSubkey1, (short) 0);
            i = 0;
            while (i < AES_BLOCK_LEN) {
                out[(short) (outOff + pos + i)] =
                        (byte) (scratchCmacSubkey1[i] ^ scratchCmacState[i]);
                i++;
            }
            Util.arrayCopyNonAtomic(ciphertext, (short) (ctOff + pos), scratchCmacState, (short) 0, AES_BLOCK_LEN);
            pos = (short) (pos + AES_BLOCK_LEN);
        }

        while (outLen > 0 && out[(short) (outOff + outLen - 1)] == 0x00) {
            outLen--;
        }
        if (outLen <= 0 || out[(short) (outOff + outLen - 1)] != (byte) 0x80) {
            return (short) -1;
        }
        return (short) (outLen - 1);
    }

    public void resetEuiccOtpk() {
        otkp.genKeyPair();
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

    public void setSmdpPbPublicKey(byte[] w, short off, short len) {
        smdpPbPk.setW(w, off, len);
    }

    public void resetSmdpPbPublicKey() {
        smdpPbPk.clearKey();
    }

    public boolean hasSmdpPbPublicKey() {
        return smdpPbPk.isInitialized();
    }

    public ECPublicKey getSmdpPbPublicKey() {
        return smdpPbPk;
    }

    public void setSmdpAuthPublicKey(byte[] w, short off, short len) {
        smdpAuthPk.setW(w, off, len);
    }

    public void resetSmdpAuthPublicKey() {
        smdpAuthPk.clearKey();
    }

    public boolean hasSmdpAuthPublicKey() {
        return smdpAuthPk.isInitialized();
    }

    public ECPublicKey getSmdpAuthPublicKey() {
        return smdpAuthPk;
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

    /**
     * Phase-1 pid KDF: K_pid = SHA256(SK_B_SEED || mnoChallenge), pid = SHA256(K_pid || eid).
     * Uses scratchScalar1 as a 32-byte intermediate buffer.
     */
    public void computePid(byte[] mnoChallenge, short mcOff, byte[] eid, short eidOff, short eidLen,
                           byte[] out, short outOff) {
        sha256.reset();
        sha256.update(SK_B_SEED, (short) 0, (short) SK_B_SEED.length);
        sha256.doFinal(mnoChallenge, mcOff, (short) 16, scratchScalar1, (short) 0);

        sha256.reset();
        sha256.update(scratchScalar1, (short) 0, SCALAR_LEN);
        sha256.doFinal(eid, eidOff, eidLen, out, outOff);
    }

    /**
     * ECIES encryption of EID under pk_LEA.
     * Generates a fresh ephemeral keypair, computes ECDH(eSK, pk_LEA), derives AES-128 key,
     * AES-128-ECB encrypts the EID (single block), and writes ePK(65B)||ct(16B) to out.
     * Returns 81 (total bytes written).
     * Uses scratchScalar1 (ECDH x-coord), scratchScalar2 (K_enc), scratchAes16 (AES key),
     * scratchPoint1 (LEA pk bytes), scratchPoint2 (ePK export).
     */
    public short encryptEidEcies(byte[] eid, short eidOff, short eidLen, byte[] out, short outOff) {
        eciesKp.genKeyPair();

        // ECDH(eSK, pk_LEA) → x-coordinate in scratchScalar1 (32 B)
        ka.init(eciesEtsk);
        short leaLen = leakPk.getW(scratchPoint1, (short) 0);
        ka.generateSecret(scratchPoint1, (short) 0, leaLen, scratchScalar1, (short) 0);

        // K_enc = SHA256(shared_x)[0:16]
        sha256.reset();
        sha256.doFinal(scratchScalar1, (short) 0, SCALAR_LEN, scratchScalar2, (short) 0);

        // AES-128-ECB(K_enc, EID) — equivalent to AES-CBC with IV=0 on one block
        workAesKey.setKey(scratchScalar2, (short) 0);
        aesEcb.init(workAesKey, Cipher.MODE_ENCRYPT);
        aesEcb.doFinal(eid, eidOff, eidLen, scratchAes16, (short) 0);

        // out = ePK (65 B) || ciphertext (16 B)
        short ePKLen = eciesEtpk.getW(out, outOff);
        Util.arrayCopyNonAtomic(scratchAes16, (short) 0, out, (short) (outOff + ePKLen), (short) 16);
        return (short) (ePKLen + 16);
    }

    /**
     * EC Schnorr proof-of-knowledge of sk_U bound to stmtBytes (the ZKStatement raw concat).
     * Deterministic nonce: k = H(FIXED_DEVICE_SCALAR || stmtBytes) mod n.
     * Proof = R (65 B) || s (32 B) where:
     *   R = k·G,  c = H(stmtBytes || R) mod n,  s = (k + c·sk_U) mod n.
     * Returns 97 (total bytes written to proofOut).
     */
    public short generateSchnorrProof(byte[] stmtBytes, short stmtOff, short stmtLen,
                                      byte[] proofOut, short proofOff) {
        ensureZkInitialized();

        // Deterministic nonce k = H(current_sk_U || stmtBytes) mod n.
        // Using the current private key (either fixed or session-derived) keeps the nonce
        // consistent with the public key committed to in the ZKStatement.
        jcmathlib.BigNat k = new jcmathlib.BigNat(SCALAR_LEN, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);
        ((ECPrivateKey) uSk).getS(scratchScalar2, (short) 0);
        sha256.reset();
        sha256.update(scratchScalar2, (short) 0, SCALAR_LEN);
        sha256.doFinal(stmtBytes, stmtOff, stmtLen, scratchScalar1, (short) 0);
        k.fromByteArray(scratchScalar1, (short) 0, SCALAR_LEN);
        k.mod(curve.rBN);

        // R = k·G
        jcmathlib.ECPoint R = new jcmathlib.ECPoint(curve);
        R.setW(jcmathlib.SecP256r1.G, (short) 0, (short) jcmathlib.SecP256r1.G.length);
        R.multiplication(k);
        short rLen = R.getW(proofOut, proofOff); // 65 bytes

        // c = H(stmtBytes || R) mod n — R is now in proofOut[proofOff..proofOff+rLen)
        jcmathlib.BigNat c = new jcmathlib.BigNat(SCALAR_LEN, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);
        sha256.reset();
        sha256.update(stmtBytes, stmtOff, stmtLen);
        sha256.doFinal(proofOut, proofOff, rLen, scratchScalar1, (short) 0);
        c.fromByteArray(scratchScalar1, (short) 0, SCALAR_LEN);
        c.mod(curve.rBN);

        // sk_U as BigNat
        jcmathlib.BigNat skU = new jcmathlib.BigNat(SCALAR_LEN, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);
        ((ECPrivateKey) uSk).getS(scratchScalar1, (short) 0);
        skU.fromByteArray(scratchScalar1, (short) 0, SCALAR_LEN);

        // s = (k + c·sk_U) mod n
        jcmathlib.BigNat s = new jcmathlib.BigNat(SCALAR_LEN, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);
        computeResponse(k, c, skU, s);
        s.copyToByteArray(proofOut, (short) (proofOff + rLen));

        return (short) (rLen + SCALAR_LEN); // 65 + 32 = 97
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

    private void computeAesCmac(byte[] key, short keyOff, byte[] msg, short msgOff, short msgLen, byte[] out, short outOff) {
        short fullBlocks = (short) (msgLen / AES_BLOCK_LEN);
        short lastBlockLen = (short) (msgLen % AES_BLOCK_LEN);
        short blocksBeforeLast;
        short msgPos = msgOff;
        short i;

        workAesKey.setKey(key, keyOff);
        deriveCmacSubkeys();

        Util.arrayFillNonAtomic(scratchCmacState, (short) 0, AES_BLOCK_LEN, (byte) 0x00);

        if (msgLen == 0) {
            fullBlocks = 0;
            lastBlockLen = 0;
            blocksBeforeLast = 0;
        } else if (lastBlockLen == 0) {
            blocksBeforeLast = (short) (fullBlocks - 1);
            lastBlockLen = AES_BLOCK_LEN;
        } else {
            blocksBeforeLast = fullBlocks;
        }

        i = 0;
        while (i < blocksBeforeLast) {
            xorIntoBlock(scratchCmacState, (short) 0, msg, msgPos, scratchCmacBlock);
            aesEncryptBlock(scratchCmacBlock, (short) 0, scratchCmacState, (short) 0);
            msgPos = (short) (msgPos + AES_BLOCK_LEN);
            i++;
        }

        Util.arrayFillNonAtomic(scratchCmacBlock, (short) 0, AES_BLOCK_LEN, (byte) 0x00);
        if (msgLen != 0 && (short) (msgLen % AES_BLOCK_LEN) == 0) {
            Util.arrayCopyNonAtomic(msg, msgPos, scratchCmacBlock, (short) 0, AES_BLOCK_LEN);
            xorBlock(scratchCmacBlock, scratchCmacSubkey1);
        } else {
            if (lastBlockLen > 0) {
                Util.arrayCopyNonAtomic(msg, msgPos, scratchCmacBlock, (short) 0, lastBlockLen);
            }
            scratchCmacBlock[lastBlockLen] = (byte) 0x80;
            xorBlock(scratchCmacBlock, scratchCmacSubkey2);
        }

        xorBlock(scratchCmacBlock, scratchCmacState);
        aesEncryptBlock(scratchCmacBlock, (short) 0, out, outOff);
    }

    private void deriveCmacSubkeys() {
        Util.arrayFillNonAtomic(scratchCmacBlock, (short) 0, AES_BLOCK_LEN, (byte) 0x00);
        aesEncryptBlock(scratchCmacBlock, (short) 0, scratchCmacState, (short) 0);
        leftShiftBlock(scratchCmacState, scratchCmacSubkey1);
        if ((scratchCmacState[0] & 0x80) != 0) {
            scratchCmacSubkey1[(short) (AES_BLOCK_LEN - 1)] ^= (byte) 0x87;
        }
        leftShiftBlock(scratchCmacSubkey1, scratchCmacSubkey2);
        if ((scratchCmacSubkey1[0] & 0x80) != 0) {
            scratchCmacSubkey2[(short) (AES_BLOCK_LEN - 1)] ^= (byte) 0x87;
        }
    }

    private void aesEncryptBlock(byte[] in, short inOff, byte[] out, short outOff) {
        aesEcb.init(workAesKey, Cipher.MODE_ENCRYPT);
        aesEcb.doFinal(in, inOff, AES_BLOCK_LEN, out, outOff);
    }

    private void aesDecryptBlock(byte[] in, short inOff, byte[] out, short outOff) {
        aesEcb.init(workAesKey, Cipher.MODE_DECRYPT);
        aesEcb.doFinal(in, inOff, AES_BLOCK_LEN, out, outOff);
    }

    private static void leftShiftBlock(byte[] in, byte[] out) {
        byte carry = 0;
        short i = (short) (AES_BLOCK_LEN - 1);
        while (i >= 0) {
            byte value = in[i];
            out[i] = (byte) ((value << 1) | carry);
            carry = (byte) (((value & 0x80) != 0) ? 1 : 0);
            i--;
        }
    }

    private static void xorIntoBlock(byte[] left, short leftOff, byte[] right, short rightOff, byte[] out) {
        short i = 0;
        while (i < AES_BLOCK_LEN) {
            out[i] = (byte) (left[(short) (leftOff + i)] ^ right[(short) (rightOff + i)]);
            i++;
        }
    }

    private static void xorBlock(byte[] block, byte[] other) {
        short i = 0;
        while (i < AES_BLOCK_LEN) {
            block[i] ^= other[i];
            i++;
        }
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
            aesEcb = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
            aesCbc = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
            workAesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);

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

            otkp = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
            setP256Params(otkp.getPrivate());
            setP256Params(otkp.getPublic());
            euiccOtsk = (ECPrivateKey) otkp.getPrivate();
            euiccOtpk = (ECPublicKey) otkp.getPublic();
            otkp.genKeyPair();

            smdpPbPk = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);
            setP256Params(smdpPbPk);
            smdpAuthPk = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);
            setP256Params(smdpAuthPk);
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

            // Phase-0 hardcoded public keys for MNO and LEA.
            mnoPk.setW(MNO_PUBLIC_W, (short) 0, (short) MNO_PUBLIC_W.length);
            leakPk.setW(LEA_PUBLIC_W, (short) 0, (short) LEA_PUBLIC_W.length);

            eciesKp = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
            setP256Params(eciesKp.getPrivate());
            setP256Params(eciesKp.getPublic());
            eciesEtsk = (ECPrivateKey) eciesKp.getPrivate();
            eciesEtpk = (ECPublicKey) eciesKp.getPublic();
            eciesKp.genKeyPair();
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
