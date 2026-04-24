import com.licel.jcardsim.base.Simulator;
import javacard.framework.AID;
import javacard.security.ECPublicKey;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;

import static org.junit.Assert.*;

/**
 * Direct unit tests for zk.esim.applet.Crypto.
 *
 * All test methods call Crypto methods as plain Java method calls with
 * pre-built byte[] arguments.  No APDU transmission is used anywhere.
 *
 * Bootstrap: a CryptoTestHarness applet is installed into a jCardSim
 * Simulator (providing the required JCRE context), and the Crypto object
 * is obtained via CryptoTestHarness.INSTANCE.getCrypto().  After that,
 * tests interact with Crypto directly.
 */
public class CryptoTest {

    private static final byte[] HARNESS_AID_BYTES = {
        (byte) 0xD0, 0x70, 0x02, (byte) 0xCA, 0x44, (byte) 0x90, 0x01, (byte) 0xFE
    };

    /** Keep a reference so jCardSim's JCRE context is not garbage-collected. */
    private static Simulator sim;
    private static CryptoTestHarness harness;
    private static zk.esim.applet.Crypto crypto;

    private static final byte[] TEST_HOST_ID = {
            (byte) 0xA1, (byte) 0xB2, (byte) 0xC3, (byte) 0xD4
    };
    private static final byte[] TEST_EID = {
            (byte) 0x89, (byte) 0x04, (byte) 0x90, (byte) 0x32,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x12, 0x34,
            0x56, 0x78, (byte) 0x90, 0x12
    };

    @BeforeClass
    public static void setup() throws Exception {
        sim = new Simulator();
        AID aid = new AID(HARNESS_AID_BYTES, (short) 0, (byte) HARNESS_AID_BYTES.length);
        sim.installApplet(aid, CryptoTestHarness.class);
        assertTrue("CryptoTestHarness must be selectable", sim.selectApplet(aid));

        harness = CryptoTestHarness.INSTANCE;
        crypto = harness.getCrypto();

        // Inject dummy P-256 points into the private mnoPk/leakPk fields so that
        // generateZkp() can proceed (these are normally set via the SGP.22 protocol).
        harness.initZkpKeys();
    }

    private static byte[] encodeUncompressedPoint(java.security.interfaces.ECPublicKey publicKey) {
        byte[] out = new byte[65];
        out[0] = 0x04;
        byte[] xBytes = publicKey.getW().getAffineX().toByteArray();
        byte[] yBytes = publicKey.getW().getAffineY().toByteArray();
        int xStart = (xBytes.length == 33 && xBytes[0] == 0) ? 1 : 0;
        int yStart = (yBytes.length == 33 && yBytes[0] == 0) ? 1 : 0;
        int xLen = xBytes.length - xStart;
        int yLen = yBytes.length - yStart;
        System.arraycopy(xBytes, xStart, out, 1 + (32 - xLen), xLen);
        System.arraycopy(yBytes, yStart, out, 33 + (32 - yLen), yLen);
        return out;
    }

    private static byte[] deriveBspMaterialJava(byte[] sharedSecret, byte[] hostId, byte[] eid) throws Exception {
        ByteArrayOutputStream sharedInfo = new ByteArrayOutputStream();
        sharedInfo.write(0x88);
        sharedInfo.write(0x10);
        sharedInfo.write(hostId.length);
        sharedInfo.write(hostId);
        sharedInfo.write(eid.length);
        sharedInfo.write(eid);

        byte[] sharedInfoBytes = sharedInfo.toByteArray();
        byte[] kdfOut = new byte[48];
        int outPos = 0;
        int counter = 1;
        while (outPos < kdfOut.length) {
            // ANSI X9.63 KDF: H(sharedSecret || counter (4-byte BE) || sharedInfo).
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(sharedSecret);
            digest.update(new byte[]{0x00, 0x00, 0x00, (byte) counter});
            digest.update(sharedInfoBytes);
            byte[] block = digest.digest();
            int toCopy = Math.min(block.length, kdfOut.length - outPos);
            System.arraycopy(block, 0, kdfOut, outPos, toCopy);
            outPos += toCopy;
            counter++;
        }
        return kdfOut;
    }

    private static byte[] aesEncryptBlock(byte[] key, byte[] block) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
        return cipher.doFinal(block);
    }

    private static byte[] leftShiftBlock(byte[] in) {
        byte[] out = new byte[16];
        int carry = 0;
        for (int i = 15; i >= 0; i--) {
            int value = in[i] & 0xFF;
            out[i] = (byte) ((value << 1) | carry);
            carry = (value >>> 7) & 0x01;
        }
        return out;
    }

    private static byte[] xor(byte[] left, byte[] right) {
        byte[] out = new byte[left.length];
        for (int i = 0; i < left.length; i++) {
            out[i] = (byte) (left[i] ^ right[i]);
        }
        return out;
    }

    private static byte[] aesCmac(byte[] key, byte[] data) throws Exception {
        byte[] l = aesEncryptBlock(key, new byte[16]);
        byte[] k1 = leftShiftBlock(l);
        if ((l[0] & 0x80) != 0) {
            k1[15] ^= (byte) 0x87;
        }
        byte[] k2 = leftShiftBlock(k1);
        if ((k1[0] & 0x80) != 0) {
            k2[15] ^= (byte) 0x87;
        }

        int blockCount = data.length == 0 ? 1 : ((data.length + 15) / 16);
        boolean completeLastBlock = data.length != 0 && (data.length % 16) == 0;

        byte[] state = new byte[16];
        for (int i = 0; i < blockCount - 1; i++) {
            byte[] block = Arrays.copyOfRange(data, i * 16, (i + 1) * 16);
            state = aesEncryptBlock(key, xor(state, block));
        }

        byte[] lastBlock = new byte[16];
        if (completeLastBlock) {
            System.arraycopy(data, (blockCount - 1) * 16, lastBlock, 0, 16);
            lastBlock = xor(lastBlock, k1);
        } else {
            int lastLen = data.length - ((blockCount - 1) * 16);
            if (lastLen > 0) {
                System.arraycopy(data, (blockCount - 1) * 16, lastBlock, 0, lastLen);
            }
            lastBlock[lastLen] = (byte) 0x80;
            lastBlock = xor(lastBlock, k2);
        }

        return aesEncryptBlock(key, xor(state, lastBlock));
    }

    private static byte[] encryptBspPayload(byte[] sEnc, int blockNr, byte[] plaintext) throws Exception {
        byte[] padded = new byte[((plaintext.length + 1 + 15) / 16) * 16];
        System.arraycopy(plaintext, 0, padded, 0, plaintext.length);
        padded[plaintext.length] = (byte) 0x80;

        byte[] counterBlock = new byte[16];
        counterBlock[12] = (byte) ((blockNr >> 24) & 0xFF);
        counterBlock[13] = (byte) ((blockNr >> 16) & 0xFF);
        counterBlock[14] = (byte) ((blockNr >> 8) & 0xFF);
        counterBlock[15] = (byte) (blockNr & 0xFF);

        Cipher icvCipher = Cipher.getInstance("AES/CBC/NoPadding");
        icvCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(sEnc, "AES"), new IvParameterSpec(new byte[16]));
        byte[] icv = icvCipher.doFinal(counterBlock);

        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(sEnc, "AES"), new IvParameterSpec(icv));
        return cipher.doFinal(padded);
    }

    private static byte[] wrapTlvHeader(int tag, int valueLen) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(tag & 0xFF);
        out.write(valueLen & 0xFF);
        return out.toByteArray();
    }

    private static byte[] buildProtectedSegment(byte[] sEnc, byte[] sMac, byte[] mcv,
                                                int blockNr, int tag, byte[] plaintext,
                                                boolean macOnly) throws Exception {
        byte[] protectedData = macOnly ? plaintext : encryptBspPayload(sEnc, blockNr, plaintext);
        byte[] header = wrapTlvHeader(tag, protectedData.length + 8);
        byte[] macInput = new byte[mcv.length + header.length + protectedData.length];
        System.arraycopy(mcv, 0, macInput, 0, mcv.length);
        System.arraycopy(header, 0, macInput, mcv.length, header.length);
        System.arraycopy(protectedData, 0, macInput, mcv.length + header.length, protectedData.length);
        byte[] fullCmac = aesCmac(sMac, macInput);
        System.arraycopy(fullCmac, 0, mcv, 0, 16);

        byte[] out = new byte[header.length + protectedData.length + 8];
        System.arraycopy(header, 0, out, 0, header.length);
        System.arraycopy(protectedData, 0, out, header.length, protectedData.length);
        System.arraycopy(fullCmac, 0, out, header.length + protectedData.length, 8);
        return out;
    }

    // -------------------------------------------------------------------------
    // 1. Key pair generation
    // -------------------------------------------------------------------------

    @Test
    public void testKeyPairGenerationExportsValidP256Point() throws Exception {
        byte[] pk = new byte[65];
        short n = crypto.exportPublicKey(pk, (short) 0);

        assertEquals("Exported public key must be 65 bytes", 65, n);
        assertEquals("Public key must start with 0x04 (uncompressed point)",
                (byte) 0x04, pk[0]);

        // Reconstruct via Java SE KeyFactory; generatePublic() throws
        // InvalidKeySpecException if the point is not on secp256r1.
        AlgorithmParameters ap = AlgorithmParameters.getInstance("EC");
        ap.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec params = ap.getParameterSpec(ECParameterSpec.class);

        BigInteger x = new BigInteger(1, Arrays.copyOfRange(pk, 1, 33));
        BigInteger y = new BigInteger(1, Arrays.copyOfRange(pk, 33, 65));
        KeyFactory.getInstance("EC")
                  .generatePublic(new ECPublicKeySpec(new java.security.spec.ECPoint(x, y), params));
    }

    // -------------------------------------------------------------------------
    // 2. Sign / verify round-trip (internal verifier)
    // -------------------------------------------------------------------------

    @Test
    public void testSignVerifyRoundTripInternal() {
        byte[] msg = "hello zkesim".getBytes();
        byte[] sig = new byte[80];
        short sigLen = crypto.sign(msg, (short) 0, (short) msg.length, sig, (short) 0);

        byte[] pk = new byte[65];
        crypto.exportPublicKey(pk, (short) 0);

        assertTrue("Valid signature must verify with internal verifier",
                harness.verifyEcdsaSha256(pk, (short) 65,
                        msg, (short) msg.length,
                        sig, sigLen));

        // Negative: flip one byte inside the signature
        byte[] badSig = Arrays.copyOf(sig, sig.length);
        badSig[sigLen / 2] ^= (byte) 0xFF;
        assertFalse("Tampered signature must not verify",
                harness.verifyEcdsaSha256(pk, (short) 65,
                        msg, (short) msg.length,
                        badSig, sigLen));
    }

    // -------------------------------------------------------------------------
    // 3. Cross-verify applet signature with Java SE ECDSA
    // -------------------------------------------------------------------------

    @Test
    public void testSignatureVerifiesWithJavaSeCrypto() throws Exception {
        byte[] msg = "cross-verify test".getBytes();
        byte[] sig = new byte[80];
        short sigLen = crypto.sign(msg, (short) 0, (short) msg.length, sig, (short) 0);

        byte[] pk = new byte[65];
        crypto.exportPublicKey(pk, (short) 0);

        AlgorithmParameters ap = AlgorithmParameters.getInstance("EC");
        ap.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec params = ap.getParameterSpec(ECParameterSpec.class);
        BigInteger x = new BigInteger(1, Arrays.copyOfRange(pk, 1, 33));
        BigInteger y = new BigInteger(1, Arrays.copyOfRange(pk, 33, 65));
        java.security.PublicKey jsePublicKey = KeyFactory.getInstance("EC")
                .generatePublic(new ECPublicKeySpec(
                        new java.security.spec.ECPoint(x, y), params));

        java.security.Signature jseSig =
                java.security.Signature.getInstance("SHA256withECDSA");
        jseSig.initVerify(jsePublicKey);
        jseSig.update(msg);
        assertTrue("Applet ECDSA signature must verify with Java SE SHA256withECDSA",
                jseSig.verify(Arrays.copyOf(sig, sigLen)));
    }

    // -------------------------------------------------------------------------
    // 4. ZKP: well-formed output
    // -------------------------------------------------------------------------

    @Test
    public void testGenerateZkpProducesWellFormedOutput() throws Exception {
        byte[] eid = new byte[32];
        Arrays.fill(eid, (byte) 0xAB);
        byte[] pid = new byte[32];
        crypto.hashEidToPid(eid, pid);
        byte[] nonce = new byte[16];
        Arrays.fill(nonce, (byte) 0x55);

        byte[] s = new byte[32];
        byte[] t = new byte[65];
        short tLen = crypto.generateZkp(eid, pid, nonce, s, (short) 0, t, (short) 0);

        assertEquals("t must be 65 bytes", 65, tLen);
        assertEquals("t must start with 0x04 (uncompressed point)", (byte) 0x04, t[0]);

        // t must be a valid point on secp256r1
        AlgorithmParameters ap = AlgorithmParameters.getInstance("EC");
        ap.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec params = ap.getParameterSpec(ECParameterSpec.class);
        BigInteger tx = new BigInteger(1, Arrays.copyOfRange(t, 1, 33));
        BigInteger ty = new BigInteger(1, Arrays.copyOfRange(t, 33, 65));
        KeyFactory.getInstance("EC")
                  .generatePublic(new ECPublicKeySpec(
                          new java.security.spec.ECPoint(tx, ty), params));

        // s must be a non-zero scalar less than the group order
        BigInteger sVal = new BigInteger(1, s);
        BigInteger order = params.getOrder();
        assertTrue("s must be > 0", sVal.compareTo(BigInteger.ZERO) > 0);
        assertTrue("s must be < group order n", sVal.compareTo(order) < 0);
    }

    // -------------------------------------------------------------------------
    // 5. ZKP: output is randomised across calls
    // -------------------------------------------------------------------------

    @Test
    public void testGenerateZkpIsRandomized() {
        byte[] eid = new byte[32];
        Arrays.fill(eid, (byte) 0x11);
        byte[] pid = new byte[32];
        crypto.hashEidToPid(eid, pid);
        byte[] nonce = new byte[16];
        Arrays.fill(nonce, (byte) 0x22);

        byte[] s1 = new byte[32];
        byte[] t1 = new byte[65];
        crypto.generateZkp(eid, pid, nonce, s1, (short) 0, t1, (short) 0);

        byte[] s2 = new byte[32];
        byte[] t2 = new byte[65];
        crypto.generateZkp(eid, pid, nonce, s2, (short) 0, t2, (short) 0);

        assertFalse("ZKP outputs must differ across calls (randomised witness / r)",
                Arrays.equals(s1, s2) && Arrays.equals(t1, t2));
    }

    // -------------------------------------------------------------------------
    // 6. deriveSessionKey: cross-validate ECDH with Java SE
    // -------------------------------------------------------------------------

    @Test
    public void testDeriveSessionKeyMatchesJavaEcdh() throws Exception {
        // Generate a peer key pair in Java SE on secp256r1
        java.security.KeyPairGenerator kpg =
                java.security.KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        java.security.KeyPair peerKp = kpg.generateKeyPair();
        java.security.interfaces.ECPublicKey peerPkJse =
                (java.security.interfaces.ECPublicKey) peerKp.getPublic();

        // Encode peer public key as an uncompressed 65-byte point for JavaCard
        java.security.spec.ECPoint w = peerPkJse.getW();
        byte[] peerW = new byte[65];
        peerW[0] = 0x04;
        byte[] xBytes = w.getAffineX().toByteArray();
        byte[] yBytes = w.getAffineY().toByteArray();
        // BigInteger.toByteArray() may prepend a sign byte; strip it and left-pad to 32
        int xStart = (xBytes.length == 33 && xBytes[0] == 0) ? 1 : 0;
        int yStart = (yBytes.length == 33 && yBytes[0] == 0) ? 1 : 0;
        int xLen = xBytes.length - xStart;
        int yLen = yBytes.length - yStart;
        System.arraycopy(xBytes, xStart, peerW, 1  + (32 - xLen), xLen);
        System.arraycopy(yBytes, yStart, peerW, 33 + (32 - yLen), yLen);

        // Wrap into a JavaCard ECPublicKey
        ECPublicKey peerPkJc = harness.buildP256PublicKey(peerW, (short) 65);

        // Perform ECDH inside the JavaCard runtime
        byte[] sharedOut  = new byte[65];
        byte[] sessionOut = new byte[32];
        short sharedLen = crypto.deriveSessionKey(
                peerPkJc, sharedOut, (short) 0, sessionOut, (short) 0);

        assertTrue("sharedLen must be > 0", sharedLen > 0);

        // Compute the same ECDH on Java SE: peer private key × applet public key
        byte[] appletPkBytes = new byte[65];
        crypto.exportPublicKey(appletPkBytes, (short) 0);

        AlgorithmParameters ap = AlgorithmParameters.getInstance("EC");
        ap.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec params = ap.getParameterSpec(ECParameterSpec.class);
        BigInteger ax = new BigInteger(1, Arrays.copyOfRange(appletPkBytes, 1, 33));
        BigInteger ay = new BigInteger(1, Arrays.copyOfRange(appletPkBytes, 33, 65));
        java.security.PublicKey appletPkJse = KeyFactory.getInstance("EC")
                .generatePublic(new ECPublicKeySpec(
                        new java.security.spec.ECPoint(ax, ay), params));

        javax.crypto.KeyAgreement jseKa =
                javax.crypto.KeyAgreement.getInstance("ECDH");
        jseKa.init(peerKp.getPrivate());
        jseKa.doPhase(appletPkJse, true);
        byte[] jseSharedX = jseKa.generateSecret();   // 32-byte X coordinate

        // ALG_EC_SVDP_DH_PLAIN may return 32-byte X-only or 65-byte uncompressed point
        // depending on jCardSim version; extract X for comparison in either case.
        byte[] appletSharedX;
        if (sharedLen == 65) {
            appletSharedX = Arrays.copyOfRange(sharedOut, 1, 33);
        } else {
            appletSharedX = Arrays.copyOf(sharedOut, (int) sharedLen);
        }
        assertArrayEquals("ECDH shared X-coordinate must match Java SE output",
                jseSharedX, appletSharedX);

        // Validate session key = SHA-256(sharedOut[0..sharedLen-1])
        byte[] expectedSession = MessageDigest.getInstance("SHA-256")
                .digest(Arrays.copyOf(sharedOut, (int) sharedLen));
        assertArrayEquals("Session key must equal SHA-256(shared secret)", expectedSession, sessionOut);
    }

    @Test
    public void testGenerateEuiccOtpkAndSharedSecretMatchJavaSeEcdh() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair peerKp = kpg.generateKeyPair();
        java.security.interfaces.ECPublicKey peerPkJse =
                (java.security.interfaces.ECPublicKey) peerKp.getPublic();

        byte[] peerW = new byte[65];
        peerW[0] = 0x04;
        byte[] xBytes = peerPkJse.getW().getAffineX().toByteArray();
        byte[] yBytes = peerPkJse.getW().getAffineY().toByteArray();
        int xStart = (xBytes.length == 33 && xBytes[0] == 0) ? 1 : 0;
        int yStart = (yBytes.length == 33 && yBytes[0] == 0) ? 1 : 0;
        int xLen = xBytes.length - xStart;
        int yLen = yBytes.length - yStart;
        System.arraycopy(xBytes, xStart, peerW, 1 + (32 - xLen), xLen);
        System.arraycopy(yBytes, yStart, peerW, 33 + (32 - yLen), yLen);

        byte[] euiccOtpk = new byte[65];
        short otpkLen = crypto.generateEuiccOtpk(euiccOtpk, (short) 0);
        assertEquals("Generated euiccOtpk must be an uncompressed P-256 point", 65, otpkLen);
        assertEquals("euiccOtpk must start with 0x04", (byte) 0x04, euiccOtpk[0]);

        byte[] sharedOut = new byte[65];
        short sharedLen = crypto.computeBspSharedSecret(peerW, (short) 0, (short) peerW.length, sharedOut, (short) 0);
        assertTrue("Shared secret must not be empty", sharedLen > 0);

        AlgorithmParameters ap = AlgorithmParameters.getInstance("EC");
        ap.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec params = ap.getParameterSpec(ECParameterSpec.class);
        BigInteger ax = new BigInteger(1, Arrays.copyOfRange(euiccOtpk, 1, 33));
        BigInteger ay = new BigInteger(1, Arrays.copyOfRange(euiccOtpk, 33, 65));
        java.security.PublicKey euiccOtpkJse = KeyFactory.getInstance("EC")
                .generatePublic(new ECPublicKeySpec(new java.security.spec.ECPoint(ax, ay), params));

        javax.crypto.KeyAgreement jseKa = javax.crypto.KeyAgreement.getInstance("ECDH");
        jseKa.init(peerKp.getPrivate());
        jseKa.doPhase(euiccOtpkJse, true);
        byte[] jseSharedX = jseKa.generateSecret();

        byte[] appletSharedX = (sharedLen == 65)
                ? Arrays.copyOfRange(sharedOut, 1, 33)
                : Arrays.copyOf(sharedOut, (int) sharedLen);
        assertArrayEquals("Ephemeral ECDH shared X-coordinate must match Java SE output",
                jseSharedX, appletSharedX);
    }

    @Test
    public void testDeriveBspKeysMatchesJavaKdf() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair peerKp = kpg.generateKeyPair();

        byte[] peerW = encodeUncompressedPoint((java.security.interfaces.ECPublicKey) peerKp.getPublic());
        byte[] euiccOtpk = new byte[65];
        short otpkLen = crypto.generateEuiccOtpk(euiccOtpk, (short) 0);
        assertEquals(65, otpkLen);

        byte[] sharedSecret = new byte[65];
        short sharedLen = crypto.computeBspSharedSecret(peerW, (short) 0, (short) peerW.length, sharedSecret, (short) 0);
        byte[] appletSharedX = (sharedLen == 65)
                ? Arrays.copyOfRange(sharedSecret, 1, 33)
                : Arrays.copyOf(sharedSecret, (int) sharedLen);

        AlgorithmParameters ap = AlgorithmParameters.getInstance("EC");
        ap.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec params = ap.getParameterSpec(ECParameterSpec.class);
        BigInteger ax = new BigInteger(1, Arrays.copyOfRange(euiccOtpk, 1, 33));
        BigInteger ay = new BigInteger(1, Arrays.copyOfRange(euiccOtpk, 33, 65));
        java.security.PublicKey euiccOtpkJse = KeyFactory.getInstance("EC")
                .generatePublic(new ECPublicKeySpec(new java.security.spec.ECPoint(ax, ay), params));

        javax.crypto.KeyAgreement ka = javax.crypto.KeyAgreement.getInstance("ECDH");
        ka.init(peerKp.getPrivate());
        ka.doPhase(euiccOtpkJse, true);
        byte[] jseSharedX = ka.generateSecret();
        assertArrayEquals(jseSharedX, appletSharedX);

        byte[] sEnc = new byte[16];
        byte[] sMac = new byte[16];
        byte[] mcv = new byte[16];
        crypto.deriveBspKeys(sharedSecret, (short) 0, sharedLen,
                (byte) 0x88, (byte) 0x10,
                TEST_HOST_ID, (short) 0, (short) TEST_HOST_ID.length,
                TEST_EID, (short) 0, (short) TEST_EID.length,
                sEnc, (short) 0,
                sMac, (short) 0,
                mcv, (short) 0);

        byte[] expected = deriveBspMaterialJava(jseSharedX, TEST_HOST_ID, TEST_EID);
        assertArrayEquals("Initial MCV must match Java KDF", Arrays.copyOfRange(expected, 0, 16), mcv);
        assertArrayEquals("sEnc must match Java KDF", Arrays.copyOfRange(expected, 16, 32), sEnc);
        assertArrayEquals("sMac must match Java KDF", Arrays.copyOfRange(expected, 32, 48), sMac);
    }

    @Test
    public void testVerifyBspSegmentAcceptsJavaBuiltSegment() throws Exception {
        byte[] sEnc = {
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
        };
        byte[] sMac = {
                0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F
        };
        byte[] initialMcv = {
                0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F
        };
        byte[] plaintext = {
                0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF
        };

        byte[] expectedMcv = Arrays.copyOf(initialMcv, initialMcv.length);
        byte[] segment = buildProtectedSegment(sEnc, sMac, expectedMcv, 1, 0x87, plaintext, false);

        byte[] actualMcv = Arrays.copyOf(initialMcv, initialMcv.length);
        assertTrue("Java-built BSP segment must verify in applet Crypto",
                crypto.verifyBspSegment(segment, (short) 0, (short) segment.length, sMac, (short) 0, actualMcv, (short) 0));
        assertArrayEquals("Successful verification must advance MCV to full CMAC", expectedMcv, actualMcv);

        segment[segment.length - 1] ^= 0x01;
        assertFalse("Tampered BSP MAC must fail verification",
                crypto.verifyBspSegment(segment, (short) 0, (short) segment.length, sMac, (short) 0,
                        Arrays.copyOf(initialMcv, initialMcv.length), (short) 0));
    }

    // -------------------------------------------------------------------------
    // 7. encryptEid: output length, not plaintext, randomised across calls
    // -------------------------------------------------------------------------

    @Test
    public void testEncryptEidRandomisedAndLength() {
        byte[] eid = new byte[16];
        Arrays.fill(eid, (byte) 0xAA);

        byte[] out1 = crypto.encryptEid(eid);
        byte[] out2 = crypto.encryptEid(eid);

        assertEquals("Encrypted output must be 16 bytes", 16, out1.length);
        assertEquals("Encrypted output must be 16 bytes", 16, out2.length);
        assertFalse("Ciphertext must differ from plaintext", Arrays.equals(eid, out1));
        assertFalse("Ciphertext must differ from plaintext", Arrays.equals(eid, out2));
        assertFalse("Two encryptions with different random keys must differ",
                Arrays.equals(out1, out2));
    }

    // -------------------------------------------------------------------------
    // 8. buildCertificate: ASN.1 SEQUENCE wrapping
    // -------------------------------------------------------------------------

    @Test
    public void testBuildCertificateWrapsAsAsn1Sequence() {
        byte[] serial   = {0x01, 0x02};
        byte[] sigAlg   = {0x03, 0x04};
        byte[] issuer   = {0x05, 0x06};
        byte[] validity = {0x07, 0x08};
        byte[] subject  = {0x09, 0x0A};
        byte[] spki     = {0x0B, 0x0C};

        byte[] out = new byte[64];
        short tbsLen = crypto.buildCertificate(
                serial,   (short) serial.length,
                sigAlg,   (short) sigAlg.length,
                issuer,   (short) issuer.length,
                validity, (short) validity.length,
                subject,  (short) subject.length,
                spki,     (short) spki.length,
                out, (short) 0);

        assertEquals("First byte must be SEQUENCE tag 0x30", (byte) 0x30, out[0]);

        // Parse the DER length field
        int contentLen;
        int headerLen;
        if ((out[1] & 0xFF) < 128) {
            contentLen = out[1] & 0xFF;
            headerLen  = 2;
        } else {
            // 0x81 LL form
            contentLen = out[2] & 0xFF;
            headerLen  = 3;
        }

        int expectedContentLen = serial.length + sigAlg.length + issuer.length
                               + validity.length + subject.length + spki.length;
        assertEquals("Content length must equal sum of all field lengths",
                expectedContentLen, contentLen);
        assertEquals("tbsLen must equal header bytes + content length",
                headerLen + contentLen, (int) tbsLen);

        // Fields must be concatenated in order starting after the header
        int pos = headerLen;
        for (byte[] field : new byte[][] {serial, sigAlg, issuer, validity, subject, spki}) {
            for (byte b : field) {
                assertEquals("Field bytes must appear in order inside SEQUENCE", b, out[pos++]);
            }
        }
    }

    // -------------------------------------------------------------------------
    // 9. verifyCertificate: round-trip and tamper detection
    // -------------------------------------------------------------------------

    @Test
    public void testVerifyCertificateRoundTrip() {
        byte[] serial   = {0x11, 0x22};
        byte[] sigAlg   = {0x33, 0x44};
        byte[] issuer   = {0x55, 0x66};
        byte[] validity = {0x77, (byte) 0x88};
        byte[] subject  = {(byte) 0x99, (byte) 0xAA};
        byte[] spki     = {(byte) 0xBB, (byte) 0xCC};

        // Build the TBS (to-be-signed) structure
        byte[] tbs = new byte[512];
        short tbsLen = crypto.buildCertificate(
                serial,   (short) serial.length,
                sigAlg,   (short) sigAlg.length,
                issuer,   (short) issuer.length,
                validity, (short) validity.length,
                subject,  (short) subject.length,
                spki,     (short) spki.length,
                tbs, (short) 0);

        // Sign the TBS with the device key
        byte[] sig = new byte[80];
        short sigLen = crypto.sign(tbs, (short) 0, tbsLen, sig, (short) 0);

        // Positive: original fields + original signature must verify
        assertTrue("Valid certificate must verify",
                crypto.verifyCertificate(
                        crypto.getDevicePublicKey(),
                        serial,   (short) serial.length,
                        sigAlg,   (short) sigAlg.length,
                        issuer,   (short) issuer.length,
                        validity, (short) validity.length,
                        subject,  (short) subject.length,
                        spki,     (short) spki.length,
                        sig, sigLen));

        // Negative A: tamper one byte in the signature
        byte[] tamperedSig = Arrays.copyOf(sig, sig.length);
        tamperedSig[sigLen / 2] ^= (byte) 0xFF;
        assertFalse("Tampered signature must not verify",
                crypto.verifyCertificate(
                        crypto.getDevicePublicKey(),
                        serial,   (short) serial.length,
                        sigAlg,   (short) sigAlg.length,
                        issuer,   (short) issuer.length,
                        validity, (short) validity.length,
                        subject,  (short) subject.length,
                        spki,     (short) spki.length,
                        tamperedSig, sigLen));

        // Negative B: tamper a TBS field (serial number second byte 0x22 → 0x23)
        // verifyCertificate re-builds the TBS from the supplied fields, so the
        // rebuilt TBS will not match what was signed, causing verification to fail.
        byte[] tamperedSerial = {0x11, 0x23};
        assertFalse("Tampered TBS field must invalidate the signature",
                crypto.verifyCertificate(
                        crypto.getDevicePublicKey(),
                        tamperedSerial, (short) tamperedSerial.length,
                        sigAlg,   (short) sigAlg.length,
                        issuer,   (short) issuer.length,
                        validity, (short) validity.length,
                        subject,  (short) subject.length,
                        spki,     (short) spki.length,
                        sig, sigLen));
    }

    // -------------------------------------------------------------------------
    // 10. buildSelfSignedEuiccCert: parseable by Java SE, self-signature verifies,
    //     SPKI carries the device public key.
    // -------------------------------------------------------------------------

    @Test
    public void testBuildSelfSignedEuiccCertIsValidX509() throws Exception {
        byte[] out = new byte[512];
        short certLen = crypto.buildSelfSignedEuiccCert(out, (short) 0);

        assertTrue("cert length must be > 0", certLen > 0);
        assertTrue("cert length must fit in buffer", certLen <= out.length);
        assertEquals("cert must start with SEQUENCE tag", (byte) 0x30, out[0]);

        byte[] certDer = Arrays.copyOf(out, certLen);

        java.security.cert.CertificateFactory cf =
                java.security.cert.CertificateFactory.getInstance("X.509");
        java.security.cert.X509Certificate cert = (java.security.cert.X509Certificate)
                cf.generateCertificate(new java.io.ByteArrayInputStream(certDer));

        // Self-signed: verify the cert using its own public key.
        cert.verify(cert.getPublicKey());

        // SPKI must carry the device public key bytes.
        byte[] devicePk = new byte[65];
        crypto.exportPublicKey(devicePk, (short) 0);

        java.security.interfaces.ECPublicKey certPk =
                (java.security.interfaces.ECPublicKey) cert.getPublicKey();
        java.security.spec.ECPoint w = certPk.getW();
        BigInteger dx = new BigInteger(1, Arrays.copyOfRange(devicePk, 1, 33));
        BigInteger dy = new BigInteger(1, Arrays.copyOfRange(devicePk, 33, 65));
        assertEquals("cert SPKI x-coordinate must match device public key", dx, w.getAffineX());
        assertEquals("cert SPKI y-coordinate must match device public key", dy, w.getAffineY());

        // Issuer == Subject (self-signed).
        assertEquals("self-signed cert must have issuer == subject",
                cert.getIssuerX500Principal(), cert.getSubjectX500Principal());
    }
}
