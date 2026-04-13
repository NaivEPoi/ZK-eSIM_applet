import com.licel.jcardsim.base.Simulator;
import javacard.framework.AID;
import javacard.security.ECPublicKey;
import org.junit.BeforeClass;
import org.junit.Test;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
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
}
