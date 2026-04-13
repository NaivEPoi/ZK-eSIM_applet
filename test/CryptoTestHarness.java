import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.security.ECKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.Signature;

/**
 * Minimal test-only applet whose sole purpose is to instantiate Crypto inside
 * the JCRE context that jCardSim provides, and then expose the resulting object
 * for direct-call unit tests in CryptoTest.
 *
 * AID d0:70:02:ca:44:90:01:FE (distinct from the production applet 90:01:01).
 * The process() method is a no-op — tests never send APDUs to this applet.
 */
public final class CryptoTestHarness extends Applet {

    /** Set by the constructor; accessed by CryptoTest via CryptoTestHarness.INSTANCE. */
    public static CryptoTestHarness INSTANCE;

    private final zk.esim.applet.Crypto crypto;

    public static void install(byte[] b, short o, byte l) {
        new CryptoTestHarness(b, o, l);
    }

    private CryptoTestHarness(byte[] b, short o, byte l) {
        crypto = new zk.esim.applet.Crypto();   // all JCRE allocations happen here
        register();
        INSTANCE = this;
    }

    /** Returns the Crypto instance for direct-call testing. */
    public zk.esim.applet.Crypto getCrypto() {
        return crypto;
    }

    /**
     * Initialise mnoPk and leakPk to a valid P-256 point (the device public key)
     * so that generateZkp() can run.  These fields are private in Crypto and are
     * normally set by the applet during the SGP.22 protocol; for unit testing we
     * inject a dummy value via reflection.
     */
    public void initZkpKeys() {
        try {
            byte[] pk = new byte[65];
            crypto.exportPublicKey(pk, (short) 0);

            java.lang.reflect.Field mnoPkField =
                    zk.esim.applet.Crypto.class.getDeclaredField("mnoPk");
            mnoPkField.setAccessible(true);
            ECPublicKey mnoPk = (ECPublicKey) mnoPkField.get(crypto);
            mnoPk.setW(pk, (short) 0, (short) 65);

            java.lang.reflect.Field leakPkField =
                    zk.esim.applet.Crypto.class.getDeclaredField("leakPk");
            leakPkField.setAccessible(true);
            ECPublicKey leakPk = (ECPublicKey) leakPkField.get(crypto);
            leakPk.setW(pk, (short) 0, (short) 65);
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize ZKP keys via reflection", e);
        }
    }

    /**
     * Verify an ECDSA-SHA-256 signature without going through APDU parsing.
     * Replicates the cryptographic core of Crypto.verifySignature() — build an
     * ECPublicKey with P-256 parameters, init the Signature in VERIFY mode, and
     * call verify().
     */
    public boolean verifyEcdsaSha256(byte[] pk, short pkLen,
                                     byte[] msg, short msgLen,
                                     byte[] sig, short sigLen) {
        ECPublicKey verifyKey = (ECPublicKey) KeyBuilder.buildKey(
                KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);
        setP256Params(verifyKey);
        verifyKey.setW(pk, (short) 0, pkLen);

        Signature sig256 = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        sig256.init(verifyKey, Signature.MODE_VERIFY);
        return sig256.verify(msg, (short) 0, msgLen, sig, (short) 0, sigLen);
    }

    /**
     * Build a JavaCard ECPublicKey configured for secp256r1 from an uncompressed
     * point W.  Used by testDeriveSessionKeyMatchesJavaEcdh to wrap the Java-SE
     * peer's public key into a JavaCard object.
     */
    public ECPublicKey buildP256PublicKey(byte[] w, short wLen) {
        ECPublicKey key = (ECPublicKey) KeyBuilder.buildKey(
                KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);
        setP256Params(key);
        key.setW(w, (short) 0, wLen);
        return key;
    }

    /** Mirrors Crypto.setP256Params() using the same SecP256r1 constants. */
    private static void setP256Params(javacard.security.Key key) {
        ECKey ecKey = (ECKey) key;
        ecKey.setFieldFP(zk.esim.applet.jcmathlib.SecP256r1.p,
                (short) 0, (short) zk.esim.applet.jcmathlib.SecP256r1.p.length);
        ecKey.setA(zk.esim.applet.jcmathlib.SecP256r1.a,
                (short) 0, (short) zk.esim.applet.jcmathlib.SecP256r1.a.length);
        ecKey.setB(zk.esim.applet.jcmathlib.SecP256r1.b,
                (short) 0, (short) zk.esim.applet.jcmathlib.SecP256r1.b.length);
        ecKey.setG(zk.esim.applet.jcmathlib.SecP256r1.G,
                (short) 0, (short) zk.esim.applet.jcmathlib.SecP256r1.G.length);
        ecKey.setR(zk.esim.applet.jcmathlib.SecP256r1.r,
                (short) 0, (short) zk.esim.applet.jcmathlib.SecP256r1.r.length);
        ecKey.setK(zk.esim.applet.jcmathlib.SecP256r1.k);
    }

    @Override
    public void process(APDU apdu) { /* no-op: tests never call this */ }
}
