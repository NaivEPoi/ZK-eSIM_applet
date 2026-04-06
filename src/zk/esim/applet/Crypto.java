//package zk.esim.applet;
//
//import javax.smartcardio.CommandAPDU;
//import java.security.MessageDigest;
//import java.security.SecureRandom;
//
//import javacard.security.RandomData;
//import javacard.security.Signature;
//import zk.esim.applet.jcmathlib.*;
//
//public class Crypto {
//
//    // JCMathLib objects
//    private ResourceManager   rm;
//    private ECCurve           curve;
//    private ECPoint           G;          // generator
//    private ECPoint           H;          // independent Pedersen generator
//    private ECPoint           tmpPoint1;  // scratch
//    private ECPoint           tmpPoint2;  // scratch
//    private BigNat            tmpScalar;  // scratch
//
//    // Secrets — never leave card
//    private BigNat   sk_b;
//    private BigNat   r_b;
//    private BigNat   r_blind;
//    private BigNat   alpha;
//    private BigNat   m_EID;
//
//    // Shared state between the two APDU calls
//    private byte[]   pk_MNO;
//    private byte[]   sigma_EID;
//
//    private final MessageDigest sha256;
//    private final RandomData rng;
//    private final Signature ecdsaVerify;
//
//    private static final short SCALAR_LEN = 32;
//    private static final short POINT_LEN  = 65;
//
//    public static CommandAPDU genRandom(int lambda) {
//        SecureRandom random = new SecureRandom();
//        byte[] r = new byte[lambda /8];
//        random.nextBytes(r);
//
//        return new CommandAPDU(0x00, 0x84, 0x00, 0x00, r);
//    }
//
//    public static CommandAPDU createMeid(CommandAPDU apdu) {
//
//    }
//}
