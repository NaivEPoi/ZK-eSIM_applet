import org.junit.Test;
import javacard.framework.ISOException;
import zk.esim.applet.Asn1;

import java.io.ByteArrayOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class Asn1Test {

    private static byte[] fromHex(String hex) {
        int len = hex.length();
        if ((len & 1) != 0) {
            throw new IllegalArgumentException("Hex string must have even length");
        }

        byte[] out = new byte[len / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(hex.charAt(i * 2), 16);
            int lo = Character.digit(hex.charAt(i * 2 + 1), 16);
            if (hi < 0 || lo < 0) {
                throw new IllegalArgumentException("Invalid hex input");
            }
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    private static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            out.write(part, 0, part.length);
        }
        return out.toByteArray();
    }

    private static byte[] wrapTlv(int tag, byte[] value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        if ((tag & 0xFF00) != 0) {
            out.write((tag >> 8) & 0xFF);
        }
        out.write(tag & 0xFF);
        appendLength(out, value.length);
        out.write(value, 0, value.length);
        return out.toByteArray();
    }

    private static void appendLength(ByteArrayOutputStream out, int len) {
        if (len < 0x80) {
            out.write(len);
        } else if (len < 0x100) {
            out.write(0x81);
            out.write(len);
        } else {
            out.write(0x82);
            out.write((len >> 8) & 0xFF);
            out.write(len & 0xFF);
        }
    }

    private static byte[] loadDpAuthCertDer() {
        try {
            return Files.readAllBytes(Paths.get("..", "pysim", "smdpp-data", "certs", "DPauth",
                    "CERT_S_SM_DPauth_ECDSA_NIST.der"));
        } catch (Exception e) {
            throw new RuntimeException("Unable to load DPauth certificate", e);
        }
    }

    @Test
    public void testDecodeBoundProfilePackageCapturesOffsets() {
        Asn1 asn1 = new Asn1();
        Asn1.DecodedMessage dm = new Asn1.DecodedMessage();

        byte[] txId = fromHex("01020304");
        byte[] hostId = fromHex("A1B2C3D4");
        byte[] smdpOtpk = new byte[65];
        smdpOtpk[0] = 0x04;
        for (int i = 1; i < smdpOtpk.length; i++) {
            smdpOtpk[i] = (byte) (0x20 + i);
        }
        byte[] smdpSign = fromHex("11223344556677889900AABBCCDDEEFF");
        byte[] crt = wrapTlv(0xA6, concat(fromHex("800188810110"), wrapTlv(0x84, hostId)));
        byte[] expectedSignedSpan = concat(
                fromHex("820101"),
                wrapTlv(0x80, txId),
                crt,
                wrapTlv(0x5F49, smdpOtpk)
        );

        byte[] bf23 = wrapTlv(0xBF23, concat(
                fromHex("820101"),
                wrapTlv(0x80, txId),
                crt,
                wrapTlv(0x5F49, smdpOtpk),
                wrapTlv(0x5F37, smdpSign)
        ));
        byte[] a0 = wrapTlv(0xA0, concat(wrapTlv(0x87, fromHex("01020304")), wrapTlv(0x87, fromHex("05060708"))));
        byte[] a1 = wrapTlv(0xA1, wrapTlv(0x88, fromHex("11121314")));
        byte[] a2 = wrapTlv(0xA2, wrapTlv(0x87, fromHex("21222324")));
        byte[] a3 = wrapTlv(0xA3, wrapTlv(0x86, fromHex("31323334")));
        byte[] bpp = wrapTlv(0xBF36, concat(bf23, a0, a1, a2, a3));

        asn1.decode(bpp, (short) bpp.length, dm);

        assertEquals(Asn1.TYPE_BOUND_PROFILE_PACKAGE, dm.type);
        assertArrayEquals(txId, slice(dm.txId, dm.txIdLen, 0));
        assertArrayEquals(smdpOtpk, slice(bpp, dm.bf23SmdpOtpkLen, dm.bf23SmdpOtpkOff));
        assertArrayEquals(smdpSign, slice(bpp, dm.bf23SmdpSignLen, dm.bf23SmdpSignOff));
        assertArrayEquals(hostId, slice(bpp, dm.hostIdLen, dm.hostIdOff));
        assertArrayEquals(expectedSignedSpan, slice(bpp, (short) (dm.bf23SignedEnd - dm.bf23SignedStart), dm.bf23SignedStart));
        assertArrayEquals(crt, slice(bpp, dm.bf23CrtLen, dm.bf23CrtOff));
        assertArrayEquals(a0, slice(bpp, dm.a0Len, dm.a0Off));
        assertArrayEquals(a1, slice(bpp, dm.a1Len, dm.a1Off));
        assertArrayEquals(a2, slice(bpp, dm.a2Len, dm.a2Off));
        assertArrayEquals(a3, slice(bpp, dm.a3Len, dm.a3Off));
    }

    @Test
    public void testDecodeBoundProfilePackageLeavesA2UnsetWhenAbsent() {
        Asn1 asn1 = new Asn1();
        Asn1.DecodedMessage dm = new Asn1.DecodedMessage();
        byte[] hostId = fromHex("CAFEBABE");

        byte[] bpp = wrapTlv(0xBF36, concat(
                wrapTlv(0xBF23, concat(
                        fromHex("820101"),
                        fromHex("800401020304"),
                        wrapTlv(0xA6, concat(fromHex("800188810110"), wrapTlv(0x84, hostId))),
                        wrapTlv(0x5F49, concat(new byte[]{0x04}, new byte[64])),
                        wrapTlv(0x5F37, fromHex("0102030405060708"))
                )),
                fromHex("A00487020102"),
                fromHex("A10488020304"),
                fromHex("A30486020506")
        ));

        asn1.decode(bpp, (short) bpp.length, dm);

        assertEquals(0, dm.a2Off);
        assertEquals(0, dm.a2Len);
        assertArrayEquals(hostId, slice(bpp, dm.hostIdLen, dm.hostIdOff));
    }

    @Test(expected = ISOException.class)
    public void testDecodeBoundProfilePackageRejectsIncompleteControlRefTemplate() {
        Asn1 asn1 = new Asn1();
        Asn1.DecodedMessage dm = new Asn1.DecodedMessage();

        byte[] bpp = wrapTlv(0xBF36, concat(
                wrapTlv(0xBF23, concat(
                        fromHex("820101"),
                        fromHex("800401020304"),
                        fromHex("A603800188"),
                        wrapTlv(0x5F49, concat(new byte[]{0x04}, new byte[64])),
                        wrapTlv(0x5F37, fromHex("0102030405060708"))
                )),
                fromHex("A00487020102"),
                fromHex("A10488020304"),
                fromHex("A30486020506")
        ));

        asn1.decode(bpp, (short) bpp.length, dm);
    }

    @Test
    public void testDecodeAuthenticateServerAcceptsMinimalCtxParams1() {
        Asn1 asn1 = new Asn1();
        Asn1.DecodedMessage dm = new Asn1.DecodedMessage();

        byte[] bf38 = wrapTlv(0xBF38, concat(
                wrapTlv(0x30, concat(
                        wrapTlv(0x80, fromHex("01020304")),
                        wrapTlv(0x81, fromHex("00112233445566778899AABBCCDDEEFF")),
                        wrapTlv(0x83, fromHex("736D64702E636F6D")),
                        wrapTlv(0x84, fromHex("102132435465768798A9BACBDCEDFE0F"))
                )),
                wrapTlv(0x5F37, new byte[64]),
                wrapTlv(0x04, fromHex("AABBCCDD")),
                wrapTlv(0x30, new byte[0]),
                fromHex("A00AA108800401020304A100")
        ));

        asn1.decode(bf38, (short) bf38.length, dm);

        assertEquals(Asn1.TYPE_AUTHENTICATE_SERVER_REQUEST, dm.type);
        assertArrayEquals(fromHex("01020304"), slice(dm.txId, dm.txIdLen, 0));
        assertArrayEquals(fromHex("736D64702E636F6D"), slice(dm.serverAddress, dm.serverAddressLen, 0));
    }

    @Test
    public void testDecodeAuthenticateServerAcceptsRealCertificate() {
        Asn1 asn1 = new Asn1();
        Asn1.DecodedMessage dm = new Asn1.DecodedMessage();
        byte[] cert = loadDpAuthCertDer();

        byte[] bf38 = wrapTlv(0xBF38, concat(
                wrapTlv(0x30, concat(
                        wrapTlv(0x80, fromHex("01020304")),
                        wrapTlv(0x81, fromHex("00112233445566778899AABBCCDDEEFF")),
                        wrapTlv(0x83, fromHex("736D64702E636F6D")),
                        wrapTlv(0x84, fromHex("102132435465768798A9BACBDCEDFE0F"))
                )),
                wrapTlv(0x5F37, new byte[64]),
                wrapTlv(0x04, fromHex("AABBCCDD")),
                cert,
                fromHex("A00AA108800401020304A100")
        ));

        asn1.decode(bf38, (short) bf38.length, dm);

        assertEquals(Asn1.TYPE_AUTHENTICATE_SERVER_REQUEST, dm.type);
        assertEquals((short) cert.length, dm.smdpCertificateLen);
        assertArrayEquals(cert, slice(dm.smdpCertificate, dm.smdpCertificateLen, 0));
    }

    @Test(expected = ISOException.class)
    public void testDecodeAuthenticateServerRejectsEmptyCtxParams1() {
        Asn1 asn1 = new Asn1();
        Asn1.DecodedMessage dm = new Asn1.DecodedMessage();

        byte[] bf38 = wrapTlv(0xBF38, concat(
                wrapTlv(0x30, concat(
                        wrapTlv(0x80, fromHex("01020304")),
                        wrapTlv(0x81, fromHex("00112233445566778899AABBCCDDEEFF")),
                        wrapTlv(0x83, fromHex("736D64702E636F6D")),
                        wrapTlv(0x84, fromHex("102132435465768798A9BACBDCEDFE0F"))
                )),
                wrapTlv(0x5F37, new byte[64]),
                wrapTlv(0x04, fromHex("AABBCCDD")),
                wrapTlv(0x30, new byte[0]),
                fromHex("A000")
        ));

        asn1.decode(bf38, (short) bf38.length, dm);
    }

    private static byte[] slice(byte[] data, short len, int off) {
        byte[] out = new byte[len];
        System.arraycopy(data, off, out, 0, len);
        return out;
    }
}
