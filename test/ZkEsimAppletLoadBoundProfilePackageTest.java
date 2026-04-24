import com.licel.jcardsim.base.Simulator;
import javacard.framework.AID;
import org.junit.Test;
import zk.esim.applet.ZkEsimApplet;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * jCardSim integration tests for LoadBoundProfilePackage (ES10b, BF36).
 *
 * These tests now exercise the real Phase 4 path:
 * - BF21 establishes the session and returns the applet-generated euiccOtpk.
 * - BF23 smdpSign is generated over the exact signed bytes the applet verifies.
 * - A0/A1/A2/A3 protected segments carry valid AES-CMAC chains derived from the
 *   ECDH shared secret and the CRT hostId, matching pySim.esim.bsp semantics.
 */
public class ZkEsimAppletLoadBoundProfilePackageTest {

    private static final byte[] APPLET_AID = fromHex("D07002CA44900101");
    private static final byte[] HOST_ID = fromHex("A1B2C3D4");
    private static final byte[] EID_VALUE = fromHex("89049032000000000000123456789012");
    private static final byte[] TEST_PRIVATE_KEY_DER = fromHex(
            "308187020100301306072A8648CE3D020106082A8648CE3D030107046D306B0201010420DCD694B778957E8E9ADDBDD94433E9EF8F73D11E491C48D425A38A9491BD3BEDA14403420004104C2AE3D02DEF9C979261A7C6710076B970721D0955A2644AE05FAE4BC2314E5DC09F6BF0118026165342E212318775E365F3B57325373066B9906E0BD1388D"
    );
    private static final byte[] TEST_SMDP_CERT_DER = fromHex(
            "30820239308201DFA00302010202020101300A06082A8648CE3D04030230443110300E06035504030C07546573742043493111300F060355040B0C0854455354434552543110300E060355040A0C0752535054455354310B3009060355040613024954301E170D3230303430313038333434355A170D3330303333303038333434355A3025310D300B060355040A0C0441434D453114301206035504030C0B5445535420534D2D44502B3059301306072A8648CE3D020106082A8648CE3D03010703420004104C2AE3D02DEF9C979261A7C6710076B970721D0955A2644AE05FAE4BC2314E5DC09F6BF0118026165342E212318775E365F3B57325373066B9906E0BD1388DA381DF3081DC301F0603551D23041830168014F54172BDF98A95D65CBEB88A38A1C11D800A85C3301D0603551D0E04160414E6EAF71EE0FB9430ECCD1EBB421F881437C13263300E0603551D1104073005880388370A300E0603551D0F0101FF04040302078030170603551D200101FF040D300B300906076781120102010530610603551D1F045A3058302AA028A0268624687474703A2F2F63692E746573742E6578616D706C652E636F6D2F43524C2D412E63726C302AA028A0268624687474703A2F2F63692E746573742E6578616D706C652E636F6D2F43524C2D422E63726C300A06082A8648CE3D040302034800304502203EA51B0129FC11E843C38C8CB104244CCF92D8DDBCD4D5F9DAFD0AEF700A9B1C022100FEF382FF71FEFC58168A3607D5685DB7CB48F6B434261891496385BCD6B5857A"
    );

    private static final class ApduResult {
        final byte[] response;
        final byte[] data;
        final int sw;

        ApduResult(byte[] response) {
            this.response = response;
            this.data = new byte[response.length - 2];
            System.arraycopy(response, 0, this.data, 0, this.data.length);
            this.sw = ((response[response.length - 2] & 0xFF) << 8) | (response[response.length - 1] & 0xFF);
        }
    }

    private static final class BspMaterial {
        final byte[] initialMcv;
        final byte[] sEnc;
        final byte[] sMac;

        BspMaterial(byte[] initialMcv, byte[] sEnc, byte[] sMac) {
            this.initialMcv = initialMcv;
            this.sEnc = sEnc;
            this.sMac = sMac;
        }
    }

    private static final class BspState {
        final byte[] sEnc;
        final byte[] sMac;
        final byte[] mcv;
        int blockNr;

        BspState(BspMaterial material) {
            this.sEnc = material.sEnc;
            this.sMac = material.sMac;
            this.mcv = Arrays.copyOf(material.initialMcv, material.initialMcv.length);
            this.blockNr = 1;
        }
    }

    private static final class TlvRef {
        final int tag;
        final int offset;
        final int headerLen;
        final int valueOff;
        final int valueLen;
        final int totalLen;

        TlvRef(int tag, int offset, int headerLen, int valueLen) {
            this.tag = tag;
            this.offset = offset;
            this.headerLen = headerLen;
            this.valueOff = offset + headerLen;
            this.valueLen = valueLen;
            this.totalLen = headerLen + valueLen;
        }
    }

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

    private static ApduResult transmit(Simulator sim, byte[] command) {
        byte[] responseBytes;
        if (isExtendedStoreData(command)) {
            responseBytes = transmitExtendedStoreData(sim, command);
        } else {
            responseBytes = sim.transmitCommand(command);
        }
        return collectResult(sim, responseBytes, command);
    }

    private static boolean isExtendedStoreData(byte[] command) {
        return command.length >= 7
                && command[1] == (byte) 0xE2
                && command[4] == 0x00;
    }

    private static ApduResult collectResult(Simulator sim, byte[] responseBytes, byte[] loggedCommand) {
        ByteArrayOutputStream allData = new ByteArrayOutputStream();
        assertTrue("Response APDU must include SW1SW2", responseBytes.length >= 2);
        int sw = ((responseBytes[responseBytes.length - 2] & 0xFF) << 8)
                | (responseBytes[responseBytes.length - 1] & 0xFF);
        allData.write(responseBytes, 0, responseBytes.length - 2);

        while ((sw & 0xFF00) == 0x9100) {
            byte[] getResp = new byte[]{0x00, (byte) 0xC0, 0x00, 0x00, 0x00};
            responseBytes = sim.transmitCommand(getResp);
            assertTrue("GET RESPONSE APDU must include SW1SW2", responseBytes.length >= 2);
            sw = ((responseBytes[responseBytes.length - 2] & 0xFF) << 8)
                    | (responseBytes[responseBytes.length - 1] & 0xFF);
            allData.write(responseBytes, 0, responseBytes.length - 2);
        }

        byte[] fullResponse = new byte[allData.size() + 2];
        byte[] data = allData.toByteArray();
        System.arraycopy(data, 0, fullResponse, 0, data.length);
        fullResponse[fullResponse.length - 2] = (byte) ((sw >> 8) & 0xFF);
        fullResponse[fullResponse.length - 1] = (byte) (sw & 0xFF);

        String testName = currentTestName();
        System.out.println("[" + testName + "] APDU TX: " + toHex(loggedCommand));
        System.out.println("[" + testName + "] APDU RX: " + toHex(fullResponse) + " SW=" + String.format("%04X", sw));
        return new ApduResult(fullResponse);
    }

    private static ApduResult transmitStoreDataChained(Simulator sim, byte[] payload) {
        int blockNo = 0;
        int pos = 0;
        byte[] response = null;
        final int maxChunk = 240;

        while (pos < payload.length) {
            int remaining = payload.length - pos;
            int chunkLen = Math.min(maxChunk, remaining);
            boolean last = (pos + chunkLen) == payload.length;

            byte[] chunkApdu = new byte[5 + chunkLen];
            chunkApdu[0] = (byte) 0x80;
            chunkApdu[1] = (byte) 0xE2;
            chunkApdu[2] = last ? (byte) 0x91 : (byte) 0x11;
            chunkApdu[3] = (byte) (blockNo & 0xFF);
            chunkApdu[4] = (byte) (chunkLen & 0xFF);
            System.arraycopy(payload, pos, chunkApdu, 5, chunkLen);

            response = sim.transmitCommand(chunkApdu);
            int sw = ((response[response.length - 2] & 0xFF) << 8)
                    | (response[response.length - 1] & 0xFF);
            pos += chunkLen;
            if (!last && sw != 0x9000) {
                return collectResult(sim, response, payload);
            }
            blockNo++;
        }

        if (response == null) {
            throw new IllegalStateException("No APDU blocks transmitted");
        }

        return collectResult(sim, response, payload);
    }

    private static byte[] transmitExtendedStoreData(Simulator sim, byte[] command) {
        int dataLen = ((command[5] & 0xFF) << 8) | (command[6] & 0xFF);
        int dataOff = 7;
        if (dataOff + dataLen > command.length) {
            throw new IllegalArgumentException("Malformed extended STORE DATA APDU");
        }

        int blockNo = 0;
        int pos = dataOff;
        byte[] response = null;
        final int maxChunk = 240;

        while (pos < dataOff + dataLen) {
            int remaining = (dataOff + dataLen) - pos;
            int chunkLen = Math.min(maxChunk, remaining);
            boolean last = (pos + chunkLen) == (dataOff + dataLen);

            byte[] chunkApdu = new byte[5 + chunkLen];
            chunkApdu[0] = command[0];
            chunkApdu[1] = command[1];
            chunkApdu[2] = last ? (byte) 0x91 : (byte) 0x11;
            chunkApdu[3] = (byte) (blockNo & 0xFF);
            chunkApdu[4] = (byte) (chunkLen & 0xFF);
            System.arraycopy(command, pos, chunkApdu, 5, chunkLen);

            response = sim.transmitCommand(chunkApdu);
            int sw = ((response[response.length - 2] & 0xFF) << 8)
                    | (response[response.length - 1] & 0xFF);
            pos += chunkLen;
            if (!last && sw != 0x9000) {
                return response;
            }
            blockNo++;
        }

        if (response == null) {
            throw new IllegalStateException("No APDU blocks transmitted");
        }
        return response;
    }

    private static String currentTestName() {
        StackTraceElement[] stack = Thread.currentThread().getStackTrace();
        for (StackTraceElement element : stack) {
            if (element.getMethodName().startsWith("test")) {
                return element.getMethodName();
            }
        }
        return "unknown-test";
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    private static Simulator createAndSelect() {
        Simulator sim = new Simulator();
        AID aid = new AID(APPLET_AID, (short) 0, (byte) APPLET_AID.length);
        sim.installApplet(aid, ZkEsimApplet.class);
        assertTrue("Applet must be selectable", sim.selectApplet(aid));
        return sim;
    }

    private static byte[] buildStoreDataApdu(byte[] data) {
        if (data.length <= 255) {
            byte[] apdu = new byte[5 + data.length];
            apdu[0] = (byte) 0x80;
            apdu[1] = (byte) 0xE2;
            apdu[2] = (byte) 0x91;
            apdu[3] = 0x00;
            apdu[4] = (byte) data.length;
            System.arraycopy(data, 0, apdu, 5, data.length);
            return apdu;
        }

        byte[] apdu = new byte[7 + data.length];
        apdu[0] = (byte) 0x80;
        apdu[1] = (byte) 0xE2;
        apdu[2] = (byte) 0x91;
        apdu[3] = 0x00;
        apdu[4] = 0x00;
        apdu[5] = (byte) ((data.length >> 8) & 0xFF);
        apdu[6] = (byte) (data.length & 0xFF);
        System.arraycopy(data, 0, apdu, 7, data.length);
        return apdu;
    }

    private static byte[] buildGetPersistedBppInfoApdu() {
        return new byte[]{(byte) 0x80, (byte) 0xCA, (byte) 0xDF, 0x36, 0x00};
    }

    private static byte[] sign(byte[] data) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(TEST_PRIVATE_KEY_DER));
            Signature signer = Signature.getInstance("SHA256withECDSA");
            signer.initSign(privateKey);
            signer.update(data);
            return derEcdsaToRaw(signer.sign());
        } catch (Exception e) {
            throw new RuntimeException("Unable to sign test payload", e);
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

    private static byte[] derEcdsaToRaw(byte[] derSig) {
        if (derSig.length < 8 || derSig[0] != 0x30) {
            throw new IllegalArgumentException("Expected DER ECDSA signature");
        }

        int offset = 1;
        int seqLen = derSig[offset] & 0xFF;
        offset++;
        if ((seqLen & 0x80) != 0) {
            int lenBytes = seqLen & 0x7F;
            if (lenBytes != 1 || offset >= derSig.length) {
                throw new IllegalArgumentException("Unsupported DER ECDSA length");
            }
            seqLen = derSig[offset] & 0xFF;
            offset++;
        }

        if (derSig[offset++] != 0x02) {
            throw new IllegalArgumentException("Expected DER INTEGER for r");
        }
        int rLen = derSig[offset++] & 0xFF;
        int rStart = offset;
        offset += rLen;

        if (derSig[offset++] != 0x02) {
            throw new IllegalArgumentException("Expected DER INTEGER for s");
        }
        int sLen = derSig[offset++] & 0xFF;
        int sStart = offset;

        byte[] raw = new byte[64];
        copyDerIntegerToRaw(derSig, rStart, rLen, raw, 0);
        copyDerIntegerToRaw(derSig, sStart, sLen, raw, 32);
        return raw;
    }

    private static void copyDerIntegerToRaw(byte[] derSig, int derOff, int derLen, byte[] rawOut, int rawOff) {
        int src = derOff;
        int srcEnd = derOff + derLen;
        while (src < srcEnd && derSig[src] == 0x00) {
            src++;
        }
        int outLen = srcEnd - src;
        if (outLen > 32) {
            throw new IllegalArgumentException("DER integer too large for raw P-256 signature");
        }
        int pad = 32 - outLen;
        for (int i = 0; i < pad; i++) {
            rawOut[rawOff + i] = 0x00;
        }
        System.arraycopy(derSig, src, rawOut, rawOff + pad, outLen);
    }

    private static int derLenFieldSize(int valueLen) {
        if (valueLen < 128) {
            return 1;
        }
        return valueLen < 256 ? 2 : 3;
    }

    private static int writeDerLength(byte[] out, int off, int valueLen) {
        if (valueLen < 128) {
            out[off++] = (byte) valueLen;
            return off;
        }
        if (valueLen < 256) {
            out[off++] = (byte) 0x81;
            out[off++] = (byte) valueLen;
            return off;
        }
        out[off++] = (byte) 0x82;
        out[off++] = (byte) ((valueLen >> 8) & 0xFF);
        out[off++] = (byte) (valueLen & 0xFF);
        return off;
    }

    private static int readDerLength(byte[] data, int lenOff) {
        int first = data[lenOff] & 0xFF;
        if ((first & 0x80) == 0) {
            return first;
        }
        int bytes = first & 0x7F;
        int len = 0;
        for (int i = 0; i < bytes; i++) {
            len = (len << 8) | (data[lenOff + 1 + i] & 0xFF);
        }
        return len;
    }

    private static int derParseLenFieldSize(int firstLenByte) {
        if ((firstLenByte & 0x80) == 0) {
            return 1;
        }
        return 1 + (firstLenByte & 0x7F);
    }

    private static byte[] buildSmdpSignature2Input(byte[] smdpSigned2) {
        byte[] out = new byte[smdpSigned2.length + 3];
        int p = 0;
        System.arraycopy(smdpSigned2, 0, out, p, smdpSigned2.length);
        p += smdpSigned2.length;
        out[p++] = 0x5F;
        out[p++] = 0x37;
        out[p] = 0x00;
        return out;
    }

    private static byte[] buildPrepareDownloadApdu(byte[] txId) {
        int smdpSigned2Body = 2 + txId.length + 3;
        byte[] smdpSigned2 = new byte[2 + smdpSigned2Body];
        int p = 0;
        smdpSigned2[p++] = 0x30;
        smdpSigned2[p++] = (byte) smdpSigned2Body;
        smdpSigned2[p++] = (byte) 0x80;
        smdpSigned2[p++] = (byte) txId.length;
        System.arraycopy(txId, 0, smdpSigned2, p, txId.length);
        p += txId.length;
        smdpSigned2[p++] = 0x01;
        smdpSigned2[p++] = 0x01;
        smdpSigned2[p++] = 0x00;

        byte[] smdpSig = sign(buildSmdpSignature2Input(smdpSigned2));
        byte[] sigTlv = wrapTlv(0x5F37, smdpSig);
        int innerLen = smdpSigned2.length + sigTlv.length + TEST_SMDP_CERT_DER.length;
        int bf21LenField = derLenFieldSize(innerLen);
        byte[] bf21 = new byte[2 + bf21LenField + innerLen];
        int q = 0;
        bf21[q++] = (byte) 0xBF;
        bf21[q++] = 0x21;
        q = writeDerLength(bf21, q, innerLen);
        System.arraycopy(smdpSigned2, 0, bf21, q, smdpSigned2.length);
        q += smdpSigned2.length;
        System.arraycopy(sigTlv, 0, bf21, q, sigTlv.length);
        q += sigTlv.length;
        System.arraycopy(TEST_SMDP_CERT_DER, 0, bf21, q, TEST_SMDP_CERT_DER.length);
        return buildStoreDataApdu(bf21);
    }

    private static TlvRef parseTlv(byte[] data, int off, int end) {
        if (off >= end) {
            throw new IllegalArgumentException("TLV offset out of bounds");
        }

        int pos = off;
        int first = data[pos++] & 0xFF;
        int tag = first;
        if ((first & 0x1F) == 0x1F) {
            if (pos >= end) {
                throw new IllegalArgumentException("Incomplete multi-byte tag");
            }
            int second = data[pos++] & 0xFF;
            if ((second & 0x80) != 0) {
                throw new IllegalArgumentException("Unsupported high-tag-number form");
            }
            tag = (tag << 8) | second;
        }

        if (pos >= end) {
            throw new IllegalArgumentException("Missing TLV length");
        }

        int lenFirst = data[pos++] & 0xFF;
        int valueLen;
        if ((lenFirst & 0x80) == 0) {
            valueLen = lenFirst;
        } else {
            int lenBytes = lenFirst & 0x7F;
            if (lenBytes == 0 || lenBytes > 2 || pos + lenBytes > end) {
                throw new IllegalArgumentException("Unsupported TLV length");
            }
            valueLen = 0;
            for (int i = 0; i < lenBytes; i++) {
                valueLen = (valueLen << 8) | (data[pos++] & 0xFF);
            }
        }

        int headerLen = pos - off;
        if (pos + valueLen > end) {
            throw new IllegalArgumentException("Incomplete TLV value");
        }
        return new TlvRef(tag, off, headerLen, valueLen);
    }

    private static byte[] slice(byte[] data, int off, int len) {
        return Arrays.copyOfRange(data, off, off + len);
    }

    private static ApduResult transmitBppPiecewiseLpacStyle(Simulator sim, byte[] payload) {
        TlvRef bf36 = parseTlv(payload, 0, payload.length);
        if (bf36.tag != 0xBF36) {
            throw new IllegalArgumentException("Expected BF36 payload");
        }

        int pos = bf36.valueOff;
        int end = bf36.offset + bf36.totalLen;

        TlvRef bf23 = parseTlv(payload, pos, end);
        if (bf23.tag != 0xBF23) {
            throw new IllegalArgumentException("Expected BF23 inside BF36");
        }
        ApduResult res = transmit(sim, buildStoreDataApdu(slice(payload, 0, bf23.offset + bf23.totalLen)));
        if (res.sw != 0x9000 || res.data.length != 0) {
            return res;
        }
        pos = bf23.offset + bf23.totalLen;

        TlvRef a0 = parseTlv(payload, pos, end);
        if (a0.tag != 0xA0) {
            throw new IllegalArgumentException("Expected A0 after BF23");
        }
        res = transmit(sim, buildStoreDataApdu(slice(payload, a0.offset, a0.totalLen)));
        if (res.sw != 0x9000 || res.data.length != 0) {
            return res;
        }
        pos = a0.offset + a0.totalLen;

        TlvRef a1 = parseTlv(payload, pos, end);
        if (a1.tag != 0xA1) {
            throw new IllegalArgumentException("Expected A1 after A0");
        }
        res = transmit(sim, buildStoreDataApdu(slice(payload, a1.offset, a1.headerLen)));
        if (res.sw != 0x9000 || res.data.length != 0) {
            return res;
        }
        int childPos = a1.valueOff;
        int childEnd = a1.offset + a1.totalLen;
        while (childPos < childEnd) {
            TlvRef child = parseTlv(payload, childPos, childEnd);
            res = transmit(sim, buildStoreDataApdu(slice(payload, child.offset, child.totalLen)));
            if (res.sw != 0x9000 || res.data.length != 0) {
                return res;
            }
            childPos += child.totalLen;
        }
        pos = a1.offset + a1.totalLen;

        TlvRef maybeA2OrA3 = parseTlv(payload, pos, end);
        if (maybeA2OrA3.tag == 0xA2) {
            res = transmit(sim, buildStoreDataApdu(slice(payload, maybeA2OrA3.offset, maybeA2OrA3.totalLen)));
            if (res.sw != 0x9000 || res.data.length != 0) {
                return res;
            }
            pos = maybeA2OrA3.offset + maybeA2OrA3.totalLen;
            maybeA2OrA3 = parseTlv(payload, pos, end);
        }

        if (maybeA2OrA3.tag != 0xA3) {
            throw new IllegalArgumentException("Expected A3 before final protected elements");
        }
        res = transmit(sim, buildStoreDataApdu(slice(payload, maybeA2OrA3.offset, maybeA2OrA3.headerLen)));
        if (res.sw != 0x9000 || res.data.length != 0) {
            return res;
        }
        childPos = maybeA2OrA3.valueOff;
        childEnd = maybeA2OrA3.offset + maybeA2OrA3.totalLen;
        while (childPos < childEnd) {
            TlvRef child = parseTlv(payload, childPos, childEnd);
            res = transmit(sim, buildStoreDataApdu(slice(payload, child.offset, child.totalLen)));
            childPos += child.totalLen;
        }
        return res;
    }

    private static ApduResult transmitConstructedSequenceSgp22Style(Simulator sim, byte[] payload,
                                                                    TlvRef sequence, int expectedChildTag) {
        int childPos = sequence.valueOff;
        int childEnd = sequence.offset + sequence.totalLen;
        TlvRef firstChild = parseTlv(payload, childPos, childEnd);
        if (firstChild.tag != expectedChildTag) {
            throw new IllegalArgumentException("Unexpected first child tag in constructed sequence");
        }

        ApduResult res = transmit(sim, buildStoreDataApdu(
                slice(payload, sequence.offset, sequence.headerLen + firstChild.totalLen)));
        if (res.sw != 0x9000 || res.data.length != 0) {
            return res;
        }

        childPos += firstChild.totalLen;
        while (childPos < childEnd) {
            TlvRef child = parseTlv(payload, childPos, childEnd);
            if (child.tag != expectedChildTag) {
                throw new IllegalArgumentException("Unexpected child tag in constructed sequence");
            }
            res = transmit(sim, buildStoreDataApdu(slice(payload, child.offset, child.totalLen)));
            if (res.sw != 0x9000 || res.data.length != 0) {
                return res;
            }
            childPos += child.totalLen;
        }
        return res;
    }

    private static ApduResult transmitBppPiecewiseSgp22Style(Simulator sim, byte[] payload) {
        TlvRef bf36 = parseTlv(payload, 0, payload.length);
        if (bf36.tag != 0xBF36) {
            throw new IllegalArgumentException("Expected BF36 payload");
        }

        int pos = bf36.valueOff;
        int end = bf36.offset + bf36.totalLen;

        TlvRef bf23 = parseTlv(payload, pos, end);
        if (bf23.tag != 0xBF23) {
            throw new IllegalArgumentException("Expected BF23 inside BF36");
        }
        ApduResult res = transmit(sim, buildStoreDataApdu(slice(payload, 0, bf23.offset + bf23.totalLen)));
        if (res.sw != 0x9000 || res.data.length != 0) {
            return res;
        }
        pos = bf23.offset + bf23.totalLen;

        TlvRef a0 = parseTlv(payload, pos, end);
        if (a0.tag != 0xA0) {
            throw new IllegalArgumentException("Expected A0 after BF23");
        }
        res = transmitConstructedSequenceSgp22Style(sim, payload, a0, 0x87);
        if (res.sw != 0x9000 || res.data.length != 0) {
            return res;
        }
        pos = a0.offset + a0.totalLen;

        TlvRef a1 = parseTlv(payload, pos, end);
        if (a1.tag != 0xA1) {
            throw new IllegalArgumentException("Expected A1 after A0");
        }
        res = transmit(sim, buildStoreDataApdu(slice(payload, a1.offset, a1.headerLen)));
        if (res.sw != 0x9000 || res.data.length != 0) {
            return res;
        }
        int childPos = a1.valueOff;
        int childEnd = a1.offset + a1.totalLen;
        while (childPos < childEnd) {
            TlvRef child = parseTlv(payload, childPos, childEnd);
            res = transmit(sim, buildStoreDataApdu(slice(payload, child.offset, child.totalLen)));
            if (res.sw != 0x9000 || res.data.length != 0) {
                return res;
            }
            childPos += child.totalLen;
        }
        pos = a1.offset + a1.totalLen;

        TlvRef maybeA2OrA3 = parseTlv(payload, pos, end);
        if (maybeA2OrA3.tag == 0xA2) {
            res = transmitConstructedSequenceSgp22Style(sim, payload, maybeA2OrA3, 0x87);
            if (res.sw != 0x9000 || res.data.length != 0) {
                return res;
            }
            pos = maybeA2OrA3.offset + maybeA2OrA3.totalLen;
            maybeA2OrA3 = parseTlv(payload, pos, end);
        }

        if (maybeA2OrA3.tag != 0xA3) {
            throw new IllegalArgumentException("Expected A3 before final protected elements");
        }
        res = transmit(sim, buildStoreDataApdu(slice(payload, maybeA2OrA3.offset, maybeA2OrA3.headerLen)));
        if (res.sw != 0x9000 || res.data.length != 0) {
            return res;
        }
        childPos = maybeA2OrA3.valueOff;
        childEnd = maybeA2OrA3.offset + maybeA2OrA3.totalLen;
        while (childPos < childEnd) {
            TlvRef child = parseTlv(payload, childPos, childEnd);
            res = transmit(sim, buildStoreDataApdu(slice(payload, child.offset, child.totalLen)));
            childPos += child.totalLen;
        }
        return res;
    }

    private static byte[] prepareDownloadAndGetEuiccOtpk(Simulator sim, byte[] txId) {
        ApduResult res = transmit(sim, buildPrepareDownloadApdu(txId));
        assertEquals("PrepareDownload must succeed before LoadBPP", 0x9000, res.sw);
        byte[] euiccOtpk = extractTaggedValue(res.data, (short) 0x5F49);
        assertNotNull("PrepareDownload response must return euiccOtpk", euiccOtpk);
        assertEquals("euiccOtpk must be 65-byte uncompressed point", 65, euiccOtpk.length);
        return euiccOtpk;
    }

    private static byte[] extractTaggedValue(byte[] data, short tag) {
        int i = 0;
        while (i < data.length) {
            int tagStart = i;
            int currentTag = data[i] & 0xFF;
            i++;
            if ((currentTag & 0x1F) == 0x1F) {
                if (i >= data.length) {
                    return null;
                }
                currentTag = (currentTag << 8) | (data[i] & 0xFF);
                i++;
            }
            if (i >= data.length) {
                return null;
            }

            int firstLen = data[i] & 0xFF;
            int len;
            int lenFieldSize;
            if ((firstLen & 0x80) == 0) {
                len = firstLen;
                lenFieldSize = 1;
            } else {
                int lenBytes = firstLen & 0x7F;
                lenFieldSize = 1 + lenBytes;
                if (i + lenBytes >= data.length) {
                    return null;
                }
                len = 0;
                for (int j = 0; j < lenBytes; j++) {
                    len = (len << 8) | (data[i + 1 + j] & 0xFF);
                }
            }

            int valueOff = i + lenFieldSize;
            if (valueOff + len > data.length) {
                return null;
            }

            if ((short) currentTag == tag) {
                byte[] out = new byte[len];
                System.arraycopy(data, valueOff, out, 0, len);
                return out;
            }

            if ((data[tagStart] & 0x20) != 0) {
                byte[] found = extractTaggedValue(Arrays.copyOfRange(data, valueOff, valueOff + len), tag);
                if (found != null) {
                    return found;
                }
            }

            i = valueOff + len;
        }
        return null;
    }

    private static byte[] wrapTlv(int tag, byte[] value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        appendTag(out, tag);
        appendLength(out, value.length);
        out.write(value, 0, value.length);
        return out.toByteArray();
    }

    private static void appendTag(ByteArrayOutputStream out, int tag) {
        if ((tag & 0xFF00) != 0) {
            out.write((tag >> 8) & 0xFF);
        }
        out.write(tag & 0xFF);
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

    private static byte[] encodeUncompressedPoint(ECPublicKey publicKey) {
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

    private static byte[] computeSharedSecret(KeyPair smdpOt, byte[] euiccOtpk) {
        try {
            AlgorithmParameters ap = AlgorithmParameters.getInstance("EC");
            ap.init(new ECGenParameterSpec("secp256r1"));
            ECParameterSpec params = ap.getParameterSpec(ECParameterSpec.class);
            BigInteger x = new BigInteger(1, Arrays.copyOfRange(euiccOtpk, 1, 33));
            BigInteger y = new BigInteger(1, Arrays.copyOfRange(euiccOtpk, 33, 65));
            java.security.PublicKey euiccOtpkJse = KeyFactory.getInstance("EC")
                    .generatePublic(new ECPublicKeySpec(new java.security.spec.ECPoint(x, y), params));

            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(smdpOt.getPrivate());
            ka.doPhase(euiccOtpkJse, true);
            return ka.generateSecret();
        } catch (Exception e) {
            throw new RuntimeException("Unable to derive shared secret", e);
        }
    }

    private static BspMaterial deriveBspMaterial(byte[] sharedSecret, byte[] hostId) {
        try {
            ByteArrayOutputStream sharedInfo = new ByteArrayOutputStream();
            sharedInfo.write(0x88);
            sharedInfo.write(0x10);
            appendLength(sharedInfo, hostId.length);
            sharedInfo.write(hostId, 0, hostId.length);
            appendLength(sharedInfo, EID_VALUE.length);
            sharedInfo.write(EID_VALUE, 0, EID_VALUE.length);

            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] out = new byte[48];
            int outPos = 0;
            int counter = 1;
            while (outPos < out.length) {
                sha256.reset();
                sha256.update(sharedSecret);
                sha256.update(new byte[]{0x00, 0x00, 0x00, (byte) counter});
                sha256.update(sharedInfo.toByteArray());
                byte[] digest = sha256.digest();
                int copyLen = Math.min(digest.length, out.length - outPos);
                System.arraycopy(digest, 0, out, outPos, copyLen);
                outPos += copyLen;
                counter++;
            }

            return new BspMaterial(
                    Arrays.copyOfRange(out, 0, 16),
                    Arrays.copyOfRange(out, 16, 32),
                    Arrays.copyOfRange(out, 32, 48)
            );
        } catch (Exception e) {
            throw new RuntimeException("Unable to derive BSP material", e);
        }
    }

    private static byte[] leftShiftBlock(byte[] input) {
        byte[] out = new byte[16];
        int carry = 0;
        for (int i = 15; i >= 0; i--) {
            int value = input[i] & 0xFF;
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

    private static byte[] aesEncryptBlock(byte[] key, byte[] block) {
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
            return cipher.doFinal(block);
        } catch (Exception e) {
            throw new RuntimeException("Unable to AES-encrypt block", e);
        }
    }

    private static byte[] aesCmac(byte[] key, byte[] data) {
        byte[] zero = new byte[16];
        byte[] l = aesEncryptBlock(key, zero);
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

    private static byte[] padBspPlaintext(byte[] plaintext) {
        int paddedLen = ((plaintext.length + 1 + 15) / 16) * 16;
        byte[] padded = new byte[paddedLen];
        System.arraycopy(plaintext, 0, padded, 0, plaintext.length);
        padded[plaintext.length] = (byte) 0x80;
        return padded;
    }

    private static byte[] encryptBspPayload(byte[] sEnc, int blockNr, byte[] plaintext) {
        try {
            byte[] counterBlock = new byte[16];
            counterBlock[12] = (byte) ((blockNr >> 24) & 0xFF);
            counterBlock[13] = (byte) ((blockNr >> 16) & 0xFF);
            counterBlock[14] = (byte) ((blockNr >> 8) & 0xFF);
            counterBlock[15] = (byte) (blockNr & 0xFF);

            Cipher icvCipher = Cipher.getInstance("AES/CBC/NoPadding");
            byte[] zeroIv = new byte[16];
            icvCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(sEnc, "AES"),
                    new javax.crypto.spec.IvParameterSpec(zeroIv));
            byte[] icv = icvCipher.doFinal(counterBlock);

            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(sEnc, "AES"),
                    new javax.crypto.spec.IvParameterSpec(icv));
            return cipher.doFinal(padBspPlaintext(plaintext));
        } catch (Exception e) {
            throw new RuntimeException("Unable to BSP-encrypt payload", e);
        }
    }

    private static byte[] protectSegment(int tag, byte[] plaintext, BspState state, boolean macOnly) {
        byte[] protectedData = macOnly
                ? plaintext
                : encryptBspPayload(state.sEnc, state.blockNr, plaintext);
        byte[] header = wrapTlvHeader(tag, protectedData.length + 8);
        byte[] macInput = concat(state.mcv, header, protectedData);
        byte[] fullCmac = aesCmac(state.sMac, macInput);
        System.arraycopy(fullCmac, 0, state.mcv, 0, 16);
        state.blockNr++;
        return concat(header, protectedData, Arrays.copyOf(fullCmac, 8));
    }

    private static byte[] wrapTlvHeader(int tag, int valueLen) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        appendTag(out, tag);
        appendLength(out, valueLen);
        return out.toByteArray();
    }

    private static byte[] buildProtectedSequence(int tag, int payloadLen, int count, int seed,
                                                 BspState state, boolean macOnly) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (int i = 0; i < count; i++) {
            byte[] payload = new byte[payloadLen];
            for (int j = 0; j < payload.length; j++) {
                payload[j] = (byte) ((seed + i + j) & 0xFF);
            }
            byte[] segment = protectSegment(tag, payload, state, macOnly);
            out.write(segment, 0, segment.length);
        }
        return out.toByteArray();
    }

    private static byte[] buildValidLoadBppPayload(byte[] txId, byte[] euiccOtpk,
                                                   int segmentPayloadLen, int segmentCount,
                                                   boolean includeA2) {
        return buildLoadBppPayload(txId, euiccOtpk, segmentPayloadLen, segmentCount,
                includeA2, HOST_ID, HOST_ID);
    }

    private static byte[] buildLoadBppPayload(byte[] txId, byte[] euiccOtpk,
                                              int segmentPayloadLen, int segmentCount,
                                              boolean includeA2,
                                              byte[] crtHostId,
                                              byte[] bspHostId) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair smdpOt = kpg.generateKeyPair();
            byte[] smdpOtpk = encodeUncompressedPoint((ECPublicKey) smdpOt.getPublic());
            byte[] sharedSecret = computeSharedSecret(smdpOt, euiccOtpk);
            BspMaterial bsp = deriveBspMaterial(sharedSecret, bspHostId);
            BspState bspState = new BspState(bsp);

            byte[] remoteOpId = wrapTlv(0x82, new byte[]{0x01});
            byte[] txIdTlv = wrapTlv(0x80, txId);
            byte[] crt = wrapTlv(0xA6, concat(
                    wrapTlv(0x80, new byte[]{(byte) 0x88}),
                    wrapTlv(0x81, new byte[]{0x10}),
                    wrapTlv(0x84, crtHostId)
            ));
            byte[] smdpOtpkTlv = wrapTlv(0x5F49, smdpOtpk);
            byte[] toSign = concat(remoteOpId, txIdTlv, crt, smdpOtpkTlv, wrapTlv(0x5F49, euiccOtpk));
            byte[] smdpSign = sign(toSign);

            byte[] bf23 = wrapTlv(0xBF23, concat(
                    remoteOpId,
                    txIdTlv,
                    crt,
                    smdpOtpkTlv,
                    wrapTlv(0x5F37, smdpSign)
            ));
            byte[] a0 = wrapTlv(0xA0, buildProtectedSequence(0x87, segmentPayloadLen, segmentCount, 0x10, bspState, false));
            byte[] a1 = wrapTlv(0xA1, buildProtectedSequence(0x88, segmentPayloadLen, segmentCount, 0x40, bspState, true));
            byte[] a2 = new byte[0];
            byte[] a3;
            if (includeA2) {
                BspMaterial ppp = buildDummyPppMaterial();
                BspState pppState = new BspState(ppp);
                byte[] rsk = buildReplaceSessionKeysRequest(ppp);
                a2 = wrapTlv(0xA2, protectSegment(0x87, rsk, bspState, false));
                a3 = wrapTlv(0xA3, buildProtectedSequence(0x86, segmentPayloadLen, segmentCount, 0x70, pppState, false));
            } else {
                a3 = wrapTlv(0xA3, buildProtectedSequence(0x86, segmentPayloadLen, segmentCount, 0x70, bspState, false));
            }
            return wrapTlv(0xBF36, concat(bf23, a0, a1, a2, a3));
        } catch (Exception e) {
            throw new RuntimeException("Unable to build valid BoundProfilePackage", e);
        }
    }

    private static BspMaterial buildDummyPppMaterial() {
        byte[] pppSEnc = new byte[16];
        byte[] pppSMac = new byte[16];
        byte[] initialMcv = new byte[16];
        Arrays.fill(pppSMac, (byte) 0x11);
        Arrays.fill(initialMcv, (byte) 0x22);
        return new BspMaterial(initialMcv, pppSEnc, pppSMac);
    }

    private static byte[] buildReplaceSessionKeysRequest(BspMaterial ppp) {
        return wrapTlv(0xBF26, concat(
                wrapTlv(0x80, ppp.initialMcv),
                wrapTlv(0x81, ppp.sEnc),
                wrapTlv(0x82, ppp.sMac)
        ));
    }

    private static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            out.write(part, 0, part.length);
        }
        return out.toByteArray();
    }

    private static void tamperFirstTaggedValueByte(byte[] payload, short tag) {
        int idx = findTag(payload, tag);
        if (idx < 0) {
            throw new IllegalArgumentException("Tag not found: " + Integer.toHexString(tag & 0xFFFF));
        }
        int tagSize = (tag & 0xFF00) != 0 ? 2 : 1;
        int len = readDerLength(payload, idx + tagSize);
        int lenFieldSize = derParseLenFieldSize(payload[idx + tagSize]);
        int valueOff = idx + tagSize + lenFieldSize;
        payload[valueOff + len - 1] ^= 0x01;
    }

    private static int findTag(byte[] data, short tag) {
        for (int i = 0; i < data.length - 1; i++) {
            if ((tag & 0xFF00) != 0) {
                if ((data[i] & 0xFF) == ((tag >> 8) & 0xFF) && (data[i + 1] & 0xFF) == (tag & 0xFF)) {
                    return i;
                }
            } else if ((data[i] & 0xFF) == (tag & 0xFF)) {
                return i;
            }
        }
        return -1;
    }

    private static void assertSuccessfulInstallationResult(byte[] data, byte[] txId) {
        assertTrue("Expected ProfileInstallationResult payload", data.length > 10);
        assertEquals((byte) 0xBF, data[0]);
        assertEquals(0x37, data[1]);
        assertTrue("Response must echo transactionId", findBytes(data, concat(fromHex("80" + String.format("%02X", txId.length)), txId)));
        assertTrue("Response must contain success result AID", findBytes(data, fromHex("4F08D07002CA44900101")));
    }

    private static void assertInstallationError(byte[] data, byte[] txId, int bppCommandId, int errorReason) {
        assertTrue("Expected ProfileInstallationResult payload", data.length > 10);
        assertEquals((byte) 0xBF, data[0]);
        assertEquals(0x37, data[1]);
        assertTrue("Error response must echo transactionId", findBytes(data, concat(fromHex("80" + String.format("%02X", txId.length)), txId)));
        assertTrue("Error response must carry bppCommandId and errorReason",
                findBytes(data, fromHex(String.format("A208A1068001%02X8101%02X", bppCommandId, errorReason))));
    }

    private static boolean findBytes(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }

    private static byte[] buildAuthServerApdu(byte[] txId, byte[] euiccChallenge,
                                              byte[] serverAddress, byte[] serverChallenge,
                                              byte[] serverSig, byte[] ciPKId) {
        int ssLen = 2 + txId.length + 2 + 16 + 2 + serverAddress.length + 2 + 16;
        byte[] serverSigned1 = new byte[2 + ssLen];
        int p = 0;
        serverSigned1[p++] = 0x30;
        serverSigned1[p++] = (byte) ssLen;
        serverSigned1[p++] = (byte) 0x80;
        serverSigned1[p++] = (byte) txId.length;
        System.arraycopy(txId, 0, serverSigned1, p, txId.length);
        p += txId.length;
        serverSigned1[p++] = (byte) 0x81;
        serverSigned1[p++] = 0x10;
        System.arraycopy(euiccChallenge, 0, serverSigned1, p, 16);
        p += 16;
        serverSigned1[p++] = (byte) 0x83;
        serverSigned1[p++] = (byte) serverAddress.length;
        System.arraycopy(serverAddress, 0, serverSigned1, p, serverAddress.length);
        p += serverAddress.length;
        serverSigned1[p++] = (byte) 0x84;
        serverSigned1[p++] = 0x10;
        System.arraycopy(serverChallenge, 0, serverSigned1, p, 16);

        byte[] sigTlv = new byte[3 + serverSig.length];
        sigTlv[0] = 0x5F;
        sigTlv[1] = 0x37;
        sigTlv[2] = (byte) serverSig.length;
        System.arraycopy(serverSig, 0, sigTlv, 3, serverSig.length);

        byte[] ciTlv = new byte[2 + ciPKId.length];
        ciTlv[0] = 0x04;
        ciTlv[1] = (byte) ciPKId.length;
        System.arraycopy(ciPKId, 0, ciTlv, 2, ciPKId.length);

        byte[] certTlv = loadDpAuthCertDer();
        byte[] ctxTlv = buildMinimalCtxParams1();

        int innerLen = serverSigned1.length + sigTlv.length + ciTlv.length + certTlv.length + ctxTlv.length;
        int bf38LenField = derLenFieldSize(innerLen);
        byte[] bf38 = new byte[2 + bf38LenField + innerLen];
        int q = 0;
        bf38[q++] = (byte) 0xBF;
        bf38[q++] = 0x38;
        q = writeDerLength(bf38, q, innerLen);
        System.arraycopy(serverSigned1, 0, bf38, q, serverSigned1.length);
        q += serverSigned1.length;
        System.arraycopy(sigTlv, 0, bf38, q, sigTlv.length);
        q += sigTlv.length;
        System.arraycopy(ciTlv, 0, bf38, q, ciTlv.length);
        q += ciTlv.length;
        System.arraycopy(certTlv, 0, bf38, q, certTlv.length);
        q += certTlv.length;
        System.arraycopy(ctxTlv, 0, bf38, q, ctxTlv.length);
        return buildStoreDataApdu(bf38);
    }

    private static byte[] buildCancelSessionApdu(byte[] txId, byte reason) {
        int innerLen = 2 + txId.length + 3;
        byte[] bf41 = new byte[3 + innerLen];
        int p = 0;
        bf41[p++] = (byte) 0xBF;
        bf41[p++] = 0x41;
        bf41[p++] = (byte) innerLen;
        bf41[p++] = (byte) 0x80;
        bf41[p++] = (byte) txId.length;
        System.arraycopy(txId, 0, bf41, p, txId.length);
        p += txId.length;
        bf41[p++] = (byte) 0x81;
        bf41[p++] = 0x01;
        bf41[p] = reason;
        return buildStoreDataApdu(bf41);
    }

    private static byte[] buildMinimalCtxParams1() {
        return fromHex("A00AA108800401020304A100");
    }

    @Test
    public void testPrepareThenLoadBoundProfilePackage() {
        Simulator sim = createAndSelect();
        byte[] txId = fromHex("0A0B0C0D");
        byte[] euiccOtpk = prepareDownloadAndGetEuiccOtpk(sim, txId);

        ApduResult loadRes = transmit(sim, buildStoreDataApdu(buildValidLoadBppPayload(txId, euiccOtpk, 8, 1, false)));
        assertEquals("LoadBoundProfilePackage must succeed after PrepareDownload", 0x9000, loadRes.sw);
        assertSuccessfulInstallationResult(loadRes.data, txId);
    }

    @Test
    public void testLoadBoundProfilePackageSuccess() {
        Simulator sim = createAndSelect();
        byte[] txId = fromHex("0A0B0C0D");
        byte[] euiccOtpk = prepareDownloadAndGetEuiccOtpk(sim, txId);
        byte[] payload = buildValidLoadBppPayload(txId, euiccOtpk, 8, 1, false);

        ApduResult res = transmit(sim, buildStoreDataApdu(payload));
        assertEquals("LoadBoundProfilePackage must succeed", 0x9000, res.sw);
        assertSuccessfulInstallationResult(res.data, txId);
    }

    @Test
    public void testLoadBoundProfilePackageWithOptionalA2() {
        Simulator sim = createAndSelect();
        byte[] txId = fromHex("DEADBEEF");
        byte[] euiccOtpk = prepareDownloadAndGetEuiccOtpk(sim, txId);
        byte[] payload = buildValidLoadBppPayload(txId, euiccOtpk, 8, 1, true);

        ApduResult res = transmit(sim, buildStoreDataApdu(payload));
        assertEquals("LoadBPP with optional [2] must succeed", 0x9000, res.sw);
        assertSuccessfulInstallationResult(res.data, txId);
    }

    @Test
    public void testLoadBoundProfilePackageLargeChainedPayload() {
        Simulator sim = createAndSelect();
        byte[] txId = fromHex("11223344");
        byte[] euiccOtpk = prepareDownloadAndGetEuiccOtpk(sim, txId);
        byte[] payload = buildValidLoadBppPayload(txId, euiccOtpk, 64, 47, true);
        assertTrue("Test payload must exceed transient APDU assembly capacity", payload.length > 1536);

        ApduResult res = transmitStoreDataChained(sim, payload);
        assertEquals("Large chained LoadBoundProfilePackage must succeed", 0x9000, res.sw);
        assertSuccessfulInstallationResult(res.data, txId);
    }

    @Test
    public void testLoadBoundProfilePackageRejectsNonCompliantPiecewiseSegmentation() {
        Simulator sim = createAndSelect();
        byte[] txId = fromHex("33445566");
        byte[] euiccOtpk = prepareDownloadAndGetEuiccOtpk(sim, txId);
        byte[] payload = buildValidLoadBppPayload(txId, euiccOtpk, 8, 2, true);

        ApduResult res = transmitBppPiecewiseLpacStyle(sim, payload);
        assertEquals("Non-compliant piecewise LoadBoundProfilePackage must be rejected", 0x6A80, res.sw);
    }

    @Test
    public void testLoadBoundProfilePackagePiecewiseSgp22Style() {
        Simulator sim = createAndSelect();
        byte[] txId = fromHex("44556677");
        byte[] euiccOtpk = prepareDownloadAndGetEuiccOtpk(sim, txId);
        byte[] payload = buildValidLoadBppPayload(txId, euiccOtpk, 8, 3, true);

        ApduResult res = transmitBppPiecewiseSgp22Style(sim, payload);
        assertEquals("Piecewise SGP.22-style LoadBoundProfilePackage must succeed", 0x9000, res.sw);
        assertSuccessfulInstallationResult(res.data, txId);
    }

    @Test
    public void testLoadBppClearsSessionState() {
        Simulator sim = createAndSelect();

        ApduResult challengeRes = transmit(sim, fromHex("80E2910003BF2E00"));
        assertEquals(0x9000, challengeRes.sw);
        byte[] challenge = new byte[16];
        assertTrue("Challenge response too short", challengeRes.data.length >= 21);
        System.arraycopy(challengeRes.data, 5, challenge, 0, 16);

        byte[] txId = fromHex("01020304");
        byte[] euiccOtpk = prepareDownloadAndGetEuiccOtpk(sim, txId);
        ApduResult bppRes = transmit(sim, buildStoreDataApdu(buildValidLoadBppPayload(txId, euiccOtpk, 8, 1, false)));
        assertEquals("LoadBPP must succeed", 0x9000, bppRes.sw);

        byte[] serverAddress = fromHex("736D64702E636F6D");
        byte[] serverChallenge = fromHex("AABBCCDD11223344AABBCCDD11223344");
        byte[] serverSig = fromHex("DEADBEEFCAFEBABE");
        byte[] ciPKId = fromHex("01020304");
        byte[] authApdu = buildAuthServerApdu(txId, challenge, serverAddress, serverChallenge, serverSig, ciPKId);
        ApduResult authRes = transmit(sim, authApdu);

        assertEquals("Should return 9000 with error payload", 0x9000, authRes.sw);
        assertEquals((byte) 0xBF, authRes.data[0]);
        assertEquals(0x38, authRes.data[1]);
        assertTrue("Session must be cleared after LoadBPP", findBytes(authRes.data, fromHex("020106")));
    }

    @Test
    public void testLoadBppErrorKeepsSessionForCancel() {
        Simulator sim = createAndSelect();
        byte[] txId = fromHex("22334455");
        byte[] euiccOtpk = prepareDownloadAndGetEuiccOtpk(sim, txId);
        byte[] payload = buildValidLoadBppPayload(txId, euiccOtpk, 8, 1, false);
        payload[payload.length - 1] ^= 0x01;

        ApduResult loadRes = transmit(sim, buildStoreDataApdu(payload));
        assertEquals("Invalid segment MAC must return ProfileInstallationResult error", 0x9000, loadRes.sw);
        assertInstallationError(loadRes.data, txId, 0x05, 0x08);

        ApduResult cancelRes = transmit(sim, buildCancelSessionApdu(txId, (byte) 0x00));
        assertEquals("CancelSession must still succeed after failed LoadBPP", 0x9000, cancelRes.sw);
        assertEquals((byte) 0xBF, cancelRes.data[0]);
        assertEquals(0x41, cancelRes.data[1]);
        assertEquals("CancelSession must return the success CHOICE", (byte) 0xA0, cancelRes.data[3]);
    }

    @Test
    public void testLoadBppPersistsVerifiedPackageMetadata() {
        Simulator sim = createAndSelect();
        byte[] txId = fromHex("10203040");
        byte[] euiccOtpk = prepareDownloadAndGetEuiccOtpk(sim, txId);
        byte[] payload = buildValidLoadBppPayload(txId, euiccOtpk, 8, 1, true);

        ApduResult loadRes = transmit(sim, buildStoreDataApdu(payload));
        assertEquals("LoadBPP must succeed", 0x9000, loadRes.sw);

        AID aid = new AID(APPLET_AID, (short) 0, (byte) APPLET_AID.length);
        assertTrue("Applet must remain selectable after LoadBPP", sim.selectApplet(aid));

        ApduResult infoRes = transmit(sim, buildGetPersistedBppInfoApdu());
        assertEquals("Persisted BPP info query must succeed", 0x9000, infoRes.sw);
        assertTrue("Persisted BPP info must include encoded length",
                findBytes(infoRes.data, new byte[]{
                        (byte) 0x80, 0x02,
                        (byte) ((payload.length >> 8) & 0xFF),
                        (byte) (payload.length & 0xFF)
                }));
        assertTrue("Persisted BPP info must include txId",
                findBytes(infoRes.data, concat(new byte[]{(byte) 0x81, (byte) txId.length}, txId)));
    }

    @Test
    public void testPersistedBppInfoMissingBeforeSuccessfulLoad() {
        Simulator sim = createAndSelect();

        ApduResult infoRes = transmit(sim, buildGetPersistedBppInfoApdu());
        assertEquals("Persisted BPP info must be absent before any verified LoadBPP", 0x6A88, infoRes.sw);
    }

    @Test
    public void testLoadBppMultipleSequenceOf87Elements() {
        Simulator sim = createAndSelect();
        byte[] txId = fromHex("0A0B0C0D");
        byte[] euiccOtpk = prepareDownloadAndGetEuiccOtpk(sim, txId);
        byte[] payload = buildValidLoadBppPayload(txId, euiccOtpk, 8, 2, false);

        ApduResult res = transmit(sim, buildStoreDataApdu(payload));
        assertEquals("Multiple 87 elements in A0 must succeed", 0x9000, res.sw);
        assertSuccessfulInstallationResult(res.data, txId);
    }

    @Test
    public void testLoadBppRejectsInvalidBf23Signature() {
        Simulator sim = createAndSelect();
        byte[] txId = fromHex("A1B2C3D4");
        byte[] euiccOtpk = prepareDownloadAndGetEuiccOtpk(sim, txId);
        byte[] payload = buildValidLoadBppPayload(txId, euiccOtpk, 8, 1, false);
        tamperFirstTaggedValueByte(payload, (short) 0x5F37);

        ApduResult res = transmit(sim, buildStoreDataApdu(payload));
        assertEquals("Invalid BF23 signature must return ProfileInstallationResult error", 0x9000, res.sw);
        assertInstallationError(res.data, txId, 0x00, 0x02);
    }

    @Test
    public void testLoadBppRejectsInvalidSegmentMac() {
        Simulator sim = createAndSelect();
        byte[] txId = fromHex("55667788");
        byte[] euiccOtpk = prepareDownloadAndGetEuiccOtpk(sim, txId);
        byte[] payload = buildValidLoadBppPayload(txId, euiccOtpk, 8, 1, false);
        payload[payload.length - 1] ^= 0x01;

        ApduResult res = transmit(sim, buildStoreDataApdu(payload));
        assertEquals("Invalid segment MAC must return ProfileInstallationResult error", 0x9000, res.sw);
        assertInstallationError(res.data, txId, 0x05, 0x08);
    }

    @Test
    public void testLoadBppRejectsHostIdMismatchViaMacFailure() {
        Simulator sim = createAndSelect();
        byte[] txId = fromHex("66778899");
        byte[] euiccOtpk = prepareDownloadAndGetEuiccOtpk(sim, txId);
        byte[] payload = buildLoadBppPayload(txId, euiccOtpk, 8, 1, false,
                HOST_ID, fromHex("A1B2C3D5"));

        ApduResult res = transmit(sim, buildStoreDataApdu(payload));
        assertEquals("hostId mismatch must return ProfileInstallationResult error", 0x9000, res.sw);
        assertInstallationError(res.data, txId, 0x01, 0x08);
    }

    @Test
    public void testLoadBppRejectsMalformedPayload() {
        Simulator sim = createAndSelect();
        ApduResult res = transmit(sim, fromHex("80E2910005BF36033000"));
        assertEquals("Malformed payload must be rejected", 0x6A80, res.sw);
    }

    @Test
    public void testLoadBppRejectsMissingInitSecureChannel() {
        Simulator sim = createAndSelect();
        ApduResult res = transmit(sim, fromHex("80E2910005BF36023000"));
        assertEquals("Missing BF23 must be rejected", 0x6A80, res.sw);
    }

    @Test
    public void testLoadBppRejectsWrongRemoteOpId() {
        Simulator sim = createAndSelect();

        byte[] remoteOpId = fromHex("820102");
        byte[] txIdTlv = fromHex("80040A0B0C0D");
        byte[] crt = fromHex("A60C8001888101108404A1B2C3D4");
        byte[] otpk = new byte[65];
        otpk[0] = 0x04;
        byte[] otpkTlv = new byte[3 + otpk.length];
        otpkTlv[0] = 0x5F;
        otpkTlv[1] = 0x49;
        otpkTlv[2] = (byte) otpk.length;
        byte[] sign = fromHex("5F37080102030405060708");

        int bf23BodyLen = remoteOpId.length + txIdTlv.length + crt.length + otpkTlv.length + sign.length;
        byte[] bf23 = new byte[3 + bf23BodyLen];
        int p = 0;
        bf23[p++] = (byte) 0xBF;
        bf23[p++] = 0x23;
        bf23[p++] = (byte) bf23BodyLen;
        System.arraycopy(remoteOpId, 0, bf23, p, remoteOpId.length);
        p += remoteOpId.length;
        System.arraycopy(txIdTlv, 0, bf23, p, txIdTlv.length);
        p += txIdTlv.length;
        System.arraycopy(crt, 0, bf23, p, crt.length);
        p += crt.length;
        System.arraycopy(otpkTlv, 0, bf23, p, otpkTlv.length);
        p += otpkTlv.length;
        System.arraycopy(sign, 0, bf23, p, sign.length);

        byte[] a0 = fromHex("A00487020102");
        byte[] a1 = fromHex("A10488020304");
        byte[] a3 = fromHex("A30486020506");
        byte[] bf36 = wrapTlv(0xBF36, concat(bf23, a0, a1, a3));

        ApduResult res = transmit(sim, buildStoreDataApdu(bf36));
        assertEquals("remoteOpId != 1 must be rejected", 0x6A80, res.sw);
    }

    @Test
    public void testLoadBppRejectsNonCanonicalRemoteOpIdInteger() {
        Simulator sim = createAndSelect();

        byte[] remoteOpId = fromHex("82020001");
        byte[] txIdTlv = fromHex("80040A0B0C0D");
        byte[] crt = fromHex("A60C8001888101108404A1B2C3D4");
        byte[] otpk = new byte[65];
        otpk[0] = 0x04;
        byte[] otpkTlv = new byte[3 + otpk.length];
        otpkTlv[0] = 0x5F;
        otpkTlv[1] = 0x49;
        otpkTlv[2] = (byte) otpk.length;
        byte[] sign = fromHex("5F37080102030405060708");

        byte[] bf23 = wrapTlv(0xBF23, concat(remoteOpId, txIdTlv, crt, otpkTlv, sign));
        byte[] bf36 = wrapTlv(0xBF36, concat(bf23, fromHex("A00487020102"), fromHex("A10488020304"), fromHex("A30486020506")));

        ApduResult res = transmit(sim, buildStoreDataApdu(bf36));
        assertEquals("Non-canonical INTEGER encoding must be rejected", 0x6A80, res.sw);
    }

    @Test
    public void testLoadBppRejectsWrongTagInSequenceOf() {
        Simulator sim = createAndSelect();

        byte[] remoteOpId = fromHex("820101");
        byte[] txIdTlv = fromHex("80040A0B0C0D");
        byte[] crt = fromHex("A60C8001888101108404A1B2C3D4");
        byte[] otpk = new byte[65];
        otpk[0] = 0x04;
        byte[] otpkTlv = new byte[3 + otpk.length];
        otpkTlv[0] = 0x5F;
        otpkTlv[1] = 0x49;
        otpkTlv[2] = (byte) otpk.length;
        byte[] sign = fromHex("5F37080102030405060708");

        byte[] bf23 = wrapTlv(0xBF23, concat(remoteOpId, txIdTlv, crt, otpkTlv, sign));
        byte[] bf36 = wrapTlv(0xBF36, concat(bf23, fromHex("A00488020102"), fromHex("A10488020304"), fromHex("A30486020506")));

        ApduResult res = transmit(sim, buildStoreDataApdu(bf36));
        assertEquals("Wrong inner tag in A0 (88 instead of 87) must be rejected", 0x6A80, res.sw);
    }
}
