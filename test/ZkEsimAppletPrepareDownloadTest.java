import com.licel.jcardsim.base.Simulator;
import javacard.framework.AID;
import org.junit.Test;
import zk.esim.applet.ZkEsimApplet;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.io.ByteArrayOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

/**
 * jCardSim integration tests for PrepareDownload (ES10b, BF21).
 *
 * Per SGP.22 v3.1 section 5.7.5, the eUICC SHALL:
 * - Verify the SM-DP+ has been previously authenticated (session exists).
 * - Extract transactionId, ccRequiredFlag, optional bppEuiccOtpk from SmdpSigned2.
 * - Generate a new one-time KA key pair (otPK.EUICC.KA) if needed.
 * - Build euiccSigned2 = { transactionId [0], euiccOtpk [APPLICATION 73] }.
 * - Sign euiccSigned2 with SK.EUICC.SIG and return PrepareDownloadResponse.
 * ASN.1 (rsp.asn):
 *   PrepareDownloadRequest ::= [33] SEQUENCE { -- Tag 'BF21'
 *       smdpSigned2 SmdpSigned2,
 *       smdpSignature2 [APPLICATION 55] OCTET STRING,
 *       hashCc Octet32 OPTIONAL,
 *       smdpCertificate Certificate
 *   }
 *   SmdpSigned2 ::= SEQUENCE {
 *       transactionId [0] TransactionId,
 *       ccRequiredFlag BOOLEAN,
 *       bppEuiccOtpk [APPLICATION 73] OCTET STRING OPTIONAL
 *   }
 *   PrepareDownloadResponse ::= [33] CHOICE { -- Tag 'BF21'
 *       downloadResponseOk PrepareDownloadResponseOk,
 *       downloadResponseError PrepareDownloadResponseError
 *   }
 *   PrepareDownloadResponseOk ::= SEQUENCE {
 *       euiccSigned2 EUICCSigned2,
 *       euiccSignature2 [APPLICATION 55] OCTET STRING
 *   }
 *   EUICCSigned2 ::= SEQUENCE {
 *       transactionId [0] TransactionId,
 *       euiccOtpk [APPLICATION 73] OCTET STRING
 *   }
 */
public class ZkEsimAppletPrepareDownloadTest {

    private static final byte[] APPLET_AID = fromHex("D07002CA44900101");
        private static final byte[] TEST_PRIVATE_KEY_DER = fromHex(
            "308187020100301306072A8648CE3D020106082A8648CE3D030107046D306B0201010420DCD694B778957E8E9ADDBDD94433E9EF8F73D11E491C48D425A38A9491BD3BEDA14403420004104C2AE3D02DEF9C979261A7C6710076B970721D0955A2644AE05FAE4BC2314E5DC09F6BF0118026165342E212318775E365F3B57325373066B9906E0BD1388D"
        );
            private static final byte[] AUTH_SERVER_PRIVATE_KEY_DER = fromHex(
                "308187020100301306072A8648CE3D020106082A8648CE3D030107046D306B02010104200A7CC1C244E60C52CD5B7807AB8C360C26524601507DCABC5DD598B5A616D5D5A144034200044DFED4F4694791BF1695CEA0307A35B418019695387BB75B7D2447B6B5209F0445AE4E5E521CD13888D75FE07C8580222AE20DBAAC1D77CD76304993421BD739"
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
        ByteArrayOutputStream allData = new ByteArrayOutputStream();
        byte[] responseBytes;
        if (isExtendedStoreData(command)) {
            responseBytes = transmitStoreDataChained(sim, command);
        } else {
            responseBytes = sim.transmitCommand(command);
        }
        assertTrue("Response APDU must include SW1SW2", responseBytes.length >= 2);
        int sw = ((responseBytes[responseBytes.length - 2] & 0xFF) << 8) | (responseBytes[responseBytes.length - 1] & 0xFF);
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
        System.out.println("[" + testName + "] APDU TX: " + toHex(command));
        System.out.println("[" + testName + "] APDU RX: " + toHex(fullResponse) + " SW=" + String.format("%04X", sw));
        return new ApduResult(fullResponse);
    }

    private static boolean isExtendedStoreData(byte[] command) {
        return command.length >= 7
                && command[1] == (byte) 0xE2
                && command[4] == 0x00;
    }

    private static byte[] transmitStoreDataChained(Simulator sim, byte[] command) {
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
            pos += chunkLen;
            blockNo++;
        }

        if (response == null) {
            throw new IllegalStateException("No APDU blocks transmitted");
        }
        return response;
    }

    private static String currentTestName() {
        StackTraceElement[] stack = Thread.currentThread().getStackTrace();
        for (int i = 0; i < stack.length; i++) {
            String method = stack[i].getMethodName();
            if (method.startsWith("test")) {
                return method;
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

    private static byte[] sign(byte[] data) {
        return signWithKey(data, TEST_PRIVATE_KEY_DER);
    }

    private static byte[] signWithKey(byte[] data, byte[] privateKeyDer) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyDer));
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

    private static byte[] buildSmdpSignature2Input(byte[] smdpSigned2, byte[] euiccSignature1) {
        int euiccSigLen = euiccSignature1 == null ? 0 : euiccSignature1.length;
        byte[] out = new byte[smdpSigned2.length + 3 + euiccSigLen];
        int p = 0;
        System.arraycopy(smdpSigned2, 0, out, p, smdpSigned2.length);
        p += smdpSigned2.length;
        out[p++] = 0x5F;
        out[p++] = 0x37;
        out[p++] = (byte) euiccSigLen;
        if (euiccSigLen > 0) {
            System.arraycopy(euiccSignature1, 0, out, p, euiccSigLen);
        }
        return out;
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

    private static byte[] buildAuthenticateServerApdu(byte[] txId, byte[] euiccChallenge,
                                                       byte[] serverAddress, byte[] serverChallenge,
                                                       byte[] ciPKId) {
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

        byte[] serverSig = signWithKey(serverSigned1, AUTH_SERVER_PRIVATE_KEY_DER);

        byte[] sigTlv = new byte[3 + serverSig.length];
        sigTlv[0] = (byte) 0x5F;
        sigTlv[1] = (byte) 0x37;
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

    private static byte[] buildMinimalCtxParams1() {
        return fromHex("A00AA108800401020304A100");
    }

    private static byte[] parseEuiccSignature1(byte[] bf38ResponseData) {
        int idx = 2; // after BF38 tag
        idx += derParseLenFieldSize(bf38ResponseData[idx]);

        if (bf38ResponseData[idx] != (byte) 0xA0) {
            throw new IllegalArgumentException("AuthenticateServer response missing A0 CHOICE");
        }
        idx++;
        idx += derParseLenFieldSize(bf38ResponseData[idx]);

        if (bf38ResponseData[idx] != 0x30) {
            throw new IllegalArgumentException("AuthenticateServer response missing euiccSigned1");
        }
        idx++;
        int euiccSigned1Len = readDerLength(bf38ResponseData, idx);
        idx += derParseLenFieldSize(bf38ResponseData[idx]);
        idx += euiccSigned1Len;

        if (bf38ResponseData[idx] != (byte) 0x5F || bf38ResponseData[idx + 1] != 0x37) {
            throw new IllegalArgumentException("AuthenticateServer response missing euiccSignature1 tag");
        }
        int sigLen = readDerLength(bf38ResponseData, idx + 2);
        int sigLenFieldSize = derParseLenFieldSize(bf38ResponseData[idx + 2]);
        byte[] euiccSignature1 = new byte[sigLen];
        System.arraycopy(bf38ResponseData, idx + 2 + sigLenFieldSize, euiccSignature1, 0, sigLen);
        return euiccSignature1;
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

    private static byte[] performAuthenticateServerAndGetEuiccSignature1(Simulator sim) {
        ApduResult challengeRes = transmit(sim, fromHex("80E2910003BF2E00"));
        assertEquals("GetEuiccChallenge must succeed", 0x9000, challengeRes.sw);
        assertTrue("GetEuiccChallenge response too short", challengeRes.data.length >= 21);

        byte[] challenge = new byte[16];
        System.arraycopy(challengeRes.data, 5, challenge, 0, 16);

        byte[] authApdu = buildAuthenticateServerApdu(
                fromHex("01020304"),
                challenge,
                fromHex("736D64702E636F6D"),
                fromHex("AABBCCDD11223344AABBCCDD11223344"),
                fromHex("01020304")
        );

        ApduResult authRes = transmit(sim, authApdu);
        assertEquals("AuthenticateServer must succeed before strict PrepareDownload", 0x9000, authRes.sw);
        assertEquals((byte) 0xBF, authRes.data[0]);
        assertEquals((byte) 0x38, authRes.data[1]);
        return parseEuiccSignature1(authRes.data);
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

    /**
     * Build a PrepareDownloadRequest APDU.
     *
     * Structure:
     *   BF21 {
     *     30 { -- SmdpSigned2
     *       80 LL <txId>            -- transactionId [0]
     *       01 01 <ccFlag>          -- ccRequiredFlag BOOLEAN
     *     }
     *     5F37 LL <smdpSignature2>  -- [APPLICATION 55]
     *     30 00                     -- smdpCertificate (empty SEQUENCE placeholder)
     *   }
     */
    private static byte[] buildPrepareDownloadApdu(byte[] txId, boolean ccRequired, byte[] euiccSignature1) {
        // SmdpSigned2 body: 80 LL txId | 01 01 ccFlag
        int smdpSigned2Body = 2 + txId.length + 3;
        byte[] smdpSigned2 = new byte[2 + smdpSigned2Body];
        int p = 0;
        smdpSigned2[p++] = 0x30;
        smdpSigned2[p++] = (byte) smdpSigned2Body;
        smdpSigned2[p++] = (byte) 0x80;
        smdpSigned2[p++] = (byte) txId.length;
        System.arraycopy(txId, 0, smdpSigned2, p, txId.length);
        p += txId.length;
        smdpSigned2[p++] = 0x01; // BOOLEAN tag
        smdpSigned2[p++] = 0x01; // length 1
        smdpSigned2[p++] = ccRequired ? (byte) 0xFF : (byte) 0x00;

        byte[] smdpSig = sign(buildSmdpSignature2Input(smdpSigned2, euiccSignature1));

        // smdpSignature2: 5F37 LL <sig>
        byte[] sigTlv = new byte[3 + smdpSig.length];
        sigTlv[0] = 0x5F;
        sigTlv[1] = 0x37;
        sigTlv[2] = (byte) smdpSig.length;
        System.arraycopy(smdpSig, 0, sigTlv, 3, smdpSig.length);

        // smdpCertificate: real CERT.DPpb.ECDSA DER SEQUENCE
        byte[] certTlv = TEST_SMDP_CERT_DER;

        int innerLen = smdpSigned2.length + sigTlv.length + certTlv.length;

        // BF21 <canonical DER length> <inner>
        int bf21LenField = derLenFieldSize(innerLen);
        byte[] bf21 = new byte[2 + bf21LenField + innerLen];
        int q = 0;
        bf21[q++] = (byte) 0xBF;
        bf21[q++] = 0x21;
        q = writeDerLength(bf21, q, innerLen);
        System.arraycopy(smdpSigned2, 0, bf21, q, smdpSigned2.length); q += smdpSigned2.length;
        System.arraycopy(sigTlv,      0, bf21, q, sigTlv.length);      q += sigTlv.length;
        System.arraycopy(certTlv,     0, bf21, q, certTlv.length);

        return buildStoreDataApdu(bf21);
    }

    /**
     * Build a PrepareDownloadRequest APDU with optional bppEuiccOtpk.
     */
    private static byte[] buildPrepareDownloadApduWithOtpk(byte[] txId, boolean ccRequired,
                                                            byte[] bppEuiccOtpk, byte[] euiccSignature1) {
        // SmdpSigned2 body: 80 LL txId | 01 01 ccFlag | 5F49 LL otpk
        int smdpSigned2Body = 2 + txId.length + 3 + 3 + bppEuiccOtpk.length;
        byte[] smdpSigned2 = new byte[2 + smdpSigned2Body];
        int p = 0;
        smdpSigned2[p++] = 0x30;
        smdpSigned2[p++] = (byte) smdpSigned2Body;
        smdpSigned2[p++] = (byte) 0x80;
        smdpSigned2[p++] = (byte) txId.length;
        System.arraycopy(txId, 0, smdpSigned2, p, txId.length);
        p += txId.length;
        smdpSigned2[p++] = 0x01;
        smdpSigned2[p++] = (byte) 0x01;
        smdpSigned2[p++] = ccRequired ? (byte) 0xFF : (byte) 0x00;
        smdpSigned2[p++] = 0x5F;
        smdpSigned2[p++] = 0x49;
        smdpSigned2[p++] = (byte) bppEuiccOtpk.length;
        System.arraycopy(bppEuiccOtpk, 0, smdpSigned2, p, bppEuiccOtpk.length);

        byte[] smdpSig = sign(buildSmdpSignature2Input(smdpSigned2, euiccSignature1));

        byte[] sigTlv = new byte[3 + smdpSig.length];
        sigTlv[0] = 0x5F;
        sigTlv[1] = 0x37;
        sigTlv[2] = (byte) smdpSig.length;
        System.arraycopy(smdpSig, 0, sigTlv, 3, smdpSig.length);

        byte[] certTlv = TEST_SMDP_CERT_DER;

        int innerLen = smdpSigned2.length + sigTlv.length + certTlv.length;
        int bf21LenField = derLenFieldSize(innerLen);
        byte[] bf21 = new byte[2 + bf21LenField + innerLen];
        int q = 0;
        bf21[q++] = (byte) 0xBF;
        bf21[q++] = 0x21;
        q = writeDerLength(bf21, q, innerLen);
        System.arraycopy(smdpSigned2, 0, bf21, q, smdpSigned2.length); q += smdpSigned2.length;
        System.arraycopy(sigTlv,      0, bf21, q, sigTlv.length);      q += sigTlv.length;
        System.arraycopy(certTlv,     0, bf21, q, certTlv.length);

        return buildStoreDataApdu(bf21);
    }

    // -- Positive tests ----------------------------------------------------------

    @Test
    public void testPrepareDownloadSuccess() {
        Simulator sim = createAndSelect();
        byte[] euiccSignature1 = performAuthenticateServerAndGetEuiccSignature1(sim);

        byte[] txId = fromHex("0A0B0C0D");
        byte[] apdu = buildPrepareDownloadApdu(txId, false, euiccSignature1);
        ApduResult res = transmit(sim, apdu);

        assertEquals("Well-formed BF21 must succeed", 0x9000, res.sw);
        assertTrue("Response must contain BF21 tag", res.data.length >= 3);
        assertEquals((byte) 0xBF, res.data[0]);
        assertEquals((byte) 0x21, res.data[1]);
        // PrepareDownloadResponse is a CHOICE: downloadResponseOk auto-tagged as [0] IMPLICIT,
        // replacing the PrepareDownloadResponseOk SEQUENCE tag 0x30 with context tag 0xA0.
        assertEquals("First inner element should be CHOICE [0] (A0)", (byte) 0xA0, res.data[4]);
    }

    @Test
    public void testPrepareDownloadContainsTxIdAndOtpk() {
        Simulator sim = createAndSelect();
        byte[] euiccSignature1 = performAuthenticateServerAndGetEuiccSignature1(sim);

        byte[] txId = fromHex("AABBCCDD");
        byte[] apdu = buildPrepareDownloadApdu(txId, false, euiccSignature1);
        ApduResult res = transmit(sim, apdu);

        assertEquals("Well-formed BF21 must succeed", 0x9000, res.sw);
        assertTrue("Response must echo transactionId", findBytes(res.data, fromHex("8004AABBCCDD")));
        // 0x41 = 65 decimal, which is the length of an uncompressed P-256 public key (04 || X || Y)
        assertTrue("Response must contain euiccOtpk (5F49)", findBytes(res.data, fromHex("5F4941")));
    }

    @Test
    public void testPrepareDownloadContainsSignature() {
        Simulator sim = createAndSelect();
        byte[] euiccSignature1 = performAuthenticateServerAndGetEuiccSignature1(sim);

        byte[] txId = fromHex("01");
        byte[] apdu = buildPrepareDownloadApdu(txId, false, euiccSignature1);
        ApduResult res = transmit(sim, apdu);

        assertEquals("Well-formed BF21 must succeed", 0x9000, res.sw);
        assertTrue("Response must contain euiccSignature2 (5F37)", findBytes(res.data, fromHex("5F37")));
    }

    @Test
    public void testPrepareDownloadWithCcRequiredFlag() {
        Simulator sim = createAndSelect();
        byte[] euiccSignature1 = performAuthenticateServerAndGetEuiccSignature1(sim);

        byte[] txId = fromHex("01020304050607");
        byte[] apdu = buildPrepareDownloadApdu(txId, true, euiccSignature1);
        ApduResult res = transmit(sim, apdu);

        assertEquals("PrepareDownload with ccRequired=true must succeed", 0x9000, res.sw);
        assertEquals((byte) 0xBF, res.data[0]);
        assertEquals((byte) 0x21, res.data[1]);
    }

    @Test
    public void testPrepareDownloadWithBppEuiccOtpk() {
        Simulator sim = createAndSelect();
        byte[] euiccSignature1 = performAuthenticateServerAndGetEuiccSignature1(sim);

        byte[] txId = fromHex("AABB");
        byte[] otpk = new byte[65];
        otpk[0] = 0x04;
        for (int i = 1; i < 65; i++) otpk[i] = (byte) i;
        byte[] apdu = buildPrepareDownloadApduWithOtpk(txId, false, otpk, euiccSignature1);
        ApduResult res = transmit(sim, apdu);

        assertEquals("PrepareDownload with bppEuiccOtpk must succeed", 0x9000, res.sw);
        assertEquals((byte) 0xBF, res.data[0]);
        assertEquals((byte) 0x21, res.data[1]);
        byte[] returnedOtpk = extractTaggedValue(res.data, (short) 0x5F49);
        assertNotNull("Response must contain generated euiccOtpk", returnedOtpk);
        assertEquals("Generated euiccOtpk must be 65 bytes", 65, returnedOtpk.length);
        assertFalse("Response euiccOtpk must not echo request bppEuiccOtpk", Arrays.equals(otpk, returnedOtpk));
    }

    // -- Negative tests ----------------------------------------------------------

    @Test
    public void testPrepareDownloadRejectsMalformedPayload() {
        Simulator sim = createAndSelect();

        // Malformed BF21: outer length claims more data than provided
        ApduResult res = transmit(sim, fromHex("80E2910005BF21033000"));
        assertEquals("Malformed payload must be rejected", 0x6A80, res.sw);
    }

    @Test
    public void testPrepareDownloadRejectsMissingSmdpSigned2() {
        Simulator sim = createAndSelect();

        // BF21 containing only a signature (no SmdpSigned2 SEQUENCE first)
        // BF21 { 5F37 02 AABB }
        ApduResult res = transmit(sim, fromHex("80E2910008BF21055F370200AA"));
        assertEquals("Missing SmdpSigned2 must be rejected", 0x6A80, res.sw);
    }

    @Test
    public void testPrepareDownloadRejectsTxIdTooLong() {
        Simulator sim = createAndSelect();

        // Build a PrepareDownloadRequest where txId is 17 bytes (exceeds max 16)
        byte[] txId = new byte[17];
        for (int i = 0; i < 17; i++) txId[i] = (byte) i;

        // Manual construction with oversized txId
        // SmdpSigned2: 30 { 80 11 <17 bytes> 01 01 00 }
        byte[] smdpSigned2Body = new byte[2 + 17 + 3];
        int p = 0;
        smdpSigned2Body[p++] = (byte) 0x80;
        smdpSigned2Body[p++] = 0x11; // 17
        System.arraycopy(txId, 0, smdpSigned2Body, p, 17); p += 17;
        smdpSigned2Body[p++] = 0x01;
        smdpSigned2Body[p++] = 0x01;
        smdpSigned2Body[p++] = 0x00;

        byte[] smdpSigned2 = new byte[2 + smdpSigned2Body.length];
        smdpSigned2[0] = 0x30;
        smdpSigned2[1] = (byte) smdpSigned2Body.length;
        System.arraycopy(smdpSigned2Body, 0, smdpSigned2, 2, smdpSigned2Body.length);

        byte[] sigTlv = fromHex("5F370100");
        byte[] certTlv = fromHex("3000");

        int innerLen = smdpSigned2.length + sigTlv.length + certTlv.length;
        byte[] bf21 = new byte[3 + innerLen];
        int q = 0;
        bf21[q++] = (byte) 0xBF;
        bf21[q++] = 0x21;
        bf21[q++] = (byte) innerLen;
        System.arraycopy(smdpSigned2, 0, bf21, q, smdpSigned2.length); q += smdpSigned2.length;
        System.arraycopy(sigTlv,      0, bf21, q, sigTlv.length);      q += sigTlv.length;
        System.arraycopy(certTlv,     0, bf21, q, certTlv.length);

        byte[] apdu = new byte[5 + bf21.length];
        apdu[0] = (byte) 0x80;
        apdu[1] = (byte) 0xE2;
        apdu[2] = (byte) 0x91;
        apdu[3] = 0x00;
        apdu[4] = (byte) bf21.length;
        System.arraycopy(bf21, 0, apdu, 5, bf21.length);

        ApduResult res = transmit(sim, apdu);
        assertEquals("TxId > 16 bytes must be rejected", 0x6A80, res.sw);
    }

    @Test
    public void testPrepareDownloadRejectsNonCanonicalBooleanTrue() {
        Simulator sim = createAndSelect();
        byte[] euiccSignature1 = performAuthenticateServerAndGetEuiccSignature1(sim);

        byte[] txId = fromHex("01020304");
        byte[] smdpSigned2 = fromHex("3009800401020304010101");
        byte[] smdpSig = sign(buildSmdpSignature2Input(smdpSigned2, euiccSignature1));

        byte[] sigTlv = new byte[3 + smdpSig.length];
        sigTlv[0] = 0x5F;
        sigTlv[1] = 0x37;
        sigTlv[2] = (byte) smdpSig.length;
        System.arraycopy(smdpSig, 0, sigTlv, 3, smdpSig.length);

        byte[] certTlv = TEST_SMDP_CERT_DER;
        int innerLen = smdpSigned2.length + sigTlv.length + certTlv.length;
        int bf21LenField = derLenFieldSize(innerLen);
        byte[] bf21 = new byte[2 + bf21LenField + innerLen];
        int q = 0;
        bf21[q++] = (byte) 0xBF;
        bf21[q++] = 0x21;
        q = writeDerLength(bf21, q, innerLen);
        System.arraycopy(smdpSigned2, 0, bf21, q, smdpSigned2.length); q += smdpSigned2.length;
        System.arraycopy(sigTlv, 0, bf21, q, sigTlv.length); q += sigTlv.length;
        System.arraycopy(certTlv, 0, bf21, q, certTlv.length);

        ApduResult res = transmit(sim, buildStoreDataApdu(bf21));
        assertEquals("Non-canonical BOOLEAN TRUE must be rejected", 0x6A80, res.sw);
    }

    @Test
    public void testPrepareDownloadRejectsInvalidHashCcLength() {
        Simulator sim = createAndSelect();
        byte[] euiccSignature1 = performAuthenticateServerAndGetEuiccSignature1(sim);

        byte[] txId = fromHex("0A0B0C0D");
        byte[] smdpSigned2 = fromHex("300980040A0B0C0D010100");
        byte[] smdpSig = sign(buildSmdpSignature2Input(smdpSigned2, euiccSignature1));

        byte[] sigTlv = new byte[3 + smdpSig.length];
        sigTlv[0] = 0x5F;
        sigTlv[1] = 0x37;
        sigTlv[2] = (byte) smdpSig.length;
        System.arraycopy(smdpSig, 0, sigTlv, 3, smdpSig.length);

        byte[] badHashCc = fromHex("0401AA");
        byte[] certTlv = TEST_SMDP_CERT_DER;
        int innerLen = smdpSigned2.length + sigTlv.length + badHashCc.length + certTlv.length;
        int bf21LenField = derLenFieldSize(innerLen);
        byte[] bf21 = new byte[2 + bf21LenField + innerLen];
        int q = 0;
        bf21[q++] = (byte) 0xBF;
        bf21[q++] = 0x21;
        q = writeDerLength(bf21, q, innerLen);
        System.arraycopy(smdpSigned2, 0, bf21, q, smdpSigned2.length); q += smdpSigned2.length;
        System.arraycopy(sigTlv, 0, bf21, q, sigTlv.length); q += sigTlv.length;
        System.arraycopy(badHashCc, 0, bf21, q, badHashCc.length); q += badHashCc.length;
        System.arraycopy(certTlv, 0, bf21, q, certTlv.length);

        ApduResult res = transmit(sim, buildStoreDataApdu(bf21));
        assertEquals("hashCc must be exactly 32 bytes when present", 0x6A80, res.sw);
    }

    // -- Helpers -----------------------------------------------------------------

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

    private static byte[] extractTaggedValue(byte[] data, short tag) {
        for (int i = 0; i < data.length - 1; i++) {
            int currentTag;
            int tagLen;
            if ((data[i] & 0xFF) == ((tag >> 8) & 0xFF) && i + 1 < data.length &&
                    (data[i + 1] & 0xFF) == (tag & 0xFF)) {
                currentTag = tag & 0xFFFF;
                tagLen = 2;
            } else if ((data[i] & 0xFF) == (tag & 0xFF)) {
                currentTag = tag & 0xFF;
                tagLen = 1;
            } else {
                continue;
            }

            int lenPos = i + tagLen;
            if (lenPos >= data.length) {
                return null;
            }
            int len = data[lenPos] & 0xFF;
            int valuePos = lenPos + 1;
            if ((len & 0x80) != 0) {
                int numLenBytes = len & 0x7F;
                if (numLenBytes == 0 || numLenBytes > 2 || valuePos + numLenBytes > data.length) {
                    return null;
                }
                len = 0;
                for (int j = 0; j < numLenBytes; j++) {
                    len = (len << 8) | (data[valuePos + j] & 0xFF);
                }
                valuePos += numLenBytes;
            }
            if (currentTag == (tag & 0xFFFF) && valuePos + len <= data.length) {
                return Arrays.copyOfRange(data, valuePos, valuePos + len);
            }
        }
        return null;
    }
}
