package zk.esim.applet;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
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

	private static final byte[] SECP256R1_FP = {
			(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
			(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF
	};

	private static final byte[] SECP256R1_A = {
			(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
			(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFC
	};

	private static final byte[] SECP256R1_B = {
			(byte) 0x5A, (byte) 0xC6, (byte) 0x35, (byte) 0xD8, (byte) 0xAA, (byte) 0x3A, (byte) 0x93, (byte) 0xE7,
			(byte) 0xB3, (byte) 0xEB, (byte) 0xBD, (byte) 0x55, (byte) 0x76, (byte) 0x98, (byte) 0x86, (byte) 0xBC,
			(byte) 0x65, (byte) 0x1D, (byte) 0x06, (byte) 0xB0, (byte) 0xCC, (byte) 0x53, (byte) 0xB0, (byte) 0xF6,
			(byte) 0x3B, (byte) 0xCE, (byte) 0x3C, (byte) 0x3E, (byte) 0x27, (byte) 0xD2, (byte) 0x60, (byte) 0x4B
	};

	private static final byte[] SECP256R1_G = {
			(byte) 0x04, (byte) 0x6B, (byte) 0x17, (byte) 0xD1, (byte) 0xF2, (byte) 0xE1, (byte) 0x2C, (byte) 0x42,
			(byte) 0x47, (byte) 0xF8, (byte) 0xBC, (byte) 0xE6, (byte) 0xE5, (byte) 0x63, (byte) 0xA4, (byte) 0x40,
			(byte) 0xF2, (byte) 0x77, (byte) 0x03, (byte) 0x7D, (byte) 0x81, (byte) 0x2D, (byte) 0xEB, (byte) 0x33,
			(byte) 0xA0, (byte) 0xF4, (byte) 0xA1, (byte) 0x39, (byte) 0x45, (byte) 0xD8, (byte) 0x98, (byte) 0xC2,
			(byte) 0x96, (byte) 0x4F, (byte) 0xE3, (byte) 0x42, (byte) 0xE2, (byte) 0xFE, (byte) 0x1A, (byte) 0x7F,
			(byte) 0x9B, (byte) 0x8E, (byte) 0xE7, (byte) 0xEB, (byte) 0x4A, (byte) 0x7C, (byte) 0x0F, (byte) 0x9E,
			(byte) 0x16, (byte) 0x2B, (byte) 0xCE, (byte) 0x33, (byte) 0x57, (byte) 0x6B, (byte) 0x31, (byte) 0x5E,
			(byte) 0xCE, (byte) 0xCB, (byte) 0xB6, (byte) 0x40, (byte) 0x68, (byte) 0x37, (byte) 0xBF, (byte) 0x51,
			(byte) 0xF5
	};

	private static final byte[] SECP256R1_R = {
			(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
			(byte) 0xBC, (byte) 0xE6, (byte) 0xFA, (byte) 0xAD, (byte) 0xA7, (byte) 0x17, (byte) 0x9E, (byte) 0x84,
			(byte) 0xF3, (byte) 0xB9, (byte) 0xCA, (byte) 0xC2, (byte) 0xFC, (byte) 0x63, (byte) 0x25, (byte) 0x51
	};

	private jcmathlib.ResourceManager rm;
	private jcmathlib.ECCurve curve;
	private final RandomData rnd;
	private final MessageDigest sha384;
	private Signature signature;
	private KeyAgreement ka;

	private KeyPair kp;
	private PublicKey uPk;
	private PrivateKey uSk;

	private ECPublicKey smdpPk;
	private ECPublicKey mnoPk;
	private ECPublicKey leakPk;

	private final byte[] rSeedBuf;
	private final byte[] rBuf;
	private final byte[] sharedSecret;
	private final byte[] sessionKey;
	private final byte[] sigEIDBuf;
	private boolean asymReady;
	private boolean zkReady;

	public Crypto() {
		rnd = createRandom();
		if (rnd == null) {
			ISOException.throwIt(SW_CRYPTO_UNAVAILABLE);
		}

		sha384 = MessageDigest.getInstance(MessageDigest.ALG_SHA_384, false);
		asymReady = false;
		zkReady = false;

		rSeedBuf = new byte[DEFAULT_RANDOM_SEED.length];
		Util.arrayCopyNonAtomic(DEFAULT_RANDOM_SEED, (short) 0, rSeedBuf, (short) 0, (short) DEFAULT_RANDOM_SEED.length);
		rBuf = new byte[SCALAR_LEN];
		sharedSecret = new byte[POINT_LEN];
		sessionKey = new byte[SCALAR_LEN];
		sigEIDBuf = new byte[80];
	}

	public void hashEidToPid(byte[] eid, byte[] pidOut) {
		sha384.reset();
		sha384.doFinal(eid, (short) 0, (short) eid.length, pidOut, (short) 0);
	}

	public void fillRandom(byte[] out, short off, short len) {
		fillRandomData(rnd, out, off, len);
	}

	public void generateRandom(byte[] seedBytes, byte[] out) {
		rnd.setSeed(seedBytes, (short) 0, (short) seedBytes.length);
		fillRandomData(rnd, out, (short) 0, (short) out.length);
	}

	public short exportPublicKey(byte[] out, short off) {
		ensureAsymmetricReady();
		return ((ECPublicKey) uPk).getW(out, off);
	}

	public short sign(byte[] msg, short msgOff, short msgLen, byte[] sigOut, short sigOff) {
		ensureAsymmetricReady();
		signature.init(uSk, Signature.MODE_SIGN);
		return signature.sign(msg, msgOff, msgLen, sigOut, sigOff);
	}

	public boolean verifySignature(APDU apdu, byte[] pubKeyBuf, byte[] msgBuf, byte[] sigBuf) {
		ensureAsymmetricReady();
		byte[] buf = apdu.getBuffer();
		apdu.setIncomingAndReceive();
		short offset = ISO7816.OFFSET_CDATA;

		short pubKeyLen = (short) (buf[offset] & 0xFF);
		offset++;
		Util.arrayCopy(buf, offset, pubKeyBuf, (short) 0, pubKeyLen);
		smdpPk.setW(pubKeyBuf, (short) 0, pubKeyLen);
		offset += pubKeyLen;

		short msgLen = Util.getShort(buf, offset);
		offset += 2;
		Util.arrayCopy(buf, offset, msgBuf, (short) 0, msgLen);
		offset += msgLen;

		short sigLen = (short) (buf[offset] & 0xFF);
		offset++;
		Util.arrayCopy(buf, offset, sigBuf, (short) 0, sigLen);

		signature.init(smdpPk, Signature.MODE_VERIFY);
		return signature.verify(msgBuf, (short) 0, msgLen, sigBuf, (short) 0, sigLen);
	}

	public byte[] encryptEid(byte[] eid) {
		AESKey aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
		byte[] keyBytes = new byte[16];

		fillRandomData(rnd, keyBytes, (short) 0, (short) keyBytes.length);
		aesKey.setKey(keyBytes, (short) 0);

		Cipher cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
		cipher.init(aesKey, Cipher.MODE_ENCRYPT);
		cipher.doFinal(eid, (short) 0, (short) eid.length, keyBytes, (short) 0);
		return keyBytes;
	}

	public short deriveSessionKey(ECPublicKey peerPk, byte[] sharedOut, short sharedOff, byte[] sessionOut, short sessionOff) {
		ensureAsymmetricReady();
		ka.init(uSk);
		byte[] peerBuf = new byte[POINT_LEN];
		short peerLen = peerPk.getW(peerBuf, (short) 0);
		short sharedLen = ka.generateSecret(peerBuf, (short) 0, peerLen, sharedOut, sharedOff);

		MessageDigest sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
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
		byte[] temp = new byte[512];
		short off = 0;

		Util.arrayCopy(serialBuf, (short) 0, temp, off, serialLen);
		off += serialLen;
		Util.arrayCopy(sigAlgBuf, (short) 0, temp, off, sigAlgLen);
		off += sigAlgLen;
		Util.arrayCopy(issuerBuf, (short) 0, temp, off, issuerLen);
		off += issuerLen;
		Util.arrayCopy(validityBuf, (short) 0, temp, off, validityLen);
		off += validityLen;
		Util.arrayCopy(subjectBuf, (short) 0, temp, off, subjectLen);
		off += subjectLen;
		Util.arrayCopy(spkiBuf, (short) 0, temp, off, spkiLen);
		off += spkiLen;

		return wrapSequence(temp, off, out, offset);
	}

	public boolean verifyCertificate(ECPublicKey signerPk,
									 byte[] serialBuf, short serialLen,
									 byte[] sigAlgBuf, short sigAlgLen,
									 byte[] issuerBuf, short issuerLen,
									 byte[] validityBuf, short validityLen,
									 byte[] subjectBuf, short subjectLen,
									 byte[] spkiBuf, short spkiLen,
									 byte[] certSigBuf, short certSigLen) {
		byte[] cert = new byte[512];
		short tbsLen = buildCertificate(
				serialBuf, serialLen,
				sigAlgBuf, sigAlgLen,
				issuerBuf, issuerLen,
				validityBuf, validityLen,
				subjectBuf, subjectLen,
				spkiBuf, spkiLen,
				cert, (short) 0);

		ensureAsymmetricReady();
		signature.init(signerPk, Signature.MODE_VERIFY);
		return signature.verify(cert, (short) 0, tbsLen, certSigBuf, (short) 0, certSigLen);
	}

	public short generateSigEid(byte[] eid, byte[] outSig, short outOff) {
		ensureAsymmetricReady();
		signature.init(uSk, Signature.MODE_SIGN);

		MessageDigest sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
		byte[] digest = new byte[SCALAR_LEN];
		sha256.doFinal(eid, (short) 0, (short) eid.length, digest, (short) 0);

		short sigLen = signature.sign(digest, (short) 0, (short) digest.length, outSig, outOff);
		Util.arrayCopyNonAtomic(outSig, outOff, sigEIDBuf, (short) 0, sigLen);
		return sigLen;
	}

	public short generateZkp(byte[] eid,
							 byte[] pid,
							 byte[] nonce,
							 byte[] outS, short outOff,
							 byte[] outT, short outTOff) {
		ensureZkReady();
		jcmathlib.BigNat wScalar = new jcmathlib.BigNat(SCALAR_LEN, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);
		jcmathlib.BigNat xScalar = new jcmathlib.BigNat(SCALAR_LEN, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);
		generateWitness(eid, wScalar);
		generateX(pid, nonce, xScalar);

		jcmathlib.BigNat r = new jcmathlib.BigNat(SCALAR_LEN, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);
		generateRandomScalar(r);

		jcmathlib.ECPoint tPoint = new jcmathlib.ECPoint(curve);
		tPoint.setW(SECP256R1_G, (short) 0, (short) SECP256R1_G.length);
		tPoint.multiplication(r);
		short tLen = tPoint.getW(outT, outTOff);

		byte[] xBuf = new byte[SCALAR_LEN];
		xScalar.copyToByteArray(xBuf, (short) 0);

		byte[] tBuf = new byte[POINT_LEN];
		Util.arrayCopyNonAtomic(outT, outTOff, tBuf, (short) 0, tLen);

		jcmathlib.BigNat c = new jcmathlib.BigNat(SCALAR_LEN, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);
		computeChallenge(xBuf, SCALAR_LEN, tBuf, tLen, c);

		jcmathlib.BigNat s = new jcmathlib.BigNat(SCALAR_LEN, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);
		computeResponse(r, c, wScalar, s);
		s.copyToByteArray(outS, outOff);
		return tLen;
	}

	public void setSmdpPublicKey(byte[] w, short off, short len) {
		ensureAsymmetricReady();
		smdpPk.setW(w, off, len);
	}

	public ECPublicKey getSmdpPublicKey() {
		ensureAsymmetricReady();
		return smdpPk;
	}

	public ECPublicKey getDevicePublicKey() {
		ensureAsymmetricReady();
		return (ECPublicKey) uPk;
	}

	public PrivateKey getDevicePrivateKey() {
		ensureAsymmetricReady();
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

		if (sigEIDBuf[0] == (byte) 0x00) {
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
		sha384.reset();
		sha384.doFinal(data, (short) 0, (short) data.length, hashBuf, (short) 0);

		out.fromByteArray(hashBuf, (short) 0, SCALAR_LEN);
		out.mod(curve.rBN);
	}

	private jcmathlib.ECPoint hashToCurve(byte[] msg) {
		short msgLen = (short) msg.length;
		byte[] hashBuf = new byte[SCALAR_LEN];
		sha384.reset();
		sha384.doFinal(msg, (short) 0, msgLen, hashBuf, (short) 0);

		jcmathlib.BigNat x = new jcmathlib.BigNat(SCALAR_LEN, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);
		x.fromByteArray(hashBuf, (short) 0, (short) hashBuf.length);
		x.mod(curve.pBN);

		jcmathlib.BigNat y = new jcmathlib.BigNat(SCALAR_LEN, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);
		jcmathlib.BigNat tmp = new jcmathlib.BigNat(SCALAR_LEN, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);
		jcmathlib.BigNat ax = new jcmathlib.BigNat(SCALAR_LEN, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);
		jcmathlib.BigNat exp3 = new jcmathlib.BigNat((short) 1, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);
		exp3.fromByteArray(new byte[] { (byte) 0x03 }, (short) 0, (short) 1);

		byte[] wBuf = new byte[POINT_LEN];
		wBuf[0] = (byte) 0x04;

		while (true) {
			tmp.copy(x);
			tmp.modExp(exp3, curve.pBN);

			ax.copy(x);
			ax.modMult(curve.aBN, curve.pBN);

			tmp.modAdd(ax, curve.pBN);
			tmp.modAdd(curve.bBN, curve.pBN);

			y.copy(tmp);
			if (y.isQuadraticResidue(curve.pBN)) {
				jcmathlib.ECPoint point = new jcmathlib.ECPoint(curve);
				x.copyToByteArray(wBuf, (short) 1);
				y.copyToByteArray(wBuf, (short) 33);
				point.setW(wBuf, (short) 0, POINT_LEN);
				return point;
			}

			x.increment();
			x.mod(curve.pBN);
		}
	}

	private void generateRandomScalar(jcmathlib.BigNat r) {
		byte[] tmp = new byte[SCALAR_LEN];
		fillRandomData(rnd, tmp, (short) 0, SCALAR_LEN);

		r.fromByteArray(tmp, (short) 0, SCALAR_LEN);
		r.mod(curve.rBN);
	}

	@SuppressWarnings("deprecation")
	private static RandomData createRandom() {
		final byte[] algs = new byte[] {
				RandomData.ALG_SECURE_RANDOM,
				RandomData.ALG_PSEUDO_RANDOM
		};

		byte i = 0;
		while (i < (byte) algs.length) {
			try {
				return RandomData.getInstance(algs[i]);
			} catch (Throwable ignored) {
				i++;
			}
		}
		return null;
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

		sha384.reset();
		sha384.doFinal(input, (short) 0, (short) input.length, hashBuf, (short) 0);

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

	private void ensureAsymmetricReady() {
		if (asymReady) {
			return;
		}

		try {
			signature = Signature.getInstance(Signature.ALG_ECDSA_SHA, false);
			ka = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);

			kp = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
			kp.genKeyPair();
			uSk = kp.getPrivate();
			uPk = kp.getPublic();

			smdpPk = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);
			mnoPk = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);
			leakPk = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);

			asymReady = true;
		} catch (Throwable t) {
			ISOException.throwIt(SW_CRYPTO_UNAVAILABLE);
		}
	}

	private void ensureZkReady() {
		if (zkReady) {
			return;
		}

		ensureAsymmetricReady();
		try {
			rm = new jcmathlib.ResourceManager((short) 512);
			curve = new jcmathlib.ECCurve(SECP256R1_FP, SECP256R1_A, SECP256R1_B, SECP256R1_G, SECP256R1_R, (short) 1, rm);
			zkReady = true;
		} catch (Throwable t) {
			ISOException.throwIt(SW_CRYPTO_UNAVAILABLE);
		}
	}
}
