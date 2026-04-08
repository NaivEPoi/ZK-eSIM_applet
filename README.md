# ZK eSIM Applet (Ant Build)

This project contains a JavaCard applet for sysmoEUICC-style eSIM workflows with zero-knowledge proof generation.

- Build system: Ant + ant-javacard (XML build)
- Applet behavior: handles ES10x transport APDUs (`INS=E2`) with ASN.1 decoding
- Response transport: strict `61 XX` + `GET RESPONSE (00 C0 00 00 Le)` for chunked payload retrieval
- Scope: all applet build artifacts stay in this directory

## Project layout

```
src/zk/esim/applet/
  ZkEsimApplet.java    — main applet, APDU dispatch, ASN.1 encode/decode
  Crypto.java          — cryptographic service (EC key gen, ECDH, ECDSA, ZK proof)
  jcmathlib.java       — vendored JCMathLib (BigNat, ECPoint, ResourceManager)
test/
  ZkEsimAppletGetEuiccChallengeTest.java
  ZkEsimAppletAuthenticateServerTest.java
  ZkEsimAppletPrepareDownloadTest.java
  ZkEsimAppletLoadBoundProfilePackageTest.java
build.xml              — CAP build definition (Ant)
dist/ZkEsimApplet.cap  — generated CAP (after build)
```

## Cryptographic design

### Asymmetric keys

The applet holds a P-256 (secp256r1) key pair generated at install time:

- `uSk` / `uPk` — device EC private/public key (P-256)
- `smdpPk`, `mnoPk`, `leakPk` — P-256 public keys for SM-DP+, MNO, and leakage-resistance respectively

Key agreement uses ECDH (`ALG_EC_SVDP_DH_PLAIN`). Signing uses ECDSA with SHA-1 (`ALG_ECDSA_SHA`).

### Zero-knowledge proof (`generateZkp`)

The applet implements a Schnorr-style sigma protocol over secp256r1 to prove knowledge of a witness without revealing it:

1. **Witness** `w` — derived deterministically from: EID + device private key + random seed + `sig(EID)` + fresh random bytes, then hashed and reduced mod the curve order `r`.
2. **Challenge input** `x` — derived from: `mnoPk || leakPk || uPk || nonce || pid`, hashed and reduced mod `r`.
3. **Commitment** `T = r·G` — a random scalar `r` multiplied by the base point `G` (EC point multiplication via JCMathLib).
4. **Challenge** `c = H(x || T)` mod `r` — Fiat-Shamir hash.
5. **Response** `s = r + c·w` mod `r`.

The proof `(s, T)` lets a verifier check `s·G == T + c·w·G` without learning `w`.

### JCMathLib integration

`jcmathlib.java` is a single-file vendor copy of [JCMathLib](https://github.com/OpenCryptoProject/JCMathLib). It provides:

- `BigNat` — big integer arithmetic over JavaCard, accelerated via RSA modular exponentiation as a computation engine
- `ECPoint` — EC point arithmetic (addition, scalar multiplication) using hardware or software primitives
- `ResourceManager` — shared scratch buffers and RSA helper objects; constructed with `maxEcLength=256` for P-256

**jCardSim 3.0.5 compatibility note:** jCardSim's BouncyCastle back-end validates RSA key material at `Cipher.init()` time and rejects the all-0xFF placeholder modulus that `ResourceManager` uses to pre-initialize its squaring helper. The fix in `Crypto.initZk()` sets `OperationSupport.RSA_SQ = false` before constructing `ResourceManager`, which disables the RSA squaring path and falls back to software squaring. All other operations (EC point multiplication, modular exponentiation with a real prime modulus) work normally via the RSA exponentiation engine in jCardSim 3.0.5.

## Prerequisites

- Java JDK 17+ (`java -version`)
- Apache Ant (`ant -version`)
- Network access on first build (Ant downloads `ant-javacard.jar`, `junit.jar`, `hamcrest-core.jar`, `jcardsim-3.0.5-*.jar` automatically)
- JavaCard SDK 3.2.0 at `ext/sdks/jc320v25.1_kit`

## Build and test

```bash
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
export PATH=$JAVA_HOME/bin:$PATH

# Compile, run all 26 jCardSim integration tests, then produce the CAP file
ant dist
```

To run tests only (without building the CAP):

```bash
ant test
```

To clean build artifacts:

```bash
ant clean
```

Optional SDK path override:

```bash
ant -Djckit=ext/sdks/jc320v25.1_kit dist
```

## Integration tests

26 jCardSim unit tests cover the four APDU operations:

| Test class | Tests | Operations covered |
|---|---|---|
| `ZkEsimAppletGetEuiccChallengeTest` | 2 | `GetEuiccChallenge` (BF2E) |
| `ZkEsimAppletAuthenticateServerTest` | 8 | `AuthenticateServer` (BF38) |
| `ZkEsimAppletPrepareDownloadTest` | 8 | `PrepareDownload` (BF21) |
| `ZkEsimAppletLoadBoundProfilePackageTest` | 8 | `LoadBoundProfilePackage` (BF36) |

All tests run against jCardSim 3.0.5 and expect `SW=9000` on all success paths.

## Build and inject into profile

```bash
bash build_and_inject_profile.sh /path/to/pysim
```

## Download profile to eSIM (lpac)

After generating the profile, run this command from the directory that contains the `lpac` binary:

```bash
sudo ../lpac/build/src/lpac profile download -s "testsmdpplus1.example.com" -m "zkesimTest"
```

Optional overrides:

```bash
BASE_PROFILE=/path/to/base.der \
MATCHING_ID=MYPROFILE01 \
LOAD_PACKAGE_AID=D07002CA44 \
CLASS_AID=D07002CA44900101 \
INSTANCE_AID=D07002CA44900101 \
OUTPUT_DIR=$(pwd)/output \
JCKIT_DIR=$(pwd)/ext/sdks/jc320v25.1_kit \
bash build_and_inject_profile.sh /path/to/pysim
```

## APDU behavior

- Supported command: `STORE DATA` transport (`INS=E2`)
- CLA: transport class ranges `0x80-0x83` or `0xC0-0xCF`
- P1: `0x91` for more segments, `0x11` for final segment
- P2: block number, incrementing from `0x00`
- On large response payloads, applet returns `61 XX`; host must fetch remainder with `GET RESPONSE (00 C0 00 00 Le)`

Unsupported APDU class/ins/parameters return ISO7816 status words (`6E00`, `6D00`, `6A86`, `6A80`, `6A88`).

## Send APDU from pySim-shell

From the repository root, start pySim-shell (adjust transport arguments for your setup):

```bash
python3 ../../pySim-shell.py -p 0
```

Inside pySim-shell:

```text
# Select the applet instance AID (D07002CA44900101)
apdu --expect-sw 9000 00A4040008D07002CA44900101

# Send an ES10x STORE DATA command (example: GetEuiccChallengeRequest BF2E)
apdu 80E2110003BF2E00

# If response status is 61XX, fetch remaining bytes:
apdu 00C0000000
```
