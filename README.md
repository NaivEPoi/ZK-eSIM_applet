# ZK eSIM Applet

This directory contains the JavaCard applet, jCardSim tests, and profile build
helper used by the ZK-eSIM workflow.

- Build system: Ant + ant-javacard
- Target: JavaCard CAP `dist/ZkEsimApplet.cap`
- Transport: ES10 `STORE DATA` APDUs (`INS=E2`)
- Response chaining: proprietary `91xx` plus `GET RESPONSE`

## Project Layout

```text
src/zk/esim/applet/
  ZkEsimApplet.java  Main applet, APDU dispatch, session/BPP state
  Crypto.java        P-256, ECDSA, ECDH, AES/CMAC/KDF, certificates, ZK helpers
  Asn1.java          Strict DER decoder for inbound ES10/ZK command objects
  Apdu.java          STORE DATA reassembly and staged response chaining
  TlvWriter.java     DER/TLV serialization helpers
  ByteArrayUtil.java Byte-array helpers
  jcmathlib.java     Single-file vendored JCMathLib copy

test/
  Asn1Test.java
  CryptoTest.java
  ZkEsimApplet*Test.java

build.xml            Ant build and test targets
build/               Generated classes
dist/                Generated CAP
output/              Generated profile DERs
```

## Supported Commands

`ZkEsimApplet` accepts ES10 transport APDUs with CLA `0x80..0x83` or
`0xC0..0xCF`, `INS=0xE2`, and DER command objects:

| Tag | Command |
|---|---|
| `BF20` | GetEuiccInfo1 |
| `BF2E` | GetEuiccChallenge |
| `BF38` | AuthenticateServer |
| `BF21` | PrepareDownload |
| `BF36` | LoadBoundProfilePackage |
| `BF41` | CancelSession |
| `BF42` | ZKProfileRequest |
| `BF43` | SetEligibilityData |
| `BF44` / `BF45` | RegisterAndIssue |
| `BF46` / `BF47` | CertInit |

The applet also supports `GET DATA` for persisted successful BPP metadata under
tag `DF36`.

## APDU Transport

Inbound ES10 APDUs use SGP.22-style command segmentation:

```text
P1 = 0x11  more command segments follow
P1 = 0x91  final command segment
P2 = block number, starting at 0
```

Outbound responses are staged in chunks up to 256 bytes. If more response bytes
remain, the applet returns proprietary `91xx`. The host must send:

```text
00 C0 00 00 <SW2>
```

This mirrors `61xx` response chaining while avoiding a real-card T=0 runtime
issue seen when throwing `61xx` on transport CLA `0x81`.

## Cryptographic Design

The applet uses P-256 (`secp256r1`) throughout:

- Device/base key material is initialized at install/select time for deterministic
  prototype interoperability.
- RegisterAndIssue uses a blind Schnorr-style credential over the EID.
- CertInit derives `sk_U` from the base seed and PCA session seed, returns
  `pk_U`, and installs `PCert_U`.
- ZKProfileRequest emits a statement with MNO key, LEA key, `pk_U`, challenge,
  pseudonym ID, encrypted EID, and `H(sigma_EID)`, plus a Schnorr proof.
- AuthenticateServer includes an `eligibilityData` extension in `EuiccSigned1`.
- PrepareDownload verifies the SM-DP+ signature over the exact signed bytes.
- LoadBoundProfilePackage derives BSP keys from BF23 ECDH data, processes
  ReplaceSessionKeys, then verifies profile package segments with PPP keys.

BF38 eligibility fields are encoded under `A5` as context tags `80..85`:

```text
80 hashedPseudonym
81 credentialSignature
82 authorizationToken
83 authorizationRoot
84 rootSignature
85 inclusionProof
```

The three MNO signatures are raw 64-byte ECDSA values (`r||s`) on wire.

## Build and Test

```bash
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
export PATH="$JAVA_HOME/bin:$PATH"

ant test
ant dist
```

Targets:

```bash
ant compile
ant compile-tests
ant test
ant dist
ant clean
```

`ant dist` depends on `test`, so it compiles the applet, compiles tests, runs
the jCardSim suite, then produces `dist/ZkEsimApplet.cap`.

Optional SDK override:

```bash
ant -Djckit=ext/sdks/jc320v25.1_kit dist
```

## Test Coverage

The current test suite contains 89 JUnit 4 tests:

| Test class | Count | Coverage |
|---|---:|---|
| `Asn1Test` | 7 | DER decoding and validation |
| `CryptoTest` | 13 | P-256, signatures, ECDH/KDF, BSP, certs, ZK helpers |
| `ZkEsimAppletGetEuiccChallengeTest` | 9 | BF2E |
| `ZkEsimAppletAuthenticateServerTest` | 9 | BF38 |
| `ZkEsimAppletPrepareDownloadTest` | 10 | BF21 |
| `ZkEsimAppletLoadBoundProfilePackageTest` | 19 | BF36, BPP assembly, BSP/PPP verification |
| `ZkEsimAppletCancelSessionTest` | 13 | BF41 |
| `ZkEsimAppletZKProfileRequestTest` | 5 | BF42 |
| `ZkEsimAppletSetEligibilityDataTest` | 4 | BF43 |

The Ant `test` target globs `**/*Test.class`, so new tests are picked up
automatically.

## Build and Inject into Profile

From this directory:

```bash
MATCHING_ID=zkesimTest \
LOAD_PACKAGE_AID=D07002CA44 \
CLASS_AID=D07002CA44900101 \
INSTANCE_AID=D07002CA44900101 \
PYSIM_ROOT=../pysim \
INSTALL_TO_SMDPP_UPP=1 \
  bash build_and_inject_profile.sh
```

Outputs:

```text
dist/ZkEsimApplet.cap
output/zkesimTest.der
../pysim/smdpp-data/upp/zkesimTest.der
```

## AIDs

| Purpose | AID |
|---|---|
| Load package | `D07002CA44` |
| Applet class / instance | `D07002CA44900101` |
| Default ISD-R, used before applet install | `A0000005591010FFFFFFFF8900000100` |

## Manual pySim-shell Smoke

After installing and enabling a profile containing the applet:

```text
apdu --expect-sw 9000 00A4040008D07002CA44900101
apdu 80E2910003BF2E00
```

If the status is `91XX`, fetch the next response chunk:

```text
apdu 00C00000XX
```

where `XX` is the returned `SW2` value.
