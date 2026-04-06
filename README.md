# ZK eSIM Applet (Ant Build)

This project contains a minimal JavaCard applet for sysmoEUICC-style eSIM workflows.

- Build system: Ant + ant-javacard (XML build)
- Applet behavior: handles ES10x transport APDUs (`INS=E2`) with ASN.1 decoding
- Response transport: strict `61 XX` + `GET RESPONSE (00 C0 00 00 Le)` for chunked payload retrieval
- Scope: all applet build artifacts stay in this directory

## Project layout

- `build.xml`: CAP build definition (Ant)
- `src/zk/esim/applet/ZkEsimApplet.java`: applet source
- `build_and_inject_profile.sh`: build CAP + inject into SAIP profile
- `dist/ZkEsimApplet.cap`: generated CAP (after build)

## Prerequisites

- Ant installed (`ant -version`)
- Java installed (JDK/JRE compatible with ant-javacard)
- JavaCard SDK path available (default in `build.xml`: `ext/sdks/jc320v25.1_kit`)
- Python 3 for `contrib/saip-tool.py`

## Build CAP

```bash
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
export PATH=$JAVA_HOME/bin:$PATH
ant dist
```

Optional override for SDK path:

```bash
ant -Djckit=ext/sdks/jc320v25.1_kit dist
```

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

Unsupported APDU class/ins/parameters return ISO7816 status words (for example `6E00`, `6D00`, `6A86`, `6A80`, `6A88`, or `6985` depending on failure mode).

## APDU test assets

The focused jCardSim integration test for GetEUICCChallenge is:

- `test/ZkEsimAppletGetEuiccChallengeTest.java`

## Send APDU from pySim-shell

From the repository root, start pySim-shell (adjust transport arguments for your setup):

```bash
python3 ../../pySim-shell.py -p 0
```

Inside pySim-shell, send these commands:

```text
# Select the applet instance AID (D07002CA44900101)
apdu --expect-sw 9000 00A4040008D07002CA44900101

# Send an ES10x STORE DATA command (example: GetEuiccChallengeRequest BF2E)
apdu 80E2110003BF2E00

# If response status is 61XX, fetch remaining bytes:
apdu 00C0000000
```
