# ZK eSIM Hello Applet (Ant Build)

This project contains a minimal JavaCard applet for sysmoEUICC-style eSIM workflows.

- Build system: Ant + ant-javacard (XML build)
- Applet behavior: responds to APDU `00 90 00 00 00`
- Response payload: `hello-world`
- Scope: all applet build artifacts stay in this directory

## Project layout

- `build.xml`: CAP build definition (Ant)
- `src/zk/esim/applet/HelloWorldApplet.java`: applet source
- `build_and_inject_profile.sh`: build CAP + inject into SAIP profile
- `dist/ZkEsimHelloApplet.cap`: generated CAP (after build)

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
bash build_and_inject_profile.sh
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
bash build_and_inject_profile.sh
```

## Example APDU

- Command (original): `00 90 00 00 00`
- Command (T=0-safe fallback): `80 10 00 00 00`
- Response data: `68 65 6c 6c 6f 2d 77 6f 72 6c 64`
- Status: `90 00`

Unsupported APDU parameters return ISO7816 status words (`6E00`, `6D00`, `6A86`, or `6700`).

## Send APDU from pySim-shell

From the repository root, start pySim-shell (adjust transport arguments for your setup):

```bash
python3 ../../pySim-shell.py -p 0
```

Inside pySim-shell, send these commands:

```text
# Select the applet instance AID (D07002CA44900101)
apdu --expect-sw 9000 00A4040008D07002CA44900101

# Send hello command (original form)
apdu --expect-sw 9000 0090000000

# If your reader/card uses T=0 and INS=90 causes transport errors, use:
apdu --expect-sw 9000 8010000000
```

Expected response data for the hello command:

```text
68656c6c6f2d776f726c64
```

That hex value is ASCII `hello-world`.
