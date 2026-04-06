# ZK eSIM Applet APDU Test Guide

This guide documents APDU vectors, pySim shell scripts, and jCardSim tests for
`workdir/ZK-eSIM_applet`.

## Coverage

- Positive paths:
  - BF2E GetEuiccChallenge
  - BF21 PrepareDownload
  - BF38 AuthenticateServer (success with matching challenge)
  - BF36 BoundProfilePackage
- Negative paths:
  - Wrong CLA
  - Wrong P1
  - GET RESPONSE without pending data
  - Chaining wrong block number
  - BF38 challenge mismatch (error object)

## Files

- APDU vectors: `apdu-vectors/`
- pySim-shell scripts: `scripts/`
- APDU vector generator: `scripts/generate_apdu_vectors.py`
- pySim TLV-style APDU builder: `scripts/build_apdu_with_pysim.py`
- jCardSim APDU integration tests: `test/ZkEsimAppletApduFlowTest.java`

## Regenerate vectors

```bash
cd workdir/ZK-eSIM_applet
python3 scripts/generate_apdu_vectors.py
```

This guarantees ASN.1 TLV lengths and APDU `Lc` values are encoded correctly.

## Build APDU using pySim euicc helpers

```bash
cd workdir/ZK-eSIM_applet
python3 scripts/build_apdu_with_pysim.py
```

This script follows the same style as `do_get_euicc_challenge` in [pySim/euicc.py](pySim/euicc.py#L412):

- use `GetEuiccChallenge()` TLV object
- encode via `to_tlv()`
- wrap in STORE DATA (`CardApplicationISDR.store_data` APDU pattern)

## Run jCardSim tests

```bash
cd workdir/ZK-eSIM_applet
ant test
```

The APDU integration tests install/select the applet in jCardSim and transmit
raw APDUs with expected status word and payload checks.

## Run pySim scripts

Use these scripts when connected to a transport that reaches the applet:

- `scripts/pysim_smoke.script`
- `scripts/pysim_core_decode.script`
- `scripts/pysim_negative.script`

Example invocation from repository root:

```bash
python3 pySim-shell.py -p 0 -e workdir/ZK-eSIM_applet/scripts/pysim_smoke.script
```

Adjust transport arguments (`-p`, reader, etc.) for your setup.

## Vector-to-test mapping

- `apdu-vectors/bf2e_get_euicc_challenge.apdu`
  - `testStoreDataGetEuiccChallenge`
- `apdu-vectors/bf21_prepare_download_valid.apdu`
  - `testStoreDataPrepareDownloadRequest`
- `apdu-vectors/bf38_authenticate_server_template.apdu`
  - `testStoreDataAuthenticateServerSuccess`
  - `testStoreDataAuthenticateServerChallengeMismatchReturnsErrorObject`
- `apdu-vectors/bf36_bound_profile_package_valid.apdu`
  - `testStoreDataBoundProfilePackageAccepted`
- `apdu-vectors/negative/wrong_cla.apdu`
  - `testWrongClaRejected`
- `apdu-vectors/negative/wrong_p1.apdu`
  - `testWrongP1Rejected`
- `apdu-vectors/negative/chaining_wrong_p2_step1.apdu`
  - `testChainingWrongBlockNumberRejected` (step 1)
- `apdu-vectors/negative/chaining_wrong_p2_step2.apdu`
  - `testChainingWrongBlockNumberRejected` (step 2)

## Notes

- The BF38 success test must use the challenge returned by BF2E in the same
  simulator session.
- A status `61XX` indicates remaining response bytes; use GET RESPONSE
  (`00C0000000`) to fetch pending chunks.
