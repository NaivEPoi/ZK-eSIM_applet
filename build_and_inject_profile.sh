#!/usr/bin/env bash
set -euo pipefail

# Build JavaCard CAP with Ant and inject it into a SAIP profile.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Use local Java 17 for this build flow.
if [[ -d "/usr/lib/jvm/java-17-openjdk-amd64" ]]; then
    export JAVA_HOME="/usr/lib/jvm/java-17-openjdk-amd64"
    export PATH="${JAVA_HOME}/bin:${PATH}"
else
    echo "ERROR: Java 17 not found at /usr/lib/jvm/java-17-openjdk-amd64" >&2
    exit 1
fi

BASE_PROFILE="${BASE_PROFILE:-${REPO_ROOT}/smdpp-data/upp/TS48V1-A-UNIQUE.der}"
CAP_FILE="${CAP_FILE:-${SCRIPT_DIR}/dist/ZkEsimHelloApplet.cap}"
OUTPUT_DIR="${OUTPUT_DIR:-${SCRIPT_DIR}/output}"
JCKIT_DIR="${JCKIT_DIR:-${SCRIPT_DIR}/ext/sdks/jc320v25.1_kit}"

# JavaCard/SAIP identity parameters.
LOAD_PACKAGE_AID="${LOAD_PACKAGE_AID:-D07002CA44}"
CLASS_AID="${CLASS_AID:-D07002CA44900101}"
INSTANCE_AID="${INSTANCE_AID:-D07002CA44900101}"
MATCHING_ID="${MATCHING_ID:-zkesimTest}"

INSTALL_TO_SMDPP_UPP="${INSTALL_TO_SMDPP_UPP:-0}"

mkdir -p "${OUTPUT_DIR}"
TMP_PROFILE="${OUTPUT_DIR}/${MATCHING_ID}.tmp.der"
FINAL_PROFILE="${OUTPUT_DIR}/${MATCHING_ID}.der"

if [[ ! -f "${BASE_PROFILE}" ]]; then
    echo "ERROR: Base profile not found: ${BASE_PROFILE}" >&2
    exit 1
fi

if [[ ! -d "${JCKIT_DIR}" ]]; then
    echo "ERROR: JavaCard SDK not found: ${JCKIT_DIR}" >&2
    exit 1
fi

echo "[1/5] Building CAP with Ant..."
(
    cd "${SCRIPT_DIR}"
    ant -Djckit="${JCKIT_DIR}" dist
)

if [[ ! -f "${CAP_FILE}" ]]; then
    echo "ERROR: CAP output not found: ${CAP_FILE}" >&2
    exit 1
fi

echo "[2/5] Inserting application load package into base profile..."
PYTHONPATH="${REPO_ROOT}" python3 "${REPO_ROOT}/contrib/saip-tool.py" \
    "${BASE_PROFILE}" add-app \
    --output-file "${TMP_PROFILE}" \
    --applet-file "${CAP_FILE}" \
    --aid "${LOAD_PACKAGE_AID}"

echo "[3/5] Adding application instance..."
PYTHONPATH="${REPO_ROOT}" python3 "${REPO_ROOT}/contrib/saip-tool.py" \
    "${TMP_PROFILE}" add-app-inst \
    --output-file "${FINAL_PROFILE}" \
    --aid "${LOAD_PACKAGE_AID}" \
    --class-aid "${CLASS_AID}" \
    --inst-aid "${INSTANCE_AID}" \
    --app-privileges "00" \
    --app-spec-pars "00" \
    --uicc-toolkit-app-spec-pars "01001505000000000000000000000000"

echo "[4/5] Validating resulting profile structure..."
PYTHONPATH="${REPO_ROOT}" python3 "${REPO_ROOT}/contrib/saip-tool.py" \
    "${FINAL_PROFILE}" check

echo "[5/5] Printing applet details in final profile..."
PYTHONPATH="${REPO_ROOT}" python3 "${REPO_ROOT}/contrib/saip-tool.py" \
    "${FINAL_PROFILE}" info --apps

rm -f "${TMP_PROFILE}"

echo "Created profile: ${FINAL_PROFILE}"

if [[ "${INSTALL_TO_SMDPP_UPP}" == "1" ]]; then
    DEST="${REPO_ROOT}/smdpp-data/upp/${MATCHING_ID}.der"
    cp -f "${FINAL_PROFILE}" "${DEST}"
    echo "Installed for osmo-smdpp matchingId lookup: ${DEST}"
fi
