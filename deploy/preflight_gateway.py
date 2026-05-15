#!/usr/bin/env python3
"""
ETP Gateway VM — Pre-flight Check Script

Validates deployment readiness before starting the Gateway VM container.
Run this after sourcing your .env.gateway file:

    source deploy/.env.gateway && python deploy/preflight_gateway.py

Or pass the env file explicitly:

    set -a; source deploy/.env.gateway; set +a
    python deploy/preflight_gateway.py

Exit codes:
    0 — all checks passed, safe to start container
    1 — one or more checks failed, do not start container

Checks performed:
    1. Required env vars set
    2. Source RPC reachable (eth_blockNumber)
    3. Dest RPC reachable (eth_blockNumber)
    4. Operator key format valid (default profile only)
    5. Bridge contract exists on source chain (eth_getCode)
    6. Registry contract live on dest chain (version() call)
    7. FedRAMP High profile checks when ETP_DEPLOYMENT_PROFILE=fedramp-high
"""

import json
import os
import sys
import urllib.parse
import urllib.error
import urllib.request

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

FEDRAMP_HIGH_PROFILE = "fedramp-high"

BASE_REQUIRED_VARS = [
    "ETP_GATEWAY_VM_SOURCE_RPC_URL",
    "ETP_GATEWAY_VM_SOURCE_BRIDGE_CONTRACT",
    "ETP_GATEWAY_VM_DEST_RPC_URL",
    "ETP_GATEWAY_VM_DEST_REGISTRY",
    "ETP_GATEWAY_VM_OPERATOR_KEY",
]

FEDRAMP_REQUIRED_VARS = [
    "ETP_GATEWAY_VM_SOURCE_RPC_URL",
    "ETP_GATEWAY_VM_SOURCE_BRIDGE_CONTRACT",
    "ETP_GATEWAY_VM_DEST_RPC_URL",
    "ETP_GATEWAY_VM_DEST_REGISTRY",
]

PLAINTEXT_OPERATOR_KEY_VARS = [
    "ETP_GATEWAY_VM_OPERATOR_KEY",
    "ETP_ANCHOR_OPERATOR_KEY",
    "OPERATOR_KEY",
]

FEDRAMP_KMS_BACKENDS = {
    "aws",
    "aws-kms",
    "aws-cloudhsm",
    "cloudhsm",
    "pkcs11",
    "azure-keyvault",
    "gcp-cloudkms",
    "hsm",
}

FEDRAMP_HSM_PROVIDERS = {
    "aws-cloudhsm",
    "cloudhsm",
    "pkcs11",
    "thales-luna",
    "entrust-nshield",
    "azure-managed-hsm",
}

INSECURE_MODE_VALUES = {
    "mock",
    "simulated",
    "simulation",
    "disabled",
    "none",
    "test",
    "dev",
}

SECURE_PROVER_MODE_VALUES = {
    "stark",
    "sp1",
    "risc0",
    "network",
    "real",
    "zk",
}

PROVER_MODE_VARS = [
    "ETP_BRIDGE_OPERATOR_ZK_MODE",
    "ETP_GATEWAY_VM_PROVER_MODE",
    "ETP_ZK_PROVER_MODE",
    "SP1_PROVE_MODE",
    "RISC0_PROVE_MODE",
]

DEV_CHAIN_IDS = {
    0,
    5,          # Goerli
    11155111,   # Sepolia
    17000,      # Holesky
    1337,
    31337,
    84532,      # Base Sepolia
    103115120,  # GSX testnet/devnet default
}

DEV_RPC_MARKERS = (
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
    "localstack",
    "anvil",
    "hardhat",
    "sepolia",
    "goerli",
    "holesky",
    "testnet",
    "devnet",
    "replace",
    "example",
    "your-rpc",
)

# version() function selector: keccak256("version()")[0:4]
VERSION_SELECTOR = "0x54fd4d50"

RPC_TIMEOUT = 10  # seconds


# ---------------------------------------------------------------------------
# JSON-RPC helper
# ---------------------------------------------------------------------------

def _rpc_call(url: str, method: str, params: list) -> dict:
    """
    Execute a raw JSON-RPC 2.0 call over HTTP POST.

    Returns the full JSON response dict on success.
    Raises urllib.error.URLError on network failure.
    Raises ValueError if the response is not valid JSON.
    """
    payload = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    }).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with urllib.request.urlopen(req, timeout=RPC_TIMEOUT) as resp:
        return json.loads(resp.read().decode("utf-8"))


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def get_deployment_profile() -> str:
    """Return the configured deployment profile."""
    return os.environ.get("ETP_DEPLOYMENT_PROFILE", "").strip().lower()


def is_fedramp_high_profile(profile: str | None = None) -> bool:
    """Return True when the active deployment profile is FedRAMP High."""
    return (profile or get_deployment_profile()) == FEDRAMP_HIGH_PROFILE


def _env_true(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def check_required_env_vars(profile: str | None = None) -> tuple[bool, str]:
    """Check that required environment variables are set and non-empty."""
    required = FEDRAMP_REQUIRED_VARS if is_fedramp_high_profile(profile) else BASE_REQUIRED_VARS
    missing = [v for v in required if not os.environ.get(v, "").strip()]
    if missing:
        return False, f"missing vars: {', '.join(missing)}"
    return True, f"all {len(required)} required vars present"


def check_source_rpc_reachable(url: str) -> tuple[bool, str]:
    """Verify source RPC endpoint responds to eth_blockNumber."""
    try:
        resp = _rpc_call(url, "eth_blockNumber", [])
        block_hex = resp.get("result", "")
        if not isinstance(block_hex, str) or not block_hex.startswith("0x"):
            return False, f"unexpected result: {block_hex!r}"
        block_num = int(block_hex, 16)
        return True, f"block #{block_num}"
    except urllib.error.URLError as exc:
        return False, f"connection error: {exc.reason}"
    except (ValueError, KeyError) as exc:
        return False, f"bad response: {exc}"


def check_dest_rpc_reachable(url: str) -> tuple[bool, str]:
    """Verify destination RPC endpoint responds to eth_blockNumber."""
    try:
        resp = _rpc_call(url, "eth_blockNumber", [])
        block_hex = resp.get("result", "")
        if not isinstance(block_hex, str) or not block_hex.startswith("0x"):
            return False, f"unexpected result: {block_hex!r}"
        block_num = int(block_hex, 16)
        return True, f"block #{block_num}"
    except urllib.error.URLError as exc:
        return False, f"connection error: {exc.reason}"
    except (ValueError, KeyError) as exc:
        return False, f"bad response: {exc}"


def check_operator_key_format(key: str) -> tuple[bool, str]:
    """Validate operator key is 0x-prefixed and exactly 66 chars (0x + 64 hex)."""
    key = key.strip()
    if not key.startswith("0x"):
        return False, "must start with 0x"
    if len(key) != 66:
        return False, f"expected 66 chars, got {len(key)}"
    hex_part = key[2:]
    if not all(c in "0123456789abcdefABCDEF" for c in hex_part):
        return False, "non-hex characters after 0x"
    return True, "valid 0x + 64-hex format"


def check_fedramp_real_crypto() -> tuple[bool, str]:
    """FedRAMP High requires the real-crypto gate to be explicitly enabled."""
    if not _env_true("ETP_REQUIRE_REAL_CRYPTO"):
        return False, "ETP_REQUIRE_REAL_CRYPTO must be true"
    return True, "real crypto gate enabled"


def check_fedramp_no_plaintext_operator_keys() -> tuple[bool, str]:
    """FedRAMP High must not receive raw private keys through env vars."""
    present = [name for name in PLAINTEXT_OPERATOR_KEY_VARS if os.environ.get(name, "").strip()]
    if present:
        return False, "plaintext key vars must be unset: " + ", ".join(present)
    return True, "no plaintext operator key env vars set"


def check_fedramp_key_management_config() -> tuple[bool, str]:
    """FedRAMP High requires KMS or HSM key references instead of raw keys."""
    kms_backend = os.environ.get("ETP_KMS_BACKEND", "").strip().lower()
    kms_key_ref = (
        os.environ.get("ETP_KMS_KEY_ARN", "").strip()
        or os.environ.get("ETP_GATEWAY_VM_OPERATOR_KMS_KEY_ID", "").strip()
        or os.environ.get("ETP_ANCHOR_OPERATOR_KMS_KEY_ID", "").strip()
    )
    if kms_backend in FEDRAMP_KMS_BACKENDS and kms_key_ref:
        return True, f"KMS configured ({kms_backend})"

    hsm_provider = os.environ.get("ETP_HSM_PROVIDER", "").strip().lower()
    hsm_key_ref = (
        os.environ.get("ETP_HSM_KEY_ID", "").strip()
        or os.environ.get("ETP_HSM_SLOT_LABEL", "").strip()
        or os.environ.get("ETP_HSM_PKCS11_URI", "").strip()
    )
    if hsm_provider in FEDRAMP_HSM_PROVIDERS and hsm_key_ref:
        return True, f"HSM configured ({hsm_provider})"

    return (
        False,
        "configure KMS/HSM: ETP_KMS_BACKEND plus key ARN/ID, or ETP_HSM_PROVIDER plus key reference",
    )


def check_fedramp_mtls_config() -> tuple[bool, str]:
    """FedRAMP High requires mTLS with a certificate, private key, and CA bundle."""
    missing = []
    if not _env_true("ETP_TLS_ENABLED"):
        missing.append("ETP_TLS_ENABLED=true")
    if not _env_true("ETP_TLS_REQUIRE_CLIENT_CERT"):
        missing.append("ETP_TLS_REQUIRE_CLIENT_CERT=true")
    for name in ("ETP_TLS_CERT_PATH", "ETP_TLS_KEY_PATH", "ETP_TLS_CA_PATH"):
        if not os.environ.get(name, "").strip():
            missing.append(name)
    if missing:
        return False, "missing mTLS settings: " + ", ".join(missing)
    return True, "mTLS required and certificate paths configured"


def check_fedramp_siem_export() -> tuple[bool, str]:
    """FedRAMP High requires an audit/SIEM export sink."""
    for name in ("ETP_SIEM_EXPORT_URL", "ETP_AUDIT_SIEM_SINK", "ETP_AUDIT_SIEM_ENDPOINT"):
        if os.environ.get(name, "").strip():
            return True, f"SIEM export configured via {name}"
    return False, "configure ETP_SIEM_EXPORT_URL or ETP_AUDIT_SIEM_SINK"


def check_fedramp_prover_modes() -> tuple[bool, str]:
    """FedRAMP High rejects mock or simulated bridge/prover modes."""
    configured: list[str] = []
    insecure: list[str] = []
    secure: list[str] = []
    for name in PROVER_MODE_VARS:
        value = os.environ.get(name, "").strip().lower()
        if not value:
            continue
        configured.append(f"{name}={value}")
        if value in INSECURE_MODE_VALUES:
            insecure.append(f"{name}={value}")
        if value in SECURE_PROVER_MODE_VALUES:
            secure.append(f"{name}={value}")

    challenge_mode = os.environ.get("ETP_GATEWAY_VM_CHALLENGE_MODE", "").strip().lower()
    if challenge_mode in {"disabled", "mock", "simulated"}:
        insecure.append(f"ETP_GATEWAY_VM_CHALLENGE_MODE={challenge_mode}")

    if insecure:
        return False, "insecure mode configured: " + ", ".join(insecure)
    if not configured:
        return False, "set a real prover/bridge mode, for example ETP_BRIDGE_OPERATOR_ZK_MODE=stark"
    if not secure:
        return False, "no approved real prover mode found: " + ", ".join(configured)
    return True, "real bridge/prover mode configured: " + ", ".join(secure)


def _is_dev_rpc_url(url: str) -> bool:
    lower_url = url.strip().lower()
    parsed = urllib.parse.urlparse(lower_url)
    host = parsed.hostname or lower_url
    haystack = f"{host} {parsed.path} {parsed.netloc}"
    return any(marker in haystack for marker in DEV_RPC_MARKERS)


def _parse_chain_id(name: str) -> int | None:
    value = os.environ.get(name, "").strip()
    if not value:
        return None
    try:
        return int(value, 0)
    except ValueError:
        return None


def check_fedramp_production_networks(source_url: str, dest_url: str) -> tuple[bool, str]:
    """FedRAMP High rejects local/dev RPC endpoints and known test chain IDs."""
    violations = []
    for label, url in (("source", source_url), ("dest", dest_url)):
        if not url.strip():
            violations.append(f"{label} RPC URL not set")
        elif _is_dev_rpc_url(url):
            violations.append(f"{label} RPC URL appears non-production: {url}")

    for name in ("ETP_GATEWAY_VM_SOURCE_CHAIN_ID", "ETP_GATEWAY_VM_DEST_CHAIN_ID"):
        chain_id = _parse_chain_id(name)
        if chain_id is None:
            violations.append(f"{name} must be set to a production chain ID")
        elif chain_id in DEV_CHAIN_IDS:
            violations.append(f"{name}={chain_id} is a known dev/test chain ID")

    if violations:
        return False, "; ".join(violations)
    return True, "production RPC endpoints and chain IDs configured"


def check_fedramp_contract_addresses(
    bridge_contract: str, registry_addr: str
) -> tuple[bool, str]:
    """FedRAMP High requires non-placeholder EVM contract addresses."""
    violations = []
    for label, addr in (
        ("ETP_GATEWAY_VM_SOURCE_BRIDGE_CONTRACT", bridge_contract),
        ("ETP_GATEWAY_VM_DEST_REGISTRY", registry_addr),
    ):
        normalized = addr.strip()
        lower = normalized.lower()
        if not normalized.startswith("0x") or len(normalized) != 42:
            violations.append(f"{label} must be a 20-byte EVM address")
            continue
        if lower == "0x" + "0" * 40:
            violations.append(f"{label} must not be the zero address")
        if "replace" in lower or "deploy" in lower:
            violations.append(f"{label} still looks like a placeholder")
    if violations:
        return False, "; ".join(violations)
    return True, "non-placeholder contract addresses configured"


def check_bridge_contract_exists(source_url: str, contract_addr: str) -> tuple[bool, str]:
    """Verify bridge contract has deployed bytecode on the source chain."""
    try:
        resp = _rpc_call(source_url, "eth_getCode", [contract_addr, "latest"])
        code = resp.get("result", "0x")
        # "0x" means no code (EOA or non-existent), anything longer means deployed
        if not isinstance(code, str) or len(code) <= 2:
            return False, f"no bytecode at {contract_addr} (got {code!r})"
        byte_count = (len(code) - 2) // 2
        return True, f"contract present, {byte_count} bytes of code"
    except urllib.error.URLError as exc:
        return False, f"connection error: {exc.reason}"
    except (ValueError, KeyError) as exc:
        return False, f"bad response: {exc}"


def check_registry_version(dest_url: str, registry_addr: str) -> tuple[bool, str]:
    """Call version() on the destination registry and confirm it returns a uint256."""
    call_obj = {
        "to": registry_addr,
        "data": VERSION_SELECTOR,
    }
    try:
        resp = _rpc_call(dest_url, "eth_call", [call_obj, "latest"])
        result = resp.get("result", "0x")
        if not isinstance(result, str) or result in ("0x", "0x" + "0" * 64):
            # A zeroed-out 32-byte word is suspicious — contract may not implement version()
            if result == "0x" + "0" * 64:
                # Zero is technically valid for version 0, but warn
                return True, "version() returned 0 (contract present, version=0)"
            return False, f"version() returned no data: {result!r}"
        version_int = int(result, 16)
        return True, f"registry live, version={version_int}"
    except urllib.error.URLError as exc:
        return False, f"connection error: {exc.reason}"
    except (ValueError, KeyError) as exc:
        return False, f"bad response: {exc}"


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------

def main() -> int:
    """Run all pre-flight checks and print a checklist. Returns exit code."""
    print("ETP Gateway VM — Pre-flight Checks")
    print("=" * 50)

    results: list[tuple[bool, str, str]] = []  # (passed, label, detail)
    profile = get_deployment_profile()
    if profile:
        print(f"Deployment profile: {profile}")

    # --- Check 1: required env vars ---
    passed, detail = check_required_env_vars(profile)
    results.append((passed, "Required env vars set", detail))

    # Collect env values now (may be empty strings if check 1 failed)
    source_url = os.environ.get("ETP_GATEWAY_VM_SOURCE_RPC_URL", "")
    bridge_contract = os.environ.get("ETP_GATEWAY_VM_SOURCE_BRIDGE_CONTRACT", "")
    dest_url = os.environ.get("ETP_GATEWAY_VM_DEST_RPC_URL", "")
    registry_addr = os.environ.get("ETP_GATEWAY_VM_DEST_REGISTRY", "")
    operator_key = os.environ.get("ETP_GATEWAY_VM_OPERATOR_KEY", "")

    # --- Check 2: source RPC reachable ---
    if source_url:
        passed, detail = check_source_rpc_reachable(source_url)
    else:
        passed, detail = False, "ETP_GATEWAY_VM_SOURCE_RPC_URL not set"
    results.append((passed, "Source RPC reachable", detail))

    # --- Check 3: dest RPC reachable ---
    if dest_url:
        passed, detail = check_dest_rpc_reachable(dest_url)
    else:
        passed, detail = False, "ETP_GATEWAY_VM_DEST_RPC_URL not set"
    results.append((passed, "Dest RPC reachable", detail))

    if is_fedramp_high_profile(profile):
        fedramp_checks = [
            ("FedRAMP real crypto gate", check_fedramp_real_crypto()),
            ("FedRAMP plaintext key block", check_fedramp_no_plaintext_operator_keys()),
            ("FedRAMP KMS/HSM key reference", check_fedramp_key_management_config()),
            ("FedRAMP mTLS configuration", check_fedramp_mtls_config()),
            ("FedRAMP SIEM export", check_fedramp_siem_export()),
            ("FedRAMP bridge/prover mode", check_fedramp_prover_modes()),
            (
                "FedRAMP production networks",
                check_fedramp_production_networks(source_url, dest_url),
            ),
            (
                "FedRAMP contract addresses",
                check_fedramp_contract_addresses(bridge_contract, registry_addr),
            ),
        ]
        for label, (passed, detail) in fedramp_checks:
            results.append((passed, label, detail))
    else:
        # --- Check 4: operator key format ---
        if operator_key:
            passed, detail = check_operator_key_format(operator_key)
        else:
            passed, detail = False, "ETP_GATEWAY_VM_OPERATOR_KEY not set"
        results.append((passed, "Operator key format valid", detail))

    # --- Check 5: bridge contract exists on source ---
    if source_url and bridge_contract:
        passed, detail = check_bridge_contract_exists(source_url, bridge_contract)
    else:
        passed, detail = False, "source URL or bridge contract address not set"
    results.append((passed, "Bridge contract exists on source", detail))

    # --- Check 6: registry version() on dest ---
    if dest_url and registry_addr:
        passed, detail = check_registry_version(dest_url, registry_addr)
    else:
        passed, detail = False, "dest URL or registry address not set"
    results.append((passed, "Registry contract live on dest", detail))

    # --- Print results ---
    print()
    all_passed = True
    for check_passed, label, detail in results:
        symbol = "[+]" if check_passed else "[x]"
        status = "PASS" if check_passed else "FAIL"
        print(f"  {symbol} {status}  {label}")
        print(f"         {detail}")
        if not check_passed:
            all_passed = False

    print()
    if all_passed:
        print("All checks passed. Safe to start the Gateway VM container.")
        return 0
    else:
        fail_count = sum(1 for p, _, _ in results if not p)
        print(f"{fail_count} check(s) failed. Fix the issues above before starting the container.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
