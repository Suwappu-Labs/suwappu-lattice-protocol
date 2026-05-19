# Release Engineering

How to cut a new release of the Entanglement Transfer Protocol.

The release pipeline is fully automated by
[`.github/workflows/release.yml`](../.github/workflows/release.yml) and
runs on the push of an annotated `v*.*.*` tag. The artifacts it
produces are signed by Sigstore (SLSA build provenance) and uploaded
to the GitHub Releases page.

## When to cut a release

- A new contract version is deployed on testnet or mainnet (e.g.
  `v5.0.0` for the GSX Testnet LTPAnchorRegistry v5 deployment).
- A new SDK surface lands that downstream consumers will pin to.
- A security fix that consumers should adopt by version (e.g. an
  LTP-A finding remediation).
- A breaking change announced via [`STABILITY_PROMISES.md`](STABILITY_PROMISES.md).

Documentation-only changes do not need a release tag.

## The checklist

1. **Confirm CI is green on `main`.**
2. **Bump `pyproject.toml` version** to the new semver.
3. **Update `CHANGELOG.md`:**
   - Promote everything under `## [Unreleased]` into a new
     `## [X.Y.Z] - YYYY-MM-DD` section.
   - Leave a fresh empty `## [Unreleased]` heading.
   - Mark breaking changes inline with `**[BREAKING]**`.
4. **Open a PR titled `release: vX.Y.Z`** with the version bump +
   CHANGELOG update. CI runs the dry-run release workflow to confirm
   the pipeline accepts the inputs.
5. **Merge the PR** to `main`.
6. **Tag the merge commit:**
   ```bash
   git checkout main
   git pull --no-rebase origin main
   git tag -a vX.Y.Z -m "Release vX.Y.Z"
   git push origin vX.Y.Z
   ```
7. **Watch the `Release` workflow run.** When it finishes,
   `gh release view vX.Y.Z` shows the artifacts:
   - `ltp-X.Y.Z.tar.gz` (sdist)
   - `ltp-X.Y.Z-py3-none-any.whl`
   - `contracts-abi.tar.gz` (when applicable)
   - SLSA attestation (`*.intoto.jsonl` linked from the Release page)
8. **Verify the SLSA provenance:**
   ```bash
   gh attestation verify ltp-X.Y.Z.tar.gz \
     --owner GlobalSettlementNetwork
   ```
9. **Announce the release** in the operator runbook channel and link
   the Release page.

## GPG signing (deferred)

The pipeline does not yet sign artifacts with a GPG key. When the
operations team provisions a release-signing key, add the secret
`RELEASE_GPG_PRIVATE_KEY` to the repository and extend the
release workflow with a `gpg --armor --detach-sign` step before
the `Stage release artifacts` step.

The release-signing key MUST live in the hardware HSM that backs
operator identities — see [`OPERATOR_RUNBOOK.md`](OPERATOR_RUNBOOK.md)
§13 for HSM provisioning.

## License blocker

`pyproject.toml` declares the package license as MIT while the
repository `LICENSE` file is Elastic License 2.0. This is tracked as
Linear `GLO-785`. Until that mismatch resolves, **the release
pipeline produces artifacts but does NOT publish to PyPI** — `python
-m twine upload` is not part of the workflow. The team must pick one
license and update both files before PyPI publication can be
considered.

## Pre-release tags

The workflow detects a hyphen in the tag (e.g. `v6.0.0-rc.1`) and
marks the Release as `prerelease = true` automatically. Pre-release
tags are the right way to ship a release candidate for testnet
validation before promoting to mainnet.

## Rolling back

GitHub Releases are immutable for the artifacts they reference. If a
release ships with a critical defect:

1. Cut a new patch release with the fix.
2. Mark the bad release as `gh release edit vX.Y.Z --draft=false
   --prerelease=true` and add a one-line "DO NOT USE — superseded by
   vX.Y.Z+1" note in the Release description.
3. Open an incident in `docs/security/campaigns/` if the defect has a
   security impact.

## Container images

Every `v*.*.*` tag push also fires
[`.github/workflows/container-build.yml`](../.github/workflows/container-build.yml),
which builds and pushes the two LTP service images to ECR:

| Image | Dockerfile | What's inside |
|---|---|---|
| `etp-node`    | [`deploy/Dockerfile.node`](../deploy/Dockerfile.node)       | Python 3.12 + `pyproject.toml`'s `[production]` extra (pqcrypto, pynacl, zfec, blake3, py_ecc). Entrypoint: `python -m src.ltp.node.main` |
| `etp-gateway` | [`deploy/Dockerfile.gateway`](../deploy/Dockerfile.gateway) | Same baseline + `[gateway,chain]` extras (fastapi, uvicorn, httpx, web3) |

Both are:

- Multi-arch (`linux/amd64` + `linux/arm64`)
- Tagged `:X.Y.Z` and `:sha-<12-char>`
- **Tag-immutable** (per `infra/terraform/modules/ecr` —
  `image_tag_mutability = "IMMUTABLE"`)
- Attested via [`actions/attest-build-provenance`](https://github.com/actions/attest-build-provenance)
  (SLSA Level 3 build provenance attestation, pushed to the registry)
- Signed via [`cosign`](https://docs.sigstore.dev/cosign/) keyless OIDC
  (Sigstore Fulcio + Rekor transparency log)

### Pulling and verifying

```bash
# Pull (after AWS_ECR_ROLE_ARN is set and the operator has docker login'd to ECR)
docker pull "${ECR_REGISTRY}/etp-node:${VERSION}"

# Verify the SLSA attestation
gh attestation verify \
    "oci://${ECR_REGISTRY}/etp-node@${DIGEST}" \
    --owner GlobalSettlementNetwork

# Verify the cosign signature
cosign verify \
    --certificate-identity-regexp "https://github.com/GlobalSettlementNetwork/gsx-lattice-protocol/.+" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    "${ECR_REGISTRY}/etp-node@${DIGEST}"
```

### Repo-level config the workflow needs

| Setting | Where | Why |
|---|---|---|
| `vars.AWS_ECR_ROLE_ARN` | repo or org Variables | Role the OIDC token assumes. Must trust `repo:GlobalSettlementNetwork/gsx-lattice-protocol:ref:refs/tags/v*.*.*` |
| ECR repos `etp-node` and `etp-gateway` | `infra/terraform/modules/ecr` | Created with `image_tag_mutability = IMMUTABLE`. Apply before the first tag push |

Until `vars.AWS_ECR_ROLE_ARN` is set, the workflow runs as a **build-only
dry-run** — it validates the Dockerfiles compile but never pushes. This
matches the same posture as the rest of the AWS-side work: code lands;
broadcasts wait for governance.

## Cross-references

- [`CHANGELOG.md`](../CHANGELOG.md) — the canonical version history.
- [`docs/STABILITY_PROMISES.md`](STABILITY_PROMISES.md) — the
  compatibility contract that the version number commits to.
- [`docs/OPERATOR_RUNBOOK.md`](OPERATOR_RUNBOOK.md) §13 — operator
  upgrade procedures triggered by a new release.
- [`.github/workflows/release.yml`](../.github/workflows/release.yml)
  — the workflow itself.
- [`.github/workflows/release-dry-run.yml`](../.github/workflows/release-dry-run.yml)
  — the PR validator.
- [`.github/workflows/container-build.yml`](../.github/workflows/container-build.yml)
  — the container image builder.
- [`scripts/extract_changelog.py`](../scripts/extract_changelog.py)
  — the changelog parser the workflow uses.
