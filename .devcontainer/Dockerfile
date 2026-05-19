# LTP devcontainer. Pinned to Python 3.12 to match the CI pin
# (contracts.yml, docs.yml, release.yml all use python-version: "3.12").
#
# Foundry is installed via `foundryup` in postCreate.sh, NOT here — that
# way the binary always tracks the version recorded in
# contracts/foundry.toml without an image rebuild.

FROM mcr.microsoft.com/devcontainers/python:1-3.12

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
        jq \
 && rm -rf /var/lib/apt/lists/*

# `just` — the developer command runner. Debian packages lag upstream,
# so install from the official binary release.
RUN curl --proto '=https' --tlsv1.2 -sSf https://just.systems/install.sh \
      | bash -s -- --to /usr/local/bin
