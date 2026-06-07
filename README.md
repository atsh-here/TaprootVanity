# TaprootVanity

TaprootVanity is a Bitcoin mainnet `bc1p...` Taproot vanity-address generator with a
correct BIP341 TapTweak implementation and an optional CUDA batch front-end.

## Security model

- The client supplies the seed material.
- Candidate private keys are deterministically derived as
  `SHA256("TaprootVanity/seed-v1" || seed || counter || round)` and are accepted only
  when `1 <= key < secp256k1_order`.
- Taproot keys are derived using BIP340/BIP341 x-only semantics: odd-Y internal keys are
  negated before applying `TaggedHash("TapTweak", internal_xonly_pubkey)`.
- The self-test validates the lowest private key vector supplied in the task, including
  internal x-only public key, TapTweak scalar, tweaked private key, tweaked x-only output
  key, and Bech32m P2TR address.

## Build

CPU reference build:

```bash
cmake -S . -B build
cmake --build build -j
```

Optional CUDA build, on a machine with the CUDA toolkit installed:

```bash
cmake -S . -B build-cuda -DENABLE_CUDA=ON
cmake --build build-cuda -j
```

The CUDA target uses constant-memory seed broadcast, a 256-thread launch bound, four
candidate derivations per thread, unrolled SHA-256 rounds, and pinned-size batches. The
current CUDA executable performs GPU-parallel seed-to-private-key derivation and then
uses the audited CPU Taproot derivation to validate and print matching addresses. This
keeps the security-critical Taproot math identical to the self-tested reference path
while still offloading the embarrassingly parallel candidate stream.

## Usage

Run the correctness vector:

```bash
# From the repository root after the CPU build:
./build/taproot-vanity --self-test

# Or, if you configured only build-cuda and are still in build-cuda/:
./taproot-vanity --self-test
```

Derive a known key:

```bash
# From the repository root:
./build/taproot-vanity --key 0000000000000000000000000000000000000000000000000000000000000001

# Or from build-cuda/:
./taproot-vanity --key 0000000000000000000000000000000000000000000000000000000000000001
```

Search on CPU:

```bash
./build/taproot-vanity --search bc1pexample "client supplied high entropy seed" 1000000
```

Search with CUDA:

```bash
# From the repository root:
./build-cuda/taproot-vanity-cuda bc1pp "$(openssl rand -hex 64)" 1000000

# Or from build-cuda/:
./taproot-vanity-cuda bc1pp "$(openssl rand -hex 64)" 1000000
```

Seed arguments that are valid even-length hex strings are decoded to bytes before key
derivation; other strings are used as UTF-8 bytes. Prefixes must start with `bc1p` and
can only contain lowercase Bech32 characters. For example, `bc1pp` asks for one vanity
character after the mandatory `bc1p` prefix and should usually return quickly.
