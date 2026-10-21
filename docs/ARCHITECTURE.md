# Architecture, security, and interview guide

## What the prototype demonstrates

The browser runs an **interview simulator**. It requests a scenario from a loopback-only endpoint; the server acts as a virtual secure tag and reader, then sends the resulting proof through the same verification method exposed by `/api/scan`. The local event store links accepted events with SHA-256. Its integrity indicator recalculates the entire chain from genesis.

The Solidity contract is a separate, deployable anchoring layer. The local demo does not call it. That distinction matters: a hash chain held by one application is useful for demonstrating audit structure, but it is not decentralized consensus.

## Scan protocol

1. The verifier generates a 128-bit random challenge valid for 60 seconds.
2. The tag increments its monotonic counter and computes `HMAC-SHA256(tag_key, canonical_json({uid,counter,challenge,tamper}))`.
3. The reader passes product ID, UID, counter, challenge, tamper bit, and MAC to the verifier over TLS.
4. The verifier consumes the challenge and checks the UID binding, MAC in constant time, and strictly increasing counter.
5. A valid scan updates the product's last counter. Tamper state is an OR latch, so it cannot revert to intact.
6. The verifier appends an event whose SHA-256 digest includes the previous event hash.

The physical chip might implement AES-based authentication rather than HMAC. In that case the reader adapter and verifier must implement the chip's specified protocol; do not assume a generic low-cost UID-only tag can execute this design.

## Threat model

| Threat | Prototype defense | Production requirement |
|---|---|---|
| Copied UID / QR | UID alone fails without MAC | Secure IC with non-exportable key; private provisioning |
| Captured scan replay | One-use challenge and increasing counter | Atomic counter store, TLS, clock sync, device attestation where useful |
| Forged tamper bit | Included in authenticated message | Irreversible physical seal, tag sensor integration, secure reader |
| Database event edit | Hash-chain verification detects direct edits | Publish event roots to an independent EVM chain and monitor them |
| Insider scanner abuse | Local demo has no operator authorization | Distinct manufacturer/inspector roles, audit, HSM, rate limits |
| RFID privacy leakage | Demo uses fictional tags only | Avoid raw UID and PII on chain; random IDs/commitments, retention policy |
| Secret extraction | Demo key never goes to browser/API | Secure manufacturing, KMS/HSM, rotation/revocation plan |

Important limits: a compromised server can rewrite its local chain; an authorized on-chain inspector can still make false attestations. The contract checks authorization, replay counters, and permanent tamper state, while **off-chain verification** establishes that an RFID proof is genuine. A tag can also be transplanted to a counterfeit package unless its physical attachment and tamper mechanism resist removal.

## Contract and optional testnet path

`contracts/PackageRegistry.sol` uses role-gated registration and scan anchoring. It stores only 32-byte package and batch commitments, a counter, tamper/revoked flags, and the latest event hash. It emits scan events with a proof digest. Never publish tag keys, raw patient/customer data, or sensitive supply-chain metadata.

To extend this demo to a local EVM chain or testnet:

1. Compile Solidity `^0.8.24` using Foundry or Hardhat. Run contract tests for unauthorized registration, duplicate IDs, replayed counters, tamper latching, and revocation before deploying.
2. Deploy to a local chain (for example Anvil) first. Configure an RPC URL, contract address, chain ID, and an inspector signer in environment variables; keep private keys out of source control.
3. After the API validates a tag proof, queue an `anchorScan` transaction. Use an outbox table so a failed RPC call cannot silently lose an accepted scan. Store transaction hash, confirmation height, and retry state.
4. Hash stable canonical event bytes and compare the on-chain `latestEventHash`/event log with the local ledger. Show pending, confirmed, and failed anchor states distinctly in the UI.
5. On a public testnet, fund only a limited-purpose signer and wait for confirmations. Monitor reorgs and duplicate submissions. Publish a contract address and explorer link only after a real deployment.

The contract cannot itself verify HMAC without revealing the secret. The chosen trust model uses an authorized inspector service to attest after off-chain verification. A future design could use public-key tags or zero-knowledge proofs, with significant cost and hardware tradeoffs.

## Hardware plan

For a physical version, select a secure NFC/RFID tag capable of documented cryptographic authentication and a compatible reader. Prototype tamper with a conductive loop or breakaway antenna that permanently changes a protected tag state. Provision each tag under a unique key inside a controlled station. The scanner should be an authorized device with TLS to the API. Record reader ID, firmware version, and calibration/provisioning records off chain. Start with a small batch and test repeated reads, power loss, poor signal, opening the seal, and tag removal.

## Interview walkthrough (about 3 minutes)

1. Show the package registry and explain that a copied RFID UID is insufficient.
2. Run **Authentic scan**: a challenge and counter are MACed; the event and ledger height advance.
3. Run **Copied UID**: the correct printed UID with a wrong key fails authentication.
4. Run **Replay old scan**: a valid key with an old counter fails the replay check.
5. Run **Trip tamper seal**, then **Authentic scan**: the state remains tripped.
6. Open the ledger and explain the local-versus-on-chain trust boundary. Show the Solidity registry and describe how an authorized inspector would anchor proof digests to a testnet.

Answer likely questions plainly: *Why blockchain?* Independent anchoring lets multiple parties verify that event commitments were not silently rewritten. *Why not put everything on chain?* Gas, privacy, and tag-secret safety. *Can a UID prevent counterfeits?* No; cryptographic proof and a tamper-resistant physical attachment are required. *What if the scanner is compromised?* Its attestations cannot be trusted; use role separation, protected keys, audit, and revocation.
