<<<<<<< HEAD
# VeritasPack

An interview-ready smart packaging prototype: authenticated RFID scans, persistent tamper state, a verifiable local audit ledger, and a Solidity registry for deployment on an EVM chain.

## Run the demo

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000. The first run seeds three fictional products. Use **Scan authentic**, **Replay old scan**, **Present copied UID**, and **Trip tamper seal** to show the difference between an RFID identifier and cryptographic authentication. **Reset demo** restores the seed data.

Run the core tests with `python -m unittest discover -s tests -v`.

Compile the EVM contract with `npm install` then `npm run contract:compile`. The contract is an optional anchoring path; the default demo requires no wallet, gas, or network.

## Architecture

```text
RFID secure tag / trusted reader
    challenge + monotonic counter + tamper bit + HMAC
                       |
                       v
              Verification API
      nonce expiry, MAC, replay, role checks
                       |
            SQLite local audit chain
             SHA-256 linked records
                       |
            EVM registry (Solidity)
      production anchoring/integration path
                       |
              Public verification UI
```

The runnable demo uses a **virtual trusted reader** and a **single-node, hash-linked local ledger**. It is deliberately labeled as such in the UI. The `contracts/PackageRegistry.sol` contract is the on-chain component, but this local demo does not silently claim that its events are already anchored to a public chain. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for deployment, threat model, hardware mapping, and interview talking points.

## Security boundaries

- A plain RFID UID or QR code can be copied. Authentication requires a tag with a non-exportable key and challenge-response support. The virtual tag models that behavior with HMAC-SHA256; a physical build should use a suitable secure NFC/RFID IC and its documented cryptographic protocol.
- A server-side random challenge expires after 60 seconds and is consumed once. A per-tag counter must strictly increase. Both are included in the MAC.
- Tamper is latched: once authenticated as tripped, later scans cannot mark it intact. A physical seal must make opening visibly or electrically irreversible.
- Secrets are stored only in the local demo database. Production keys belong in secure tag provisioning and an HSM/KMS, never in a browser or public contract.
- The local hash chain detects accidental edits and unsophisticated record modification. It does **not** provide decentralized consensus or resist an attacker who controls the app and database. Production integrity requires anchoring event roots or commitments to the deployed contract, independent observers, and a key management process.

## Resume language

“Built a smart packaging prototype with cryptographic RFID challenge-response, replay-resistant scan verification, irreversible tamper state, a hash-linked audit trail, and a Solidity registry for on-chain anchoring. Demonstrated authentic scans, cloned UID rejection, and replay detection through an interactive dashboard.”
=======
# Block-Chain
>>>>>>> d95adf37a0fdc0a0a73008b2f13fd99d1500fe6e
