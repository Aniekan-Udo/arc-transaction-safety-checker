# ArcGuard

Paste a transaction, find out whether it's safe to sign — in plain English.

Built for the [Arc Microgrants](https://dorahacks.io/hackathon/arc-microgrants) program (Circle / DoraHacks).

**Live on Arc mainnet (chain 5042):**
[app](https://arcguard-aniekan-udo.vercel.app/) ·
[API health](https://arcguard.onrender.com/health) ·
[API docs](https://arcguard.onrender.com/docs) ·
[VerdictRegistry contract](https://explorer.arc.io/address/0x6F58770abE34cd1115Eb66232ceb5559c2e2F659)

> The API is hosted on a free tier that sleeps when idle — the first check
> after a quiet period can take up to a minute. Subsequent checks take a
> few seconds.

**Part 1 is for anyone. Part 2 is for developers.**

---

# Part 1: What this is, in plain English

## The problem

Using crypto means constantly clicking "approve" or "confirm". Those
confirmation screens are full of computer code that almost nobody can read —
including people who have used crypto for years.

Scammers rely on exactly that confusion. They get people to approve something
that quietly hands over permission to take their money. Often nothing happens
straight away. The money disappears days or weeks later, long after the person
has forgotten they clicked anything. There is no undo button, and no bank to
call.

## What this tool does

You paste in a transaction before approving it — the contract address and the
data field, straight off your wallet's confirmation screen. It answers one
question: **is this safe to sign?**

You can also check a transaction that has already been sent, by its hash.

You get a short sentence with no jargon, and a clear recommendation. Real
output from the tool:

> This lets 0x2B9899bC… spend your tokens at any time, in any amount, for as
> long as you leave the permission in place.
>
> **Proceed with caution**

Compare that to a safe one:

> This sends funds to 0xF0240CE4… It does not give anyone ongoing permission
> to spend your money.
>
> **Safe to proceed**

Both are real Arc mainnet transactions, checked by the live tool.

Three possible answers: **Safe to proceed**, **Proceed with caution**, or
**Do not sign this transaction**.

## What it checks

1. **Does this give someone unlimited access to your money?** The most common
   trap. A normal payment moves a fixed amount once. A dangerous approval
   hands over permission to take any amount, at any time, forever.
2. **How new is the address receiving that permission?** Scam contracts are
   usually brand new. A legitimate app has usually existed for months.
3. **Is the address already known for scams?** Checked against an outside
   security service that tracks reported addresses.

## How much you can trust it

The decision is made by fixed rules, not by AI guessing. The AI is only used
to write one sentence in plain English, and it is never allowed to change the
verdict — it cannot decide something dangerous is safe. If the AI is switched
off entirely, the tool still works and gives the same answers.

It never touches your money. It cannot move funds, and it never sees your
password or recovery phrase. It only reads public information.

## What it does not do yet

Built in a few days for a grant submission, not a finished product. It does
**not**:

- Pop up automatically inside your wallet — you paste the details in by hand
- Catch every scam — it focuses on one very common, very costly pattern
- Maintain its own scam database — it relies on an outside service

On Arc's main network, the "how new is this address" check is currently
unavailable because the network's public records aren't openly accessible yet.
The tool says "we could not check" rather than guessing — see Part 2.

---

# Part 2: For developers

## How it works

```
User → frontend/index.html → backend/app.py
                       (POST /check-calldata, before signing)
                       (POST /check, by hash, after)
                                   │
                    ┌──────────────┴──────────────┐
                    ▼                             ▼
            backend/scanner.py            backend/analyzer.py
         decode calldata + gather        score the facts, then
         facts (deterministic)           explain them
                    │                             │
         Arc RPC, Explorer API,          templates (normal case)
          GoPlus Security API            backend/llm.py (unknown calls only)
```

![Architecture diagram](docs/architecture.png)

The whole system is read-only. It holds no funds and no keys, which keeps the
security surface small.

**The important boundary:** `scanner.py` decides what a transaction *does*,
using ABI decoding and API lookups. `analyzer.py` turns those facts into a
score and a sentence. **No language model contributes to the score**, ever.
See [Design decisions](#design-decisions).

## Project layout

```
arcguard/
├── README.md                — you are here
├── requirements.txt         — Python dependencies
├── .env.example             — config template (copy to .env)
├── backend/
│   ├── scanner.py           — decode calldata + rule-based checks → facts
│   ├── analyzer.py          — facts → score, band, recommendation, wording
│   ├── llm.py               — swappable LLM provider (wording only)
│   ├── registry.py          — compile / read / build-write the registry
│   └── app.py               — FastAPI app: /check-calldata, /check, /attestations
├── contracts/
│   └── VerdictRegistry.sol  — on-chain record of published verdicts
├── scripts/
│   ├── deploy_registry.py   — deploy the registry to Arc (run once)
│   └── attest.py            — check a tx and publish the verdict on chain
├── frontend/
│   └── index.html           — paste-and-check page, no build step
│                            (pre-sign and by-hash modes)
└── tests/
    ├── test_transactions.py — manual sanity-check harness (live chain)
    └── test_registry.py     — asserting tests for the contract (local EVM)
```

## Setup

```bash
git clone https://github.com/Aniekan-Udo/arcguard.git
cd arcguard

python -m venv .venv
source .venv/bin/activate         # Windows: .venv\Scripts\activate

pip install -r requirements.txt

cp .env.example .env
```

`.env.example` is already set up for Arc mainnet — you only need to add an
LLM key if you want one (it is optional; see below).

> Verified on Python 3.14 with `web3` 8.0.0, `anthropic` 1.7.0 and
> `hexbytes` 2.0.0. Note that `hexbytes` ≥1.0 dropped the `0x` prefix from
> `.hex()`, which silently breaks ABI decoding — `scanner.normalize_calldata()`
> exists because of it, so pass `tx["input"]` through rather than `.hex()`.

## Network

**This project runs on Arc mainnet (chain `5042`).** That is the default in
`.env.example`, the configuration the live deployment uses, and the network
the bundled test transactions come from.

```bash
ARC_RPC_URL=https://rpc.mainnet.arc.io
ARC_CHAIN_ID=5042
ARC_EXPLORER_API_BASE=
ARC_EXPLORER_CHAIN_ID=
```

### One signal is dark on mainnet, and the tool says so

Of the three risk signals, two work on mainnet and one cannot:

| Signal                    | Mainnet       |
| ------------------------- | ------------- |
| Unlimited-approval check  | works         |
| Known-scam check (GoPlus) | works         |
| Contract-age check        | unavailable   |

`explorer.arc.io` serves `/api` behind a Cloudflare bot challenge, so a
server-side client receives an HTML challenge page instead of JSON. Real API
access has to come from Arc/Circle. Until then `contract_age_hours` is always
`None`, the `fresh_contract` signal never fires, and the highest reachable
verdict for an unlimited approval is **MEDIUM (35)** rather than HIGH (60).

This is reported, never papered over: the explanation reads *"We could not
check how long that address has existed"* rather than implying the address is
established. An unverifiable signal is shown as unverified, not as clean —
see [Design decisions](#design-decisions), point 3.

The `known_scam` signal reaches **CRITICAL (70)** on mainnet on its own, so
"Do not sign this transaction" is live today for blocklisted counterparties.

> **If you do point the explorer at a chain, change all four values together.**
> `ARC_EXPLORER_CHAIN_ID` must match the chain the RPC serves or the explorer
> is ignored outright. This is a safety check, not pedantry: addresses collide
> across chains (2 of 11 sampled Arc mainnet contracts also have code at the
> same address on testnet), so an explorer indexing a different chain can
> return a creation date belonging to a completely different contract — making
> a brand-new scam contract look established and silently downgrading a HIGH
> verdict to MEDIUM. Every other failure in this system fails closed; that one
> would fail open, which is why `explorer_available()` exists.

## Running it

```bash
cd backend
uvicorn app:app --reload --port 8000
```

Check it came up, and confirm the network and model:

```bash
curl http://localhost:8000/health
# {"connected_to_arc":true,"llm_provider":"groq","model":"openai/gpt-oss-120b"}
```

Then open `frontend/index.html` in a browser. Point its `API_BASE` at your
local server to develop against it.

## The two ways to check

**Before signing** — the one that protects you. A transaction hash only
exists once a transaction has been signed and broadcast, by which point the
approval you were worried about has already been granted. So the main route
takes the unsigned call instead: the contract being called and the calldata
your wallet is about to ask you to confirm.

```bash
curl -X POST http://localhost:8000/check-calldata \
  -H "Content-Type: application/json" \
  -d '{"to":"0x3600...0000","data":"0x095ea7b3..."}'
```

Omit `data` (or pass `"0x"`) for a plain value transfer. A malformed address
or non-hex calldata returns 400 rather than being scored — unreadable input
must not be confused with calldata we simply do not recognise, which scores
MEDIUM as a genuine unknown.

**After sending** — by hash, for a transaction already on chain. This is the
route that can carry an on-chain attestation, since a call that has not
happened cannot have been attested.

```bash
curl -X POST http://localhost:8000/check \
  -H "Content-Type: application/json" \
  -d '{"tx_hash":"0x..."}'
```

Both return the same shape and the same verdict for the same call — they
differ only in how the transaction is identified, not in how it is judged.

### Where the `to` and `data` values come from

**From your wallet, which is the point.** On a contract-interaction
confirmation, MetaMask shows both values before you sign:

- **`to`** — the contract address in the "Interacting with" / recipient field
  at the top of the confirmation.
- **`data`** — the long `0x…` string under the **Hex** tab (older builds:
  *Data*, or *Advanced → Hex*).

Paste both in, read the verdict, then approve or reject. Nothing has been
signed at that point, which is the entire difference between this route and
the by-hash one.

**From a transaction already on chain**, if you want fixed values for testing
or a demo. Any transaction's `to` and `input` are the same two fields a wallet
would have shown before it was signed:

```bash
python - <<'PY'
import sys; sys.path.insert(0, "backend")
from web3 import Web3
import scanner

w3 = Web3(Web3.HTTPProvider("https://rpc.mainnet.arc.io"))
tx = w3.eth.get_transaction("0x...")
print("to:  ", tx["to"])
print("data:", scanner.normalize_calldata(tx["input"]))
PY
```

### Worked examples

The four transactions in `tests/test_transactions.py`, as their pre-sign
values. Each produces the same verdict as checking its hash.

**Unlimited approval — 35/100 MEDIUM**

```
to:   0xEb64987643db71c76b2a2BE7E723DECC995E5b37
data: 0x095ea7b30000000000000000000000002b9899bc46bf0ee094225995f4bd496d42f261afffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
```

**Bounded approval — 0/100 SAFE**

```
to:   0x3600000000000000000000000000000000000000
data: 0x095ea7b30000000000000000000000001a03539b0ad757a51565f5d0f181223a9e381b1f0000000000000000000000000000000000000000000000000000000000e606b8
```

**Plain transfer — 0/100 SAFE** (leave `data` empty)

```
to:   0xF0240CE43bB9B975FED8861EaFa5CA0746727000
data:
```

**Undecodable call — 35/100 MEDIUM**

```
to:   0x000000000022D473030F116dDEE9F6B43aC78BA3
data: 0x87517c4500000000000000000000000036000000000000000000000000000000000000000000000000000000000000004fca4a51ab4f23a7447b3284fbd7d73289a89fb1000000000000000000000000ffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000ffffffffffff
```

Put the first two side by side and the attack is visible in one screenshot.
Both start `0x095ea7b3` — same function, same shape, same length. The only
difference is the last 64 characters: `…00e606b8` is a capped allowance,
`…ffffffff` is every token you hold, forever. Note the two use different
tokens, so the `to` addresses differ as well.

## Testing

```bash
python -m tests.test_transactions
```

This runs four real Arc mainnet transactions through the full pipeline and
prints the facts, score, band, wording, and where the wording came from.

| Case               | Score | Band   | Recommendation       |
| ------------------ | ----- | ------ | -------------------- |
| Plain transfer     | 0     | SAFE   | Safe to proceed      |
| Bounded approval   | 0     | SAFE   | Safe to proceed      |
| Unlimited approval | 35    | MEDIUM | Proceed with caution |
| Undecodable call   | 35    | MEDIUM | Proceed with caution |

The unlimited approval is MEDIUM rather than HIGH because `fresh_contract`
cannot fire without contract age. HIGH (60) requires an unlimited approval
**and** a counterparty younger than 24 hours.

Public Arc nodes prune old history, so these hashes will eventually stop
resolving. Rescan recent blocks to replace them — unlimited approvals are not
rare (a scan of 300 consecutive mainnet blocks found 38 among 87 `approve()`
calls):

```bash
python - <<'PY'
import sys; sys.path.insert(0, "backend")
from web3 import Web3
import scanner

w3 = Web3(Web3.HTTPProvider("https://rpc.mainnet.arc.io"))
latest = w3.eth.block_number
for n in range(latest, latest - 300, -1):
    for tx in w3.eth.get_block(n, full_transactions=True).transactions:
        if not tx["to"]:
            continue
        decoded = scanner.decode_function_call(w3, tx["to"], tx["input"])
        if decoded and decoded["params"].get("amount") == scanner.MAX_UINT256:
            print("unlimited approval:", "0x" + tx["hash"].hex().removeprefix("0x"))
            raise SystemExit
PY
```

Check a transaction over HTTP:

```bash
curl -X POST http://localhost:8000/check \
  -H "Content-Type: application/json" \
  -d '{"tx_hash":"0x..."}'
```

## The on-chain registry

**Deployed on Arc mainnet at
[`0x6F58770abE34cd1115Eb66232ceb5559c2e2F659`](https://explorer.arc.io/address/0x6F58770abE34cd1115Eb66232ceb5559c2e2F659)**
(block 22235136). Attester: `0x148Ea81a63ED33dE1FA6b449D2Fc81bBBbc0f978`.

ArcGuard's verdicts are computed off chain by deterministic rules.
`contracts/VerdictRegistry.sol`, deployed on Arc mainnet, makes a verdict
**citable**: "this tool said MEDIUM about this transaction, at this block"
becomes a fact timestamped by Arc, rather than a claim the API makes about
its own history.

```solidity
function attest(bytes32 txHash, uint8 score, Band band) external;
function verdictOf(bytes32 txHash, address attester)
    external view returns (bool found, uint8 score, Band band, uint64 timestamp);
```

**Writes are permissionless, and that is deliberate.** Anyone may attest to
anything, so an attestation means nothing on its own — it means something
relative to *who signed it*. Records are keyed by `(txHash, attester)`, so no
one can overwrite or forge another attester's verdict, and consumers filter on
the address they trust (`ARC_ATTESTER_ADDRESS`). Records are append-only:
re-attesting the same transaction reverts rather than quietly rewriting
history, which is the entire point of putting it on chain.

**The API still holds no key.** It reads the registry and never writes to it.
Publishing is a separate, explicitly-invoked command, for two reasons: the
service that judges transactions must not be able to sign anything, and a
check is free and instant while an attestation costs gas and is permanent —
those should not be the same action.

### Deploying it

```bash
pip install -r requirements-dev.txt        # adds py-solc-x; the API doesn't need it
python -m scripts.deploy_registry
```

Needs `ATTESTER_PRIVATE_KEY` in `.env`, funded with a little USDC — Arc pays
gas in USDC. The contract is ~1.1 KB of bytecode, so this costs cents. The
script prints the two values to put in `.env` (and in your Render
environment):

```bash
ARC_REGISTRY_ADDRESS=0x...
ARC_ATTESTER_ADDRESS=0x...
```

### Publishing a verdict

```bash
python -m scripts.attest 0x<tx_hash> --dry-run   # compute only, no gas
python -m scripts.attest 0x<tx_hash>             # publish it
```

`attest.py` runs the same `scan_transaction()` and `analyze()` the API runs
and publishes their result verbatim — it never recomputes or adjusts a
verdict. What lands on chain is what the rules decided.

### Reading it back

`POST /check` includes an `attestation` field, `null` when the transaction
has not been attested. There is also a direct lookup:

```bash
curl https://arcguard.onrender.com/attestations/0x<tx_hash>
```

> **A missing attestation is not evidence of safety.** Both the endpoint's
> 404 and the `null` field mean "nothing published", never "checked and
> clean" — the same rule the `contract_age_hours` signal follows. The
> contract's `verdictOf` returns a `found` flag for exactly this reason: an
> unattested transaction would otherwise read as score 0, band SAFE.

### Testing the contract

```bash
python -m tests.test_registry
```

Two tiers. The offline tier always runs: compilation, the ABI surface, and
that Solidity's `Band` enum agrees with `analyzer.score_to_band` across all
101 scores — a mismatch there would publish a wrong band permanently. The
EVM tier runs against a local in-memory chain when `eth-tester` is
importable, and is skipped with a notice when it is not (`py-evm` needs a C
toolchain that some platforms lack).

Unlike `test_transactions.py`, this one asserts: contract behaviour is fixed
at deploy time and records are append-only, so a mistake is permanent.

The deployed contract was verified against Arc mainnet directly: a published
verdict reads back intact, an unattested transaction returns no record rather
than a zero-valued `SAFE`, and re-attesting reverts with `AlreadyAttested`
(selector `0xe7ddafdd`).

## Swapping the AI provider

The model that writes the sentence is config, not code:

```bash
LLM_PROVIDER=groq        # anthropic | groq | grok | gemini | openai
GROQ_API_KEY=...
LLM_MODEL=               # blank uses that provider's default
```

`groq` (api.groq.com, open models) and `grok` (xAI) are different services —
easy to confuse, so both are supported separately.

Everything except Anthropic speaks the OpenAI-compatible `/chat/completions`
shape, so adding a vendor — or a local model server — is one entry in
`PROVIDERS` in `backend/llm.py`.

**The provider is optional.** With no key configured the checker runs entirely
on rules and returns the same verdicts; only the wording on undecodable calls
degrades to a fixed line. Every response reports `explanation_source`:
`rules`, `model`, or `unavailable`.

## How the score works

`analyzer.py` adds up whichever signals apply, caps at 100, then maps to a
band. All of it is deterministic.

| Signal               | Points | When it fires                              |
| -------------------- | ------ | ------------------------------------------ |
| `known_scam`         | 70     | GoPlus flags the address                    |
| `unlimited_approval` | 35     | `approve()` with `amount = 2**256 - 1`      |
| `undecoded_function` | 35     | calldata present but not decodable          |
| `fresh_contract`     | 25     | counterparty contract younger than 24 hours |

| Band     | Score  | Recommendation             |
| -------- | ------ | -------------------------- |
| CRITICAL | 70–100 | Do not sign this transaction |
| HIGH     | 50–69  | Do not sign this transaction |
| MEDIUM   | 30–49  | Proceed with caution       |
| LOW      | 15–29  | Proceed with caution       |
| SAFE     | 0–14   | Safe to proceed            |

A plain transfer (no calldata) scores 0 — it is fully understood, not
unverified, which is why it doesn't collect the `undecoded_function` penalty.

**The address that gets checked is the counterparty, not the contract being
called.** For `approve()` that's the spender; for `transferFrom()` the
recipient. Approving USDC is only dangerous because of *who* you approve, so
checking the token contract instead would miss the entire attack.

## Design decisions

1. **Rule-based decoding, never LLM-based.** `scanner.py` uses deterministic
   ABI decoding to establish what a transaction does. A hallucinated "this
   looks safe" is the worst possible failure for a safety tool, so this
   boundary is load-bearing — don't blur it when extending the code.

2. **Unrecognized transactions are flagged, not hidden.** Undecodable calldata
   returns `function: None` and scores MEDIUM on its own. Not being able to
   read what you're authorising is itself a risk, weighted the same as an
   unlimited approval because both mean "you don't know what you granted".

3. **Bias conservative on ambiguity.** False negatives (says safe, isn't) are
   far worse than false positives. Reserve the hard stop for strong signals;
   use softer language for ambiguous cases. Anything unverifiable is reported
   as unverified, never as clean.

4. **The LLM writes wording, and only where rules can't.** Every decoded
   transaction is explained by a template built from the verified facts —
   instant, free, unable to hallucinate. A model is consulted for one case
   only: calldata that failed to decode, where there's nothing to template.
   It has no input to the score, so the provider is swappable, optional, and
   incapable of making a dangerous transaction look safe.

   *An earlier version let the model escalate risk on undecodable calls. It
   flagged concern on every single one it saw — established, clean contracts
   included — so that judgement became a plain weight instead: same outcome,
   no network call, and covered by tests.*

5. **No indexer, no database, no job queue.** Every check is a live call to
   RPC / explorer / GoPlus. The one exception is contract-creation times,
   cached in a process-local dict: a deployment time never changes, and the
   testnet explorer's rate limit makes re-fetching self-defeating. Only
   successes are cached — caching a failure would let one 429 disable the
   signal for an address permanently. To survive restarts or scale past one
   process, that dict is the thing to replace.

## Extending it

**Add a decodable function.** Put the ABI fragment in `ERC20_ABI` in
`scanner.py`. If the risky address is an argument rather than the contract
being called, add it to `COUNTERPARTY_PARAM` too. Then add a heuristic check
if the function needs one, and a weight in `analyzer.py`'s `WEIGHTS`.
`setApprovalForAll` (NFT blanket approvals) is the obvious next one.

**Add a template.** `describe()` in `analyzer.py` returns the sentence for a
decoded transaction, or `None` to hand off to the model. New function types
should get a branch here, or they'll fall through to the LLM path
unnecessarily.

**Tune the weights.** `WEIGHTS` and `FRESH_CONTRACT_THRESHOLD_HOURS` are
first guesses, not calibrated against a labelled dataset. They're the first
thing to revisit with real data.

**Add a provider.** One entry in `PROVIDERS` in `llm.py` if it's
OpenAI-compatible; otherwise a small class with a `complete()` method.

## Known gaps & next steps

- **Mainnet contract age is unavailable** — see [Choosing a
  network](#one-signal-is-dark-on-mainnet-and-the-tool-says-so). The single
  biggest gap: it costs the HIGH
  band on mainnet. Needs explorer API access from Arc/Circle.
- **Function coverage is narrow on purpose** — only `approve` and
  `transferFrom` are decoded today.
- **Unlimited detection is exact-match** — only `2**256 - 1`. Approvals that
  are merely enormous (a common variant) are treated as bounded.
- **Scoring weights are untuned** — see above.
- **No wallet integration.** The natural next step, if Arc/Circle wanted to
  adopt this, is a pre-sign hook inside Circle's own Wallet SDK — Circle
  controls the full signing pipeline for its own wallets, which is far more
  direct than a browser extension intercepting MetaMask.
- **CORS is wide open** (`allow_origins=["*"]` in `app.py`) — tighten to the
  real frontend domain before deploying anywhere public.
- **`tests/test_transactions.py` is a sanity harness, not a test suite.** It
  hits the live chain and prints results for a human to read. There is no
  assertion-based CI.

---

This project targets **transaction-level** safety — "is this specific action
safe to sign" — which complements token-level tools that ask "is this token
trustworthy". They catch different attacks and belong side by side in a full
safety stack.
