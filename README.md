# Bonvoyage

A small open protocol for sending tickets from one ticket printer to another.

- **Nothing at home is exposed.** Printers only connect outward, to a relay.
- **The relay cannot read tickets.** Every ticket is signed by the sender and
  sealed for the recipient before it leaves; the relay stores unreadable bytes
  and never learns who sent them.
- **The recipient decides.** You pair with people explicitly, and your own
  limits and quiet hours always apply.
- **Not tied to any software.** Anyone with a ticket printer can implement it
  from the spec.

Website and public relay: **https://bonvoyage.kaj.dev**

## Quick start

Try it in two minutes, without a printer. The reference client shows tickets
as text in your terminal; play both sides yourself to see a ticket travel.

Needs Python 3.10+ and PyNaCl.

    git clone https://github.com/Kajvdh/bonvoyage
    cd bonvoyage
    pip install pynacl

    # two printers (play both to try it)
    python examples/bonvoyage.py init kaj.json --relay bonvoyage.kaj.dev --name Kaj
    python examples/bonvoyage.py init jan.json --relay bonvoyage.kaj.dev --name Jan

    # Jan makes a contact card for Kaj; it prints one line starting with bonvoyage://
    python examples/bonvoyage.py card jan.json Kaj

    # Kaj sends Jan a ticket with that card
    python examples/bonvoyage.py send kaj.json 'bonvoyage://...' 'Koffie om 10u?'

    # Jan collects
    python examples/bonvoyage.py receive jan.json

With a friend it works the same: each of you runs `init` once, then you swap
cards. The `.json` files hold private keys; keep them to yourself.

## What is in this repository

| | |
|---|---|
| [`SPEC.md`](SPEC.md) | The protocol, version 1 (draft). Start here. |
| [`vectors/`](vectors/) | Test vectors, with a guide: keys, a signed and sealed message, a signed relay request, and messages that must be rejected. |
| [`relay/`](relay/) | The relay. One codebase that runs on Cloudflare Workers (free plan) or on your own server. |
| [`examples/bonvoyage.py`](examples/bonvoyage.py) | A reference client in one file, meant to be read next to the spec. |
| [`relay/site/`](relay/site/) | The landing page a relay serves at `/`, with the rendered spec at `/spec/`. Rebuild with `npm run build:site`. |

## Implementing a client

A client is the software between the relay and your printer. Two ways to get one:

- **Hand it to an AI coding assistant.** Give it `SPEC.md` and
  `vectors/v1.json` with a prompt like: *"Implement a Bonvoyage client in
  <language> following SPEC.md. Prove it is correct by passing every case in
  vectors/v1.json, including must_reject. Then connect it to my printer."*
- **Write it yourself.** Read `SPEC.md` with `examples/bonvoyage.py` open next
  to it. The cryptography is two libsodium functions: Ed25519 signatures and
  sealed boxes.

Either way, the **test vectors** tell you whether the result is right. They
are worked examples with the answers filled in: with exactly these keys and
this ticket, the signature is exactly this, and this sealed message opens to
exactly that. They also contain messages a correct client must refuse.
[`vectors/README.md`](vectors/README.md) lists what to check, step by step.

Beyond the protocol, a client needs four things of its own: somewhere to keep
its keys and contacts, a loop that collects from its inbox, a way to turn a
ticket into print commands for its printer, and its policy (section 8 of the
spec).

## Running a relay

A relay is a mailbox: it accepts sealed messages for an inbox and hands them
to the inbox's owner. You can use someone else's relay or run your own; two
people on different relays can still exchange tickets, because an address
names its relay.

### On Cloudflare Workers

Needs a Cloudflare account; the free plan is enough for a household relay.

    cd relay
    npm install
    npx wrangler login
    npx wrangler d1 create bonvoyage          # copy the database_id into wrangler.toml
    npx wrangler d1 migrations apply bonvoyage --remote
    npx wrangler deploy

To serve it on your own domain, uncomment the `[[routes]]` block in
`wrangler.toml` before deploying.

### On your own server

Needs Node 22.13 or newer, nothing else.

    cd relay
    BONVOYAGE_DB=/var/lib/bonvoyage/relay.db PORT=8787 node src/server.js

or with Docker:

    docker build -t bonvoyage-relay relay
    docker run -d -p 127.0.0.1:8787:8787 -v bonvoyage:/data bonvoyage-relay

Put it behind a reverse proxy that provides HTTPS. Configure that proxy **not
to log client addresses**; the relay itself logs nothing about requests.

### Settings

| | |
|---|---|
| `REGISTRATION` | `open` (default) lets anyone create an inbox; `closed` keeps existing inboxes working and refuses new ones. |

Limits (message size, messages per inbox, retention) are in
`relay/src/core.js` and are reported at `GET /v1`.

### Checking a relay

The conformance tests run against any relay:

    cd relay
    npm test                                         # in-process
    RELAY_URL=https://relay.example npm test         # a running relay

## Development

    cd relay && npm test
    uv run --with pynacl python vectors/generate.py              # regenerate the vectors
    cd examples && uv run --with pynacl --with pytest pytest     # reference client, incl. end to end

## Licence

MIT, see [`LICENSE`](LICENSE).

## Status

Version 1 is a draft. The spec may still change until two independent
implementations have exchanged tickets.
