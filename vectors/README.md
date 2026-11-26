# Test vectors

A test vector is a worked example with the answer filled in: *given exactly
these keys and this input, a correct implementation produces exactly this
output*. They let you check your own Bonvoyage code without needing a second
person, a relay, or trust in your reading of the spec. If your code reproduces
every value in [`v1.json`](v1.json) and refuses everything it should refuse,
it speaks the protocol.

All binary values are base64url without padding. Use `now` from the file as
the current time wherever a check involves time, so the results are the same
for everyone.

## What to check

| In `v1.json` | Your code must | Spec |
|---|---|---|
| `base64url` | decode `canonical`, and refuse every string in `must_reject` | 1.2 |
| `sender`, `recipient`, `stranger` | derive `signing_public`, `encryption_public`, `inbox_id` and `address` from the two secret keys | 2, 3.1 |
| `drop_token` | compute `token_id` from `token` | 4 |
| `cards.valid` | build the same `uri` as the recipient, and parse it back into the listed parts; `cards.signing_input` shows the exact bytes that are signed | 3.2 |
| `cards.must_reject` | refuse every one of these cards | 3.2 |
| `message.sealed` | open it as the recipient and get exactly `message.message_json` | 5.4 |
| `message.sig`, `message.signed_message_json` | produce the same signature and signed wrapper as the sender (Ed25519 signatures are deterministic) | 5.2 |
| `message.padded_length`, `message.sealed_length` | get the same lengths when sealing | 5.3 |
| `message.expect_plain_text` | optional: render the ticket as plain text, 48 characters wide | 7 |
| `must_reject` | refuse every one of these sealed messages in steps 1 to 6 of receiving | 5.4 |
| `contact_checks` | starting with one unpaired contact made from `cards.valid`, handle the steps in order and get `print` or `discard` for each | 3.3, 5.4 |
| `tickets.valid` | accept these tickets | 7 |
| `tickets.must_discard` | discard every one of these tickets | 7.2, 7.4 |
| `tickets.text_cleaning` | turn each `input` into its `output` | 7.3 |
| `owner_request` | produce the same `header` for that method, host, path, time and body | 6.2 |

Sealing uses a fresh random key every time, so you cannot reproduce a sealed
message byte for byte. Instead: open the given ones, and check that what you
seal yourself can be opened with the recipient's keys.

The names under `must_reject` say what is wrong with each message
(`signature_changed`, `created_is_text`, `too_old`, ...). An implementation
that skips signature verification, type checks or the time window will accept
some of them.

## See it pass

The reference client is checked against these vectors:

    cd examples
    uv run --with pynacl --with pytest pytest -v      # or: pip install pynacl pytest && pytest -v

`generate.py` rebuilds `v1.json` from fixed keys using the reference client.
