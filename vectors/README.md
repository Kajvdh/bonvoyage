# Test vectors

A test vector is a worked example with the answer filled in: *given exactly
these keys and this input, a correct implementation produces exactly this
output*. They let you check your own Bonvoyage code without needing a second
person, a relay, or trust in your reading of the spec. If your code reproduces
every value in [`v1.json`](v1.json), it speaks the protocol.

All binary values are base64url without padding.

## What to check

| In `v1.json` | Your code must | Spec |
|---|---|---|
| `sender`, `recipient` | derive `signing_public`, `encryption_public`, `inbox_id` and `address` from the two secret keys | 2, 3.1 |
| `drop_token` | compute `token_id` from `token` | 4 |
| `contact_card` | build the same `uri` from the recipient's keys and the token, and parse it back | 3.2 |
| `message.sealed` | open it with the recipient's keys and get exactly `message.message_json` | 5.4 |
| `message.sig` | produce the same signature over `message.message_json` with the sender's signing key (Ed25519 signatures are deterministic) | 5.2 |
| `message.signed_message_json`, `padded_length`, `sealed_length` | produce the same signed wrapper and the same lengths when sealing | 5.3 |
| `message.expect_plain_text` | optional: render the ticket as plain text, 48 characters wide | 7 |
| `owner_request` | produce the same `header` for that method, path, time and body | 6.2 |
| `must_reject` | refuse every one of these sealed messages | 5.4 |

Sealing uses a fresh random key every time, so you cannot reproduce
`message.sealed` byte for byte. Instead: open the given one, and check that
what you seal yourself can be opened with the recipient's keys.

Use `message.opened_at` as "now" when opening, so the time checks behave the
same for everyone.

## See it pass

The reference client is checked against these vectors:

    cd examples
    uv run --with pynacl --with pytest pytest -v      # or: pip install pynacl pytest && pytest -v

`generate.py` rebuilds `v1.json` from fixed keys using the reference client.
