# Test vectors

A test vector is a worked example with the answer filled in: *given exactly
these keys and this input, a correct implementation produces exactly this
output*. They let you check your own Bonvoyage code without needing a second
person, a relay, or trust in your reading of the spec. Code that reproduces
every value in [`v1.json`](v1.json) and refuses everything it should refuse
has the protocol's mechanics right. The vectors cannot cover everything the
spec asks for (timeouts, storage that survives a crash, your printer's own
limits), so they come after reading the spec, not instead of it.

All binary values are base64url without padding. Use `now` from the file as
the current time wherever a check involves time, so the results are the same
for everyone.

## What to check

| In `v1.json` | Your code must | Spec |
|---|---|---|
| `base64url` | decode `canonical`, and refuse every string in `must_reject` | 1.2 |
| `hosts` | accept every host under `valid` and refuse every one under `must_reject` (with development mode off) | 1.2 |
| `addresses` | allow a connection to every address under `public` and refuse every one under `must_refuse` | 1.2 |
| `sender`, `recipient`, `stranger` | derive `signing_public`, `encryption_public`, `inbox_id`, `address` and `fingerprint` from the two secret keys | 2, 3.1, 3.4 |
| `proof_of_work` | find `nonce` for that inbox ID and number of bits, and get `digest_hex` for `input` | 6.3 |
| `drop_token` | compute `token_id` from `token` | 4 |
| `cards.valid` | build the same `uri` as the recipient (parameters in the recommended order), and parse it back into the listed parts; `cards.signing_input` shows the exact bytes that are signed | 3.2 |
| `cards.also_valid` | accept these too, at time `cards.now`: no expiry or name, a name full of special characters, another parameter order with an unknown parameter | 3.2 |
| `cards.must_reject` | refuse every one of these cards, at time `cards.now` | 3.2 |
| `message.sealed` | open it as the recipient and get exactly `message.message_json` | 5.4 |
| `message.sig`, `message.signed_message_json` | produce the same signature and signed wrapper as the sender | 5.2 |
| `message.padded_length`, `message.sealed_length` | get the same lengths when sealing | 5.3 |
| `message.expect_plain_text` | optional: render the ticket as plain text, 48 characters wide | 7 |
| `must_accept` | accept every one of these sealed messages in steps 1 to 6 of receiving: the exact boundaries of the time checks, a long message, an unknown member, another relay in `to` | 5.4 |
| `must_reject` | refuse every one of these sealed messages in steps 1 to 6. Two of them (`signature_by_small_order_key`, `signature_with_non_canonical_s`) are accepted by signature libraries that are laxer than libsodium | 2, 5.4 |
| `may_reject` | not crash on these; accepting or refusing them are both allowed | 1.2 |
| `contact_checks.steps` | starting with one open contact, handle the steps in order: get `discard`, `hold` or `print` for each, end up in `state_after` with `pinned_after` pinned, show the owner `notice_fingerprint` when a contact is pinned, and leave a discarded message's contact and queue untouched | 3.3, 5.4 |
| `contact_checks.held_limit` | hold at most five tickets for a contact that is not confirmed | 3.3 |
| `contact_checks.expired_card` | refuse to pair once the card has expired | 3.3 |
| `contact_checks.two_contacts` | with two contacts: a pinned key stays with its contact whatever secret it presents, and handled messages are remembered per signing key | 3.3, 5.4 |
| `tickets.valid` | accept these tickets | 7 |
| `tickets.must_discard` | discard every one of these tickets | 7.1, 7.2, 7.4 |
| `tickets.text_cleaning` | turn each `input` into its `output` | 7.3 |
| `owner_requests` | produce the same `header` for each method, host, path, time and body | 6.2 |
| `relay_response` | from a collect response with those ids, process and delete exactly `ids_to_process` | 6.5 |

Signatures are compared byte for byte, which assumes the deterministic
Ed25519 of RFC 8032 that libsodium implements. A signer that adds randomness
produces valid signatures that differ from the ones here.

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
