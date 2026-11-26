# Bonvoyage protocol, version 1 (draft)

Bonvoyage lets ticket printers in different homes send each other tickets.
Nothing at home is reachable from the internet, and the relay that carries the
tickets cannot read them.

This document is the whole protocol. Anyone with a ticket printer should be
able to implement it from this text and check the result against the test
vectors in `vectors/`.

The words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Overview

- A **printer** is one installation: some software in front of a ticket printer.
- Every printer has an **identity**: two key pairs it generates itself.
- Every printer has an **inbox** on a **relay**. Printers only ever connect
  *out* to relays, over HTTPS.
- To send a ticket, the sender builds a **message**, signs it, seals it for the
  recipient and drops it in the recipient's inbox.
- The recipient polls its inbox, opens and checks each message, applies its own
  rules, and prints.

```
 sender printer                relay                recipient printer
       |   POST sealed message   |                          |
       |------------------------>|                          |
       |                         |   GET inbox (signed)     |
       |                         |<-------------------------|
       |                         |   sealed messages        |
       |                         |------------------------->|
       |                         |   DELETE message         |
       |                         |<-------------------------|
```

### 1.1 What a relay can and cannot learn

The relay is not trusted. The protocol is built so that a relay can delay,
drop or duplicate messages, but cannot read them, change them, or make a
recipient print something a paired contact did not send.

**A relay cannot decrypt.** The ticket, the sender's address and name, and the
pairing secret are inside the sealed part. A relay never holds a key that
opens it.

**A relay can observe:**

- that an inbox exists, when its owner polls, and from which IP address;
- that an inbox received a message, when, and from which IP address;
- the size of each sealed message, in steps of 4096 bytes (section 5.3);
- how many drop tokens an inbox has, when the list changes, and which token
  each message arrived with, so it sees a stable but nameless identity per
  contact (section 4).

**A relay can infer.** When the sender and the recipient both use the same
relay, the IP address that polls one inbox is the address that drops into
another, so that relay can work out who writes to whom. The same is true for
anyone who can watch the relay's network traffic. Someone who needs to hide
this uses a different relay from their contacts, or reaches the relay through
an anonymising network.

A relay SHOULD NOT keep logs of IP addresses. Clients cannot verify this.

### 1.2 Encodings

- **base64url** means RFC 4648 section 5, without `=` padding. Encodings MUST
  be canonical: the unused trailing bits are zero. A value that does not
  re-encode to the same text MUST be rejected.
- All JSON is UTF-8 without a byte order mark, and MUST contain only valid
  Unicode (no unpaired surrogates). Senders MUST NOT produce objects with
  duplicate member names. Unknown members MUST be ignored, so that later
  versions can add fields. Receivers MUST reject JSON nested more than 16
  levels deep.
- Times are Unix time in whole seconds, as JSON integers.
- A **host** is a lower-case DNS name with an optional `:port`, for example
  `bonvoyage.kaj.dev` or `relay.example:8443`. IP addresses, user names and
  paths are not allowed in a host.

## 2. Cryptography

Bonvoyage uses the NaCl / libsodium primitives, which exist for every common
language:

| Purpose | Primitive | libsodium name |
|---|---|---|
| Signing | Ed25519 | `crypto_sign_detached`, `crypto_sign_verify_detached` |
| Sealing for a recipient | X25519 + XSalsa20-Poly1305 "sealed box" | `crypto_box_seal`, `crypto_box_seal_open` |
| Hashing | SHA-256 | |

An identity consists of:

- a **signing key pair** (Ed25519), public part 32 bytes;
- an **encryption key pair** (X25519), public part 32 bytes.

The two key pairs are independent. Private keys never leave the printer.

Signature verification MUST behave as libsodium's does: public keys of small
order and signatures with a non-canonical `S` are rejected. Sealing MUST fail
for an encryption key of small order (libsodium does this).

## 3. Addresses and contact cards

### 3.1 Inbox ID and address

The **inbox ID** is the base64url encoding of the public signing key
(43 characters).

An **address** is `<inbox ID>@<host>`, for example:

```
0yYB4xGZ1uU5pWqT3n8Lr2VbKcJd7HsMfA6eXoPiQwE@bonvoyage.kaj.dev
```

The relay's base URL is `https://<host>`. Clients MUST use HTTPS and verify
the certificate. Plain HTTP to `localhost` is allowed only when the person
running the client has switched on a development mode; it MUST be off by
default.

Only the inbox ID identifies a printer. The host says where its inbox is and
is not authenticated by anything.

### 3.2 Contact card

To let someone send you tickets, you give them a **contact card**: a URI that
is easy to put in a QR code.

```
bonvoyage://<host>/<inbox ID>?v=1&k=<key>&t=<token>&p=<secret>&e=<time>&n=<name>&s=<signature>
```

| Part | Meaning | Format |
|---|---|---|
| host, inbox ID | your address | section 1.2, 3.1 |
| `v` | card version | `1` |
| `k` | your public encryption key | base64url, 43 characters |
| `t` | a drop token for your inbox (section 4) | base64url, 43 characters |
| `p` | a pairing secret (section 3.3) | base64url, 22 characters |
| `e` | optional: the card cannot be used to pair after this time | decimal integer |
| `n` | optional: a display name | percent-encoded UTF-8, at most 40 characters after decoding |
| `s` | your signature over the card | base64url, 86 characters |

The signature is Ed25519, made with the card issuer's signing key, over the
UTF-8 bytes of

```
"bonvoyage-v1-card\n" || host || "\n" || inbox ID || "\n" || k || "\n" || t || "\n" || p || "\n" || e || "\n" || name
```

where `e` is its decimal text or empty when absent, and `name` is the decoded
display name or empty when absent.

Someone who is given a card MUST, before using it:

- check that the URI has exactly this shape: scheme `bonvoyage`, a valid host,
  a path of exactly one inbox ID, and no user name, fragment or extra path;
- reject a card where any parameter in the table appears more than once, has
  the wrong length or is not canonical base64url, or where `v` is not `1`;
- verify `s` against the inbox ID.

Parameters not in the table are ignored.

A card contains a drop token and a pairing secret and is therefore a
**secret**: whoever holds it can pair with you in the other person's place.
Hand it over privately. Printing it as a QR code on a ticket for the other
person to scan is the intended way. Each contact MUST get their own card with
their own token and pairing secret.

### 3.3 Pairing

Pairing is one-directional: a card lets its holder send to its issuer. For
tickets in both directions, both people give each other a card.

When you issue a card you store a **contact**: your own name for that person,
the pairing secret, the token ID, and when the card expires for pairing. An
issuer SHOULD let an unused card expire after about 7 days and MUST refuse to
pair with it afterwards, whether or not the card carries `e`.

Every message carries the pairing secret of the card it was sent with
(section 5.1). It is inside the sealed part, so the relay never sees it. The
recipient uses it like this:

1. If the message's signing key is already **pinned** to a contact, the
   message belongs to that contact. The pairing secret in it is not used.
2. Otherwise, if the pairing secret equals that of a contact that has no
   pinned key yet and whose card has not expired, that contact is paired: the
   signing key is pinned to it.
3. Otherwise the message is from nobody the recipient knows and MUST be
   discarded.

Pairing secrets MUST be compared in constant time. A signing key MUST be
pinned to at most one contact, and a contact has at most one pinned key.

A recipient SHOULD tell its owner when a contact is paired, and SHOULD ask the
owner to confirm before printing that contact's first ticket. If a message
arrives with the pairing secret of a contact that is already pinned to a
different key, the recipient MUST discard it and SHOULD tell its owner: it
means the card reached someone else.

The token the relay reports for a message (section 6.5) is a hint only. It
MUST NOT be used to decide who a message is from.

## 4. Drop tokens

A **drop token** is 32 random bytes generated by the inbox owner.

The owner registers the **token ID**, which is the lower-case hex SHA-256 of
the 32 token bytes, with the relay. The relay never sees a token until a
sender uses it, and stores only token IDs.

Removing a token ID from the inbox stops that card from delivering. An owner
can also give a contact a fresh card to replace their token, which breaks the
relay's ability to link that contact's old and new messages.

## 5. Messages

### 5.1 The message

A message is a JSON object:

| Member | Type | Meaning |
|---|---|---|
| `v` | integer | protocol version, exactly `1` |
| `id` | string | 16 random bytes, base64url (22 characters); unique per message |
| `type` | string | `"ticket"`; other values are reserved |
| `from` | string | sender's address |
| `to` | string | recipient's address |
| `pair` | string | the pairing secret from the recipient's card, 22 characters |
| `created` | integer | when it was made; greater than 0 and less than 2^40 |
| `expires` | integer | optional; do not print after this time; same range |
| `from_name` | string | optional; the sender's own display name, at most 40 characters |
| `ticket` | object | the ticket (section 7), required for type `ticket` |

### 5.2 Signing

Let `M` be the UTF-8 bytes of the message JSON, exactly as the sender
serialised them. The signature is Ed25519 over the bytes:

```
"bonvoyage-v1-message\n" || M
```

The **signed message** is the JSON object

```json
{"msg": "<base64url of M>", "sig": "<base64url of the 64-byte signature>"}
```

Signing the exact bytes avoids any need to canonicalise JSON. Verifiers MUST
verify against the decoded bytes of `msg`, and only then parse them.

### 5.3 Padding and sealing

Let `S` be the UTF-8 bytes of the signed message JSON. The padded plaintext is

```
P = uint32_be(len(S)) || S || zero bytes
```

with as many zero bytes as needed to make `len(P)` a multiple of 4096.

The **sealed message** is `crypto_box_seal(P, recipient public encryption key)`.
Its length is `len(P) + 48`, so every sealed message is `48 + n * 4096` bytes
long, with `n` from 1 to 15. The largest is 61488 bytes, which leaves 61436
bytes for `S`.

### 5.4 Receiving

A recipient handles each collected message with the steps below, in this
order. If any step fails, or if handling the message raises any error at all,
the message is **discarded**: it MUST NOT be printed, it MUST be deleted from
the relay, and the recipient MUST carry on with the next message.

1. **Open.** The sealed length is `48 + n * 4096`. Open it with the encryption
   key pair to get `P`.
2. **Unpad.** Read the length `L`; it MUST be at most `len(P) - 4`, and every
   byte after `S` MUST be zero.
3. **Unwrap.** Parse `S` as JSON. `msg` and `sig` MUST be canonical base64url
   strings, `sig` of 64 bytes. Decode `msg` to the bytes `M`.
4. **Verify.** Parse `M` as JSON; it MUST be an object, and `from` MUST be a
   valid address. Take the signing key from the inbox ID in `from` and verify
   `sig` over `"bonvoyage-v1-message\n" || M`.
5. **Validate.** Every member in the table of 5.1 MUST have exactly the stated
   type and format (`v` is the number 1, not `true` or `"1"`). The inbox ID in
   `to` MUST equal the recipient's own; the host in `to` is not compared.
6. **Check the time.** Discard if `created` is more than 600 seconds in the
   future, if `created` is more than 691200 seconds (8 days) in the past, or
   if `expires` is present and has passed.
7. **Check for a repeat.** Discard if this signing key and `id` were handled
   before. Recipients MUST remember them for at least 692000 seconds, counted
   from when the message was received.
8. **Find the contact** as described in section 3.3.
9. **Record.** Store the signing key and `id` as handled, and the pinned key
   if this message paired a contact, on storage that survives a restart,
   before going on.
10. **Act.** For type `ticket`: validate the ticket (section 7), apply the
    recipient's policy (section 8), then print or queue it. Messages of any
    other type are dropped without printing.
11. **Delete** the message from the relay.

A recipient that holds a ticket for later (quiet hours, approval) SHOULD check
`expires` again at the moment of printing.

## 6. Relay HTTP interface

All paths are relative to the relay's base URL. Bodies and responses are JSON
unless stated. Errors use the matching HTTP status with
`{"error": "<short text>"}`.

Statuses used by every endpoint:

| Status | Meaning |
|---|---|
| `400` | malformed request, including any query string on a `/v1` path |
| `401` | missing or invalid credentials |
| `404` | no such path |
| `405` | method not allowed on this path |
| `413` | body too large |
| `429` | too many requests or a quota reached; a `Retry-After` header gives seconds |
| `503` | relay temporarily unavailable; may carry `Retry-After` |

A client that receives `429` or `503` MUST wait at least the given time, or 60
seconds when none is given, before trying that relay again, and SHOULD double
the wait on repeated failures up to an hour.

Clients MUST NOT follow HTTP redirects from a relay, MUST NOT read a response
larger than 4 MiB, and SHOULD NOT send headers that identify the client
software or its owner.

A relay MAY limit how many requests an IP address makes in a short period.
Keeping counters for that purpose for at most an hour is not logging in the
sense of section 1.1.

### 6.1 Relay information

`GET /v1` returns the relay's limits:

```json
{"bonvoyage": 1, "max_message_bytes": 61488, "max_messages": 50,
 "max_messages_per_token": 10, "retention_seconds": 604800,
 "max_tokens": 64, "registration": "open"}
```

`registration` is `open`, `invite` (section 6.3) or `closed`.

### 6.2 Owner authentication

Requests marked **owner** are signed with the inbox's signing key. The client
sends the header

```
Bonvoyage-Auth: t=<time>,sig=<signature>
```

exactly in that form: `time` in decimal without leading zeros, `signature` as
86 characters of base64url. The signature is Ed25519 over the UTF-8 bytes of

```
"bonvoyage-v1-request\n" || METHOD || "\n" || host || "\n" || PATH || "\n" || time || "\n" || hex(SHA-256(body))
```

`METHOD` is upper case, `host` is the relay's host as in the address, `PATH`
is the request path, and `body` is the exact request body (empty for requests
without one).

The relay MUST reject (`401`) a request whose time differs from its own by
more than 300 seconds, whose host is not the one it is being addressed as, or
whose signature does not verify against the inbox ID in the path.

A relay MUST also refuse (`409`) a `PUT` or `DELETE` of an inbox that carries
a signature it has already accepted. Because the host is signed, a request
made to one relay cannot be replayed to another. Ed25519 signatures are
deterministic, so an owner who sends the same request twice within one second
gets `409` for the second; it signs again with a later time.

A client whose clock is wrong will be refused; it can read the relay's time
from the `Date` header of any response.

### 6.3 Inbox management (owner)

`PUT /v1/inbox/<inbox ID>` creates the inbox or replaces its settings.

```json
{"tokens": ["<token ID>", "..."]}
```

`tokens` is the complete list of accepted token IDs, at most `max_tokens`.
Replacing the list is how tokens are added and revoked. Response `200` with
`{"id": "<inbox ID>", "tokens": [...]}`, duplicates removed.

`DELETE /v1/inbox/<inbox ID>` removes the inbox and everything in it (`204`).

Creating an inbox can be refused: `403` when registration is closed, the
relay is full, or an invitation is required and missing or wrong; `429` when
too many inboxes were created recently. On a relay with `registration:
"invite"`, the client adds the header `Bonvoyage-Invite: <code>` when creating
an inbox. Existing inboxes keep working in every mode.

A relay MAY remove an inbox that was never collected from after 7 days, and
any inbox that has not been collected from for 180 days.

### 6.4 Dropping a message (sender)

`POST /v1/inbox/<inbox ID>/messages`

- Header `Authorization: Bearer <drop token, base64url>`.
- Body: the sealed message, raw bytes. No particular `Content-Type` is required.

The relay accepts it (`201`, body `{"id": "<relay message id>"}`) when:

- the inbox exists and the SHA-256 of the decoded token is one of its token
  IDs, otherwise `401`;
- the body length is `48 + n * 4096` for `n` from 1 to 15, otherwise `400`, or
  `413` when it is longer than `max_message_bytes`;
- the inbox holds fewer than `max_messages` messages, and fewer than
  `max_messages_per_token` that arrived with this token, otherwise `429`.

The relay MUST NOT reveal whether a `401` was caused by an unknown inbox or by
an unknown token; both get the same response. A relay SHOULD check the
credentials' shape before reading the body.

### 6.5 Collecting (owner)

`GET /v1/inbox/<inbox ID>/messages` returns up to 20 of the oldest messages
(`404` when the inbox does not exist):

```json
{"messages": [
  {"id": "<relay message id>", "received": 1795000000,
   "token": "<token ID it arrived with>", "body": "<base64url sealed message>"}
]}
```

A relay message id matches `^[A-Za-z0-9_-]{1,64}$`. A client MUST skip any
entry whose `id` does not, and MUST NOT process more than 20 entries from one
response.

`DELETE /v1/inbox/<inbox ID>/messages/<relay message id>` removes one message
(`204`, also when it no longer exists).

Collecting does not remove messages; the recipient deletes each one after
handling it. A message that is never deleted is removed by the relay after
`retention_seconds`.

`token` tells the owner which card a message was dropped with. It comes from
the relay and is not proof of anything (section 3.3), but it is useful for
revoking a token that delivers messages which keep being discarded, which a
recipient SHOULD do.

Clients SHOULD poll no more often than once every 30 seconds.

## 7. Tickets

A ticket describes content, not printer commands. Every recipient renders it
in its own way, for its own paper width.

```json
{"blocks": [
  {"type": "text", "text": "Hallo!", "size": "large", "align": "center", "bold": true},
  {"type": "divider"},
  {"type": "list", "style": "check", "items": ["melk", "brood"]},
  {"type": "qr", "data": "https://example.com"}
]}
```

`blocks` is an array of objects. A block that is not an object makes the
ticket invalid.

### 7.1 Blocks

| Type | Members | Meaning |
|---|---|---|
| `text` | `text` (string); optional `align` (`left`, `center`, `right`), `bold`, `underline` (booleans), `size` (`small`, `normal`, `large`, `huge`) | A paragraph. Line feeds in `text` start a new line; the recipient wraps long lines. |
| `divider` | | A horizontal rule. |
| `list` | `items` (array of strings); optional `style` (`bullet`, `number`, `check`) | A list. `check` draws a box to tick. |
| `qr` | `data` (string); optional `caption` (string) | A QR code containing `data`. |
| `image` | `png` (base64url PNG); optional `alt` (string), `align` | A picture. Recipients scale it to their paper and convert it to black and white. |
| `space` | optional `lines` (integer 1 to 5, default 1) | Blank lines. |

- A recipient MUST support `text`, `divider`, `list` and `space`. If it cannot
  render a `qr` or `image` block it prints the `caption` or `alt` text instead,
  or nothing.
- Blocks of an unknown type are skipped. They still count towards the number
  of blocks.
- Unknown values for `size`, `align` or `style` are treated as the default.

### 7.2 Limits

Senders MUST NOT exceed these limits. A recipient MUST check them before
rendering and MUST discard the whole ticket if any is exceeded.

| Limit | Value |
|---|---|
| Blocks in a ticket | 100 |
| Characters in a ticket: the Unicode code points of every `text`, list item, `caption` and `alt` together | 8000 |
| Lines in a ticket: for each `text` block one plus its line feeds, for each `list` its number of items, for each `space` its lines, one per `divider` | 300 |
| Items in one list | 50 |
| `qr` blocks in a ticket | 4 |
| `data` of one QR code, in UTF-8 bytes | 512 |
| `image` blocks in a ticket | 2 |
| One image | 576 pixels wide, 1200 high |
| All images in a ticket together | 1600 pixels high |

These limits bound what a sender may ask for. On top of them, a recipient MUST
enforce its own maximum printed length per ticket, in its own units; one metre
is a reasonable ceiling. A ticket that would be longer is cut off with a
visible mark, or discarded.

### 7.3 Text

Before text reaches a printer, a recipient MUST:

- remove every code point in the Unicode categories Cc (control) and Cf
  (format), except that a line feed (U+000A) in the `text` of a `text` block
  is kept as a line break, and a tab (U+0009) becomes a space;
- replace line feeds everywhere else (list items, `caption`, `alt`, names),
  and the separators U+2028 and U+2029 everywhere, by a space.

After this, the bytes sent to the printer for text MUST NOT contain any byte
below 0x20 other than the line feeds the recipient's own renderer emits. Text
may otherwise contain any Unicode; a recipient replaces what its printer
cannot show.

### 7.4 Images

A recipient that renders images MUST, before decoding the pixel data:

- check that the data is a PNG and read the width and height from its header;
- skip the block if either is zero or over the limit;
- refuse to decompress more than the declared size requires.

It SHOULD ignore ancillary chunks and animation. Senders SHOULD use 1-bit or
8-bit greyscale. A message leaves room for about 34 kB of PNG data in total.

### 7.5 What a recipient must never do

- It MUST NOT send any part of a ticket to the printer as raw commands.
- It MUST NOT fetch URLs or other remote resources because a ticket mentions
  them. A QR code is drawn, never followed.

## 8. Recipient policy

Paper comes out in someone's home, so the recipient's rules always win. A
recipient:

- MUST discard messages from senders it has not paired with (section 3.3);
- MUST limit how many tickets each contact can print in a day, with a limit of
  its own choosing; 10 is reasonable;
- SHOULD respect its own quiet hours, holding tickets until they end;
- MUST label a received ticket with **its own name for the contact**, and
  SHOULD show that it arrived through Bonvoyage. `from_name` and the name on
  a card are only suggestions for naming a new contact; they are never printed
  as the sender;
- MAY hold tickets for approval by a person before printing;
- MAY drop tickets silently. There are no delivery receipts in version 1, so a
  sender cannot tell whether a ticket was printed.

## 9. Security notes

- **What the relay can do.** A relay can drop, delay, duplicate and reorder
  messages, lie about which token a message arrived with, and refuse service.
  It cannot read a message, change one, or get a recipient to print something
  a paired contact did not send: pairing depends on a secret the relay never
  sees, and afterwards on the sender's signature.
- **Forwarding.** `to` is inside the signed bytes, so a recipient cannot
  re-seal someone's message for a third party and have it accepted.
- **Replay.** A message can be printed once: the recipient remembers handled
  messages for longer than the maximum age it accepts (section 5.4).
- **A card that reaches the wrong person.** Whoever uses a card first is
  paired as that contact. Afterwards the intended person's messages are
  discarded, which the owner is told about (section 3.3), and the fix is to
  remove the contact and issue a new card. Expiry and owner confirmation limit
  the window. A card issued for one person can also be handed on by them to
  someone else; a card proves possession of the card, not who holds it.
- **Shared inbox.** Anyone holding a valid token can fill their own share of
  an inbox (`max_messages_per_token`) with messages that will be discarded.
  The owner sees which token and can revoke it.
- **No forward secrecy.** Whoever records sealed messages and later obtains
  the recipient's private encryption key can read them all, including who sent
  them. Keep that key safe; a printer that suspects its keys leaked creates a
  new identity and pairs again.
- **Signatures are proof.** A recipient can show a signed message to others as
  evidence that the sender wrote it.
- **Lost keys.** There is no recovery. A printer that loses its keys creates a
  new identity and pairs again.
