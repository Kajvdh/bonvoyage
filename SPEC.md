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

**The recipient chooses the relay.** A sender connects to whatever relay the
card names. Someone who runs their own relay therefore sees the IP address of
everyone who sends to them, and when.

A relay SHOULD NOT keep logs of IP addresses. Clients cannot verify this.

### 1.2 Encodings

- **base64url** means RFC 4648 section 5, without `=` padding. Encodings MUST
  be canonical: the unused trailing bits are zero. A value that does not
  re-encode to the same text MUST be rejected.
- All JSON is UTF-8 and MUST be valid RFC 8259 JSON containing only valid
  Unicode (no unpaired surrogates). A byte order mark, `NaN` and `Infinity`
  are not JSON and MUST be rejected.
- Unknown members MUST be ignored, so that later versions can add fields.
- **Nesting.** Count an array or object as one level, plus one for each array
  or object it sits inside. Receivers MUST reject JSON with a level above 16,
  and MUST do so without first parsing it with a parser that can run out of
  stack: either the parser enforces the limit itself, or the bytes are scanned
  for bracket depth (outside strings) before they are parsed. Every JSON text
  in this protocol is at most 61436 bytes.
- **Duplicate member names.** Senders MUST NOT produce them. A receiver MAY
  reject a message that has them; one that does not MUST use the same parser
  for every decision about a message, so that it cannot verify one value and
  act on another.
- **Integers.** Where this document says integer, senders MUST write a JSON
  number without fraction or exponent (`1795000000`, not `1795000000.0` or
  `1.795e9`). A receiver MUST reject a number that is not a whole number, and
  MAY reject one written with a fraction or exponent.
- A **character** is one Unicode code point.
- Times are Unix time in whole seconds, as integers.

**Hosts.** A host is a DNS name with an optional port:

- two or more labels separated by dots, with no trailing dot;
- each label 1 to 63 characters of `a`-`z`, `0`-`9` and `-`, not starting or
  ending with `-`; lower case only;
- the last label consists of letters only, which rules out every way of
  writing an IP address;
- the name is at most 253 characters, not counting the port;
- an optional `:port`, a decimal number from 1 to 65535 written with the
  ASCII digits `0`-`9` and without leading zeros. The default port 443 MUST
  NOT be written.

A relay under a top-level domain that is not letters only (the `xn--`
internationalised ones) cannot be named in version 1.

Examples: `bonvoyage.kaj.dev`, `relay.example:8443`. Not hosts: `localhost`,
`printer`, `192.168.1.10`, `2130706433`, `relay.example:443`, `Relay.Example`.

**Addresses.** A relay named in a card is chosen by someone else, so a client
MUST NOT let it point at the client's own network. Before connecting to a
host, a client MUST resolve the name and check every address it resolves to:

- An IPv6 address that carries an IPv4 address inside it is judged by that
  IPv4 address: IPv4-mapped (`::ffff:0:0/96`), IPv4-compatible (`::/96`),
  IPv4-translated (`::ffff:0:0:0/96`), NAT64 (`64:ff9b::/96`,
  `64:ff9b:1::/48`), 6to4 (`2002::/16`) and Teredo (`2001::/32`).
- The address MUST be a globally reachable unicast address according to the
  IANA special-purpose address registries for IPv4 and IPv6. This refuses,
  among others: `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10`, `127.0.0.0/8`,
  `169.254.0.0/16`, `172.16.0.0/12`, `192.0.0.0/24`, `192.168.0.0/16`,
  `198.18.0.0/15`, `224.0.0.0/3`; and `::`, `::1`, `fc00::/7`, `fe80::/10`,
  `fec0::/10`, `ff00::/8`.
- A client SHOULD also refuse an address inside a network it is directly
  attached to, which matters on IPv6 networks where every device has a
  public address.

If any address fails, the client MUST NOT connect. It MUST connect to an
address it checked, not resolve the name a second time. What remains possible
is the opening of a TLS connection to a public address of the card issuer's
choosing; nothing of a message is sent before the certificate is verified.

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
the certificate. A client MAY offer a development mode in which `localhost`
with an optional port is accepted as a host and reached over plain HTTP; it
MUST be off by default and switched on only by the person running the client.

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
| `e` | optional: the card cannot be used to pair after this time | decimal, 1 to 2^40 - 1, no leading zeros |
| `n` | optional: a display name | percent-encoded UTF-8, 1 to 40 characters after decoding |
| `s` | your signature over the card | base64url, 86 characters |

The signature is Ed25519, made with the card issuer's signing key, over the
UTF-8 bytes of

```
"bonvoyage-v1-card\n" || host || "\n" || inbox ID || "\n" || k || "\n" || t || "\n" || p || "\n" || e || "\n" || name
```

where `e` is its decimal text or empty when absent, and `name` is the decoded
display name or empty when absent.

Parameters are separated by `&` and may come in any order; the order shown is
recommended. In `n`, every byte outside `A`-`Z`, `a`-`z`, `0`-`9`, `-`, `.`,
`_` and `~` is percent-encoded; a space is `%20`, and `+` means a plus sign.
An optional parameter that has no value is left out, not written empty.

Someone who is given a card MUST, before using it:

- check that the URI has exactly this shape: scheme `bonvoyage`, a valid host
  (section 1.2), a path of exactly one inbox ID, and no user name, fragment or
  extra path;
- reject a card where any parameter in the table appears more than once, is
  empty, has the wrong length or format, is not canonical base64url, contains
  an invalid percent-escape or invalid UTF-8, or where `v` is not `1`;
- verify `s` against the inbox ID;
- reject a card whose `e` has passed.

Parameters not in the table are ignored.

**Cards for phones.** A phone camera that scans a QR code holding a
`bonvoyage://` URI does not know what to do with it. A client MAY therefore
put a web link in the QR code instead, of the form

```
https://<host>/card/#<card URI>
```

where the page at that address shows the card with a way to copy it. The part
of a link after `#` is not sent to the server, so a relay that serves such a
page still does not see the card; but whoever serves the page is trusted not
to send it anywhere from the browser. A client that takes in a card SHOULD
accept this form too, by using only what follows the `#`. This wrapping is a
convenience for people, not part of the card.

A card is checked once, when it is taken in. The sender then keeps what it
needs from it (address, encryption key, token and pairing secret) and uses
that for every message; `e` is not looked at again. Because the issuer stops
accepting a first message when the card expires (section 3.3), a sender
SHOULD send a first ticket as soon as it has taken a card in, and SHOULD tell
its user so.

A card contains a drop token and a pairing secret and is therefore a
**secret**: whoever holds it can pair with you in the other person's place.
Hand it over privately. Printing it as a QR code on a ticket for the other
person to scan is the intended way. Each contact MUST get their own card with
their own token and pairing secret.

### 3.3 Pairing

Pairing is one-directional: a card lets its holder send to its issuer. For
tickets in both directions, both people give each other a card.

When you issue a card you store a **contact**: your own name for that person,
the pairing secret, the token ID, when the card was issued, and when it
expires for pairing. An issuer SHOULD let an unused card expire after about 7
days, measured by its own clock, whether or not the card carries `e`.

A contact is in one of three states:

| State | Meaning |
|---|---|
| **open** | The card has been issued. No signing key belongs to the contact yet. |
| **pending** | A signing key has claimed the card and is **pinned** to the contact. The owner has not confirmed it yet. Tickets from that key are held, not printed. |
| **paired** | The owner confirmed. Tickets from the pinned key are printed. |

Every message carries the pairing secret of the card it was sent with
(section 5.1), inside the sealed part, so the relay never sees it. For each
authentic message the recipient decides who it is from:

1. If the message's signing key is pinned to a contact, the message is from
   that contact. The pairing secret in it is not looked at.
2. Otherwise, if the pairing secret equals that of an **open** contact whose
   card has not expired at the moment the message is handled, the sender is a
   **candidate** for that contact.
3. Otherwise the message is from nobody the recipient knows and MUST be
   discarded.

The transitions:

- **open to pending.** A candidate's message that is a valid ticket (type
  `ticket`, passing section 7) pins the candidate's signing key to the
  contact. Any other message from a candidate is discarded and changes
  nothing.
- **Notice.** On this transition the recipient MUST tell its owner, on
  paper or on a screen the owner will see: a fixed text saying that a new
  contact wants to pair, the recipient's own name for the contact, and the
  fingerprint (section 3.4) of the pinned key. Pairing is therefore never
  silent, even when the ticket itself is empty. The notice shows nothing the
  sender chose, except that it MAY show `from_name` clearly marked as the
  sender's own claim.
- **pending to paired.** The owner confirms, ideally after comparing the
  fingerprint with the other person. Held tickets are then printed.
- **pending to removed.** The owner declines. The contact is removed, with
  its held tickets. The right person then needs a new card.
- A recipient MAY confirm automatically, going from open to paired at once.
  It MUST still give the notice.
- While a contact is pending, at most 5 of its tickets are held; further ones
  are discarded. Held tickets count towards the contact's daily limit.

Rules that keep this safe:

- Pairing secrets MUST be compared in constant time.
- A signing key MUST be pinned to at most one contact, and a contact has at
  most one pinned key. Rule 1 is applied before rule 2, so a key that is
  already pinned can never claim a second contact.
- A message whose `created` is more than 600 seconds before its contact's
  card was issued MUST be discarded. This stops old messages from a sender
  who was removed and later paired again.
- If a message from an unknown key carries the pairing secret of a contact
  that is pending or paired, the recipient MUST discard it. It SHOULD tell
  its owner that the card was used by a second party, at most once a day per
  contact and never by printing. The warning does not say which of the two
  is the intended person; comparing fingerprints does.
- The token the relay reports for a message (section 6.5) is a hint only. It
  MUST NOT be used to decide who a message is from.

**Removing a contact** means deleting it: the pinned key, the pairing secret
and any tickets of it that are held or queued. Its messages are then
discarded by rule 3. Revoking its drop token at the relay (section 4) is good
housekeeping but is not what blocks it.

### 3.4 Fingerprints

The **fingerprint** of a signing key lets two people check, over the phone or
face to face, that a printer paired with the key they think it did. Take the
first 5 bytes of

```
SHA-256("bonvoyage-v1-fingerprint\n" || the 32 bytes of the public signing key)
```

as a big-endian number, take it modulo 10^12, and write it as 12 decimal
digits in three groups of four, for example `4821 0937 5512`. A client MUST
be able to show the fingerprint of its own key.

## 4. Drop tokens

A **drop token** is 32 random bytes generated by the inbox owner.

The owner registers the **token ID**, which is the lower-case hex SHA-256 of
the 32 token bytes, with the relay. The relay never sees a token until a
sender uses it, and stores only token IDs.

Removing a token ID from the inbox stops that card from delivering.

An owner can replace a paired contact's token: it registers a new token for
that contact and hands them a card carrying it. The contact's key stays
pinned, so the pairing secret on that card is never used; the owner MUST put
a fresh random value there and not store it, so that it cannot pair anyone.
This breaks the relay's ability to link that contact's old and new messages.

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
| `expires` | integer | optional; the message is not printed once the time is later than this; same range |
| `from_name` | string | optional; the sender's own display name, 1 to 40 characters |
| `ticket` | object | the ticket (section 7), required for type `ticket` |

A sender that tries again after a failed drop MUST send the same sealed
message, or at least a message with the same `id`, so that a drop which did
succeed the first time is not printed twice.

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
order, one message at a time. Two receive loops MUST NOT run at the same time
on the same stored state.

A message that fails a step is **discarded**: it MUST NOT be printed, it
leaves no state behind other than what the steps explicitly record, the
recipient deletes it from the relay, and carries on with the next message. An
error while handling a message that was caused by the message counts as a
failed step.

A failure of the recipient itself is different: no connection to the relay, a
full disk, an error while writing its state. Then the recipient MUST stop
without deleting the message, and try again later.

Let `now` be the recipient's own clock.

1. **Open.** The sealed length is `48 + n * 4096` with `n` from 1 to 15. Open
   it with the encryption key pair to get `P`.
2. **Unpad.** Read the length `L`; it MUST be at most `len(P) - 4`, and every
   byte after `S` MUST be zero.
3. **Unwrap.** Parse `S` as JSON. `msg` and `sig` MUST be canonical base64url
   strings, `sig` of 64 bytes. Decode `msg` to the bytes `M`.
4. **Verify.** Parse `M` as JSON; it MUST be an object, and `from` MUST be a
   valid address. Take the signing key from the inbox ID in `from` and verify
   `sig` over `"bonvoyage-v1-message\n" || M`, the bytes exactly as decoded.
5. **Validate.** Every member in the table of 5.1 MUST have exactly the stated
   type and format (`v` is the number 1, not `true` or `"1"`; `id` and `pair`
   are canonical base64url). The inbox ID in `to` MUST equal the recipient's
   own, exactly; the host in `to` is not compared.
6. **Check the time.** Discard if `created > now + 600`, if
   `created < now - 691200` (8 days), or if `expires` is present and
   `expires < now`.
7. **Check for a repeat.** Discard if this signing key together with this
   `id` was handled before. Recipients MUST remember the pair for at least
   692000 seconds, counted from when the message was received.
8. **Find the contact** (section 3.3): a pinned contact, a candidate, or
   discard.
9. **Check the content.** For type `ticket`, validate the ticket (section 7).
   A candidate whose message is not a valid ticket is discarded here, and
   nothing about it is recorded.
10. **Record.** In one step that survives a restart, store: the signing key
    and `id` as handled; the pin and the new state, if this message moved a
    contact from open to pending or paired; and, if it is a valid ticket, the
    ticket in a queue. A crash after this step must lose neither the record
    nor the ticket. A message from a pinned contact that is not a valid
    ticket (an unknown type, or a ticket that fails section 7) is recorded as
    handled and otherwise dropped.
11. **Delete** the message from the relay. If that fails, the relay offers the
    message again and step 7 discards it.

Printing happens from the queue, where the recipient's policy applies
(section 8): quiet hours, the daily limit, holding tickets of a pending
contact. A recipient SHOULD check `expires` again at the moment of printing.

**Clocks.** These checks use the recipient's own clock, never a time supplied
by a relay, which could otherwise revive expired messages. But a recipient
with a wrong clock would discard every valid message as too old or from the
future, so:

- A relay MUST send a `Date` header on every response.
- Each time it collects, a recipient MUST compare its clock with that header.
  If the header is missing or differs by more than 300 seconds, it MUST NOT
  handle or delete any message until its clock is right.
- A sender SHOULD make the same comparison before sending, because a message
  with a wrong `created` is discarded without a trace.

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
| `500`, `503` | the relay failed or is temporarily unavailable; may carry `Retry-After` |

A relay may check the conditions for a request in any order, so a request that
is wrong in two ways can get either status.

A client that receives `429`, `500` or `503` MUST wait before trying that
relay again: the number of seconds in `Retry-After` when it is a decimal
number, otherwise 60 seconds, and never more than 3600. It SHOULD double the
wait on repeated failures, up to an hour.

Clients MUST NOT follow HTTP redirects from a relay, MUST NOT read a response
larger than 4 MiB, MUST give up on a request that has not completed within 60
seconds, and SHOULD NOT send headers that identify the client software or its
owner. Sending a ticket MUST NOT block a client's receive loop, because the
relay it sends to is chosen by someone else.

A relay MUST send a `Date` header on every response (section 5.4).

A relay MAY limit how many requests an IP address makes, and how many inboxes
it creates, in a short period. Keeping counters for that purpose for at most
a day, in a form from which the address cannot be read back, is not logging
in the sense of section 1.1.

### 6.1 Relay information

`GET /v1` returns the relay's limits:

```json
{"bonvoyage": 1, "max_message_bytes": 61488, "max_messages": 50,
 "max_messages_per_token": 10, "retention_seconds": 604800,
 "max_tokens": 64, "poll_seconds": 300, "pow_bits": 20,
 "registration": "open"}
```

`poll_seconds` is how long the relay asks clients to wait between collections
(section 6.5); it is never less than 60. `pow_bits` is the proof of work a new
inbox needs (section 6.3), from 0 (none) to 32. `registration` is `open`,
`invite` (section 6.3) or `closed`.

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

`METHOD` is upper case. `host` is the relay's host exactly as in the address
(section 1.2). `PATH` is the request path exactly as sent: clients MUST NOT
send dot segments (`/./`, `/../`), empty segments or percent-escapes, and a
relay MUST refuse a path containing `%`. `body` is the exact request body
(empty for requests without one).

The relay MUST reject (`401`) a request whose time differs from its own by
more than 300 seconds, whose host is not its own, or whose signature does not
verify against the inbox ID in the path. A relay MUST know its own host from
its configuration or from routing it controls, not merely from a header the
client supplies; otherwise a request made to another relay could be replayed
to it.

**Order.** A `PUT` or `DELETE` of an inbox MUST carry a time strictly greater
than that of the last such request the relay accepted for that inbox;
otherwise the relay refuses it (`409`). The relay keeps that time for at least
600 seconds after an inbox is deleted. A request that was held back therefore
cannot undo a later one, and none can be replayed. An owner who gets `409`
signs the request again with a later time; two changes within the same second
need a one-second pause.

A client whose clock is wrong will be refused; it can read the relay's time
from the `Date` header of any response and use it for this header only (see
"Clocks" in section 5.4).

### 6.3 Inbox management (owner)

`PUT /v1/inbox/<inbox ID>` creates the inbox or replaces its settings.

```json
{"tokens": ["<token ID>", "..."]}
```

`tokens` is the complete list of accepted token IDs, at most `max_tokens`.
Replacing the list is how tokens are added and revoked. Response `200` with
`{"id": "<inbox ID>", "tokens": [...]}`, duplicates removed.

`DELETE /v1/inbox/<inbox ID>` removes the inbox and everything in it (`204`).

Creating an inbox can be refused: `403` when registration is closed, an
invitation is required and missing or wrong, or the proof of work is missing
or too small; `429` when too many inboxes were created recently, by everyone
or from the same address; `503` when the relay has no room. On a relay with
`registration: "invite"`, the client adds the header
`Bonvoyage-Invite: <code>` when creating an inbox. Existing inboxes keep
working in every mode.

**Proof of work.** A relay that reports `pow_bits` greater than 0 asks whoever
creates an inbox to spend a little computing time first, so that creating
thousands of inboxes is expensive while creating one costs a second or two.
The client finds a `nonce`, a decimal number from 0 to 10^20 - 1 without
leading zeros, such that

```
SHA-256("bonvoyage-v1-pow\n" || inbox ID || "\n" || nonce)
```

starts with at least `pow_bits` zero bits, and sends it as the header
`Bonvoyage-Pow: <nonce>` on the `PUT` that creates the inbox. The simplest
search tries 0, 1, 2 and so on. The work is tied to the inbox ID, so it
cannot be reused for another inbox; it is not needed to update an inbox that
exists.

**Inboxes do not last forever.** A relay MAY remove an inbox that was never
collected from after 7 days, any inbox that has not been collected from for
30 days, and, when it is full, the inbox that has gone unused the longest. A
client whose collect returns `404` MUST create its inbox again with its
current token list, and carry on. Its contacts need nothing new: the address
and the cards stay valid. Tickets sent while the inbox was gone are lost.

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

A relay that is full as a whole MAY make room by removing waiting messages,
oldest first, from the inboxes that hold the most; or it answers `503`.

**Delivery is not guaranteed.** A `201` means the relay stored the message,
not that it will be printed: the relay may drop it when full or after
`retention_seconds`, the inbox may be gone, and the recipient may discard it.
There are no receipts in version 1.

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

A relay message id matches `^[A-Za-z0-9_-]{1,64}$`. A client MUST look at no
more than the first 20 entries of a response, and of those MUST skip every
entry whose `id` is not a string of that form.

`DELETE /v1/inbox/<inbox ID>/messages/<relay message id>` removes one message
(`204`, also when it no longer exists).

Collecting does not remove messages; the recipient deletes each one after
handling it. A message that is never deleted is removed by the relay after
`retention_seconds`.

`token` tells the owner which card a message was dropped with. It comes from
the relay and is not proof of anything (section 3.3), but it is useful for
revoking a token that delivers messages which keep being discarded, which a
recipient SHOULD do.

**Polling.** A client MUST NOT collect from an inbox more often than once
every 60 seconds, and SHOULD wait at least the relay's `poll_seconds`. Once
every 5 minutes is the recommended rhythm: a relay's capacity is mostly spent
on polling, and a ticket that arrives a few minutes later is still a ticket.

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
- `text`, `items`, `data`, `png` and `lines` decide what is printed. If one of
  them is missing where required or has the wrong type or range, the ticket
  is invalid. `data` is 1 to 512 bytes.
- `align`, `bold`, `underline`, `size`, `style`, `caption` and `alt` only
  dress it up. One with a wrong type or an unknown value is treated as absent.

### 7.2 Limits

Senders MUST NOT exceed these limits. A recipient MUST check them before
rendering and MUST discard the whole ticket if any is exceeded.

| Limit | Value |
|---|---|
| Blocks in a ticket | 100 |
| Characters in a ticket: the Unicode code points of every `text`, list item, `caption` and `alt` together, counted as received, before the cleaning of section 7.3 | 8000 |
| Lines in a ticket: for each `text` block one plus its line feeds, for each `list` its number of items, for each `space` its lines, one per `divider` | 300 |
| Items in one list | 50 |
| `qr` blocks in a ticket | 4 |
| `data` of one QR code, in UTF-8 bytes | 512 |
| `image` blocks in a ticket | 2 |
| One image | 576 pixels wide, 1200 high |
| All images in a ticket together | 1600 pixels high |

An image that is not a valid PNG, or whose size is zero or over a limit, makes
the whole ticket invalid (section 7.4).

**These limits do not bound paper.** They bound the size of the request, not
the printout: a "line" above is a line break in the data, and a single long
paragraph in a large size on narrow paper still wraps into hundreds of printed
lines. The bound on paper is the recipient's own:

- A recipient MUST lay out a ticket completely and measure it before sending
  the first byte to the printer.
- It MUST enforce its own maximum printed length per ticket, in its own
  units; one metre is a reasonable ceiling. A ticket that would be longer is
  cut off with a visible mark, or discarded.

### 7.3 Text

Before text reaches a printer, a recipient MUST:

- remove every code point in the Unicode categories Cc (control) and Cf
  (format), with three exceptions: a line feed (U+000A) in the `text` of a
  `text` block is kept as a line break; a tab (U+0009) becomes a space; the
  joiners U+200C and U+200D are kept, because emoji and several scripts need
  them. The categories are those of the Unicode version the recipient's
  platform provides;
- replace line feeds everywhere else (list items, `caption`, `alt`, names),
  and the separators U+2028 and U+2029 everywhere, by a space.

After this, the bytes sent to the printer for text MUST NOT contain any byte
below 0x20 other than the line feeds the recipient's own renderer emits. Text
may otherwise contain any Unicode; a recipient replaces what its printer
cannot show.

The `data` of a QR code is encoded into the code as bytes. A recipient that
uses a QR command built into its printer MUST pass the data in a
length-delimited form, so that no byte of it can be read as a command.

### 7.4 Images

Every recipient, whether or not it can print images, MUST check each `image`
block before accepting a ticket:

- `png` is canonical base64url and decodes to data that starts with the
  8-byte PNG signature, followed by a first chunk that is named `IHDR`, is
  13 bytes long and has a correct checksum;
- in that header the width and height are at least 1 and within the limits
  of section 7.2; the colour type is 0 (greyscale); the bit depth is 1 or 8;
  the interlace method is 0.

A ticket with an image that fails these checks is invalid. The restriction
to plain greyscale keeps the memory a recipient needs small and predictable:
at most 576 x 1200 bytes per image. A recipient that renders images MUST NOT
decompress more than the declared size requires, and SHOULD ignore ancillary
chunks and animation. A message leaves room for about 34 kB of PNG data in
total.

### 7.5 What a recipient must never do

- It MUST NOT send any part of a ticket to the printer as raw commands.
- It MUST NOT fetch URLs or other remote resources because a ticket mentions
  them. A QR code is drawn, never followed.

## 8. Recipient policy

Paper comes out in someone's home, so the recipient's rules always win. A
recipient:

- MUST discard messages from senders it has not paired with, and MUST tell
  its owner whenever a contact is paired (section 3.3);
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
  remove the contact and issue a new card. Expiry limits the window, and the
  pairing notice with its fingerprint (sections 3.3, 3.4) is what lets the
  owner catch it. The separate warning about a second party depends on the
  intended person's message arriving, so a relay working with the thief can
  suppress it; the notice does not depend on the relay. A card issued for one
  person can also be handed on by them to someone else; a card proves
  possession of the card, not who holds it.
- **Shared inbox.** Anyone holding a valid token can fill their own share of
  an inbox (`max_messages_per_token`) with messages that will be discarded.
  The owner sees which token and can revoke it.
- **Delivery.** A relay may lose a message: when it is full, when the inbox
  was removed, when it fails. A sender is not told. Version 1 accepts this; a
  ticket is not a registered letter.
- **No forward secrecy.** Whoever records sealed messages and later obtains
  the recipient's private encryption key can read them all, including who sent
  them. Keep that key safe; a printer that suspects its keys leaked creates a
  new identity and pairs again.
- **Signatures are proof.** A recipient can show a signed message to others as
  evidence that the sender wrote it. Doing so also reveals the pairing secret
  of that contact, which is harmless once the contact is paired.
- **A relay named in a card.** A card can name any relay, including one run by
  the card's issuer or a host chosen to probe the sender's network. The host
  rules of section 1.2 and the request rules of section 6 exist for this.
- **An open relay can be exhausted.** A relay that lets anyone create an inbox
  can be filled or kept busy by someone determined, whatever its quotas. The
  protocol limits the damage to delay: nothing is disclosed, and anyone can
  move to another relay or run their own.
- **Lost keys.** There is no recovery. A printer that loses its keys creates a
  new identity and pairs again.
