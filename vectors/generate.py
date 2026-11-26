#!/usr/bin/env python3
"""Regenerates vectors/v1.json from fixed keys, using the reference client.

Everything is deterministic except sealed messages: sealing uses a fresh random
key every time, so implementations check that they can OPEN the given sealed
messages, and that what they seal themselves can be opened with `recipient`.
"""
import base64
import hashlib
import json
import pathlib
import struct
import sys
import zlib

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent / "examples"))
import bonvoyage as bv  # noqa: E402
from nacl.public import PrivateKey, SealedBox  # noqa: E402
from nacl.signing import SigningKey  # noqa: E402

NOW = 1795000000


def identity(seed: bytes, relay: str, name: str) -> dict:
    sign = hashlib.sha256(b"sign" + seed).digest()
    enc = hashlib.sha256(b"enc" + seed).digest()
    return {"relay": relay, "name": name, "sign": bv.b64(sign), "enc": bv.b64(enc), "contacts": {}, "cards": {}, "seen": {}, "queue": []}


def public(ident: dict) -> dict:
    return {
        "name": ident["name"],
        "signing_secret_seed": ident["sign"],
        "signing_public": bv.b64(bytes(SigningKey(bv.unb64(ident["sign"])).verify_key)),
        "encryption_secret": ident["enc"],
        "encryption_public": bv.b64(bytes(PrivateKey(bv.unb64(ident["enc"])).public_key)),
        "inbox_id": bv.inbox_id(ident),
        "address": bv.address(ident),
        "fingerprint": bv.fingerprint(bv.unb64(bv.inbox_id(ident), 32)),
    }


def chunk(kind: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))


def png(width: int, height: int, claim: tuple[int, int] | None = None, break_crc: bool = False, depth: int = 1,
        colour: int = 0, interlace: int = 0, first: bytes | None = None) -> str:
    """A 1-bit all-white greyscale PNG, base64url. The keyword arguments write something else in the
    header (always with a correct checksum unless break_crc), or put another chunk first."""
    rows = (b"\0" + b"\xff" * ((width + 7) // 8)) * height
    header = chunk(b"IHDR", struct.pack(">IIBBBBB", *(claim or (width, height)), depth, colour, 0, 0, interlace))
    if break_crc:
        header = header[:-1] + bytes([header[-1] ^ 1])
    return bv.b64(b"\x89PNG\r\n\x1a\n" + (first or b"") + header + chunk(b"IDAT", zlib.compress(rows, 9)) + chunk(b"IEND", b""))


def worsen(text: str) -> str:
    """The same bytes, but with the unused trailing bits of the last character set: not canonical."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    return text[:-1] + alphabet[alphabet.index(text[-1]) + 1]


sender = identity(b"vector-sender", "relay.example", "Kaj")
recipient = identity(b"vector-recipient", "bonvoyage.example", "Jan")
stranger = identity(b"vector-stranger", "relay.example", "Eve")
token = hashlib.sha256(b"vector-token").digest()
pair = hashlib.sha256(b"vector-pair").digest()[:16]
CARD_ISSUED = NOW - 3600
card_expires = CARD_ISSUED + 7 * 24 * 3600
card_uri = bv.make_card(recipient, token, pair, expires=card_expires)
card = bv.parse_card(card_uri, now=NOW)
enc_secret = PrivateKey(bv.unb64(recipient["enc"]))

ticket = {"blocks": [
    {"type": "text", "text": "Dag Jan! ♥", "size": "large", "align": "center", "bold": True},
    {"type": "divider"},
    {"type": "list", "style": "check", "items": ["koffie", "café € 2,50"]},
    {"type": "qr", "data": "https://example.com", "caption": "voorbeeld"},
    {"type": "hologram", "note": "unknown block types are skipped"},
]}
MID = bytes(range(16))


def seal(who=sender, **kw) -> bytes:
    return bv.seal_message(who, card, kw.pop("ticket", ticket), now=kw.pop("now", NOW), message_id=kw.pop("message_id", MID), **kw)


def mid(letter: str) -> bytes:
    return letter.encode() * 16


sealed = seal()
padded = SealedBox(enc_secret).decrypt(sealed)
length = int.from_bytes(padded[:4], "big")
signed_bytes = padded[4:4 + length]
signed = json.loads(signed_bytes)
_, opened = bv.open_message(recipient, sealed, now=NOW)
message_json = bv.unb64(signed["msg"])


def reseal(signed_json: bytes | dict) -> bytes:
    data = signed_json if isinstance(signed_json, bytes) else json.dumps(signed_json, separators=(",", ":")).encode()
    return bv.seal_signed(data, card["key"])


def raw_seal(plaintext: bytes) -> bytes:
    return SealedBox(enc_secret.public_key).encrypt(plaintext)


def signed_by(who: dict, m: bytes) -> bytes:
    return bv.sign_message(who, m)


def without(member: str) -> bytes:
    return json.dumps({k: v for k, v in opened.items() if k != member}, ensure_ascii=False, separators=(",", ":")).encode()


# The neutral element of the curve: a lax verifier accepts the all-zero-S signature below for ANY message.
SMALL_ORDER_KEY = bytes([1]) + bytes(31)
ED25519_L = 2 ** 252 + 27742317777372353535851937790883648493


def non_canonical_s(sig: bytes) -> bytes:
    """The same signature with the group order added to S: valid for a lax verifier, refused by libsodium."""
    s_value = int.from_bytes(sig[32:], "little") + ED25519_L
    assert s_value < 2 ** 256
    return sig[:32] + s_value.to_bytes(32, "little")


flipped_sig = bytearray(bv.unb64(signed["sig"]))
flipped_sig[0] ^= 1
loose = base64.urlsafe_b64encode(message_json).decode()  # keeps '=' padding: not canonical
big_text = {"blocks": [{"type": "text", "text": "Een lange brief. " * 400}]}

must_accept = {
    "note": "Each opens and passes steps 1 to 6 of receiving at time `now`.",
    "longer_than_one_block": bv.b64(seal(ticket=big_text, message_id=mid("a"))),
    "to_names_another_relay": bv.b64(seal(_override={"to": bv.inbox_id(recipient) + "@elsewhere.example"}, message_id=mid("b"))),
    "expires_later": bv.b64(seal(expires=NOW + 3600, message_id=mid("c"))),
    "expires_exactly_now": bv.b64(seal(expires=NOW, message_id=mid("d"))),
    "created_600_seconds_ahead": bv.b64(seal(now=NOW + 600, message_id=mid("e"))),
    "created_exactly_8_days_ago": bv.b64(seal(now=NOW - 691200, message_id=mid("f"))),
    "unknown_member": bv.b64(seal(_override={"future_field": {"anything": [1, 2, 3]}}, message_id=mid("g"))),
    "sixteen_levels_of_nesting": bv.b64(seal(_override={"deep": json.loads("[" * 15 + "]" * 15)}, message_id=mid("h"))),
    # The signature is over the bytes as sent. This message is valid JSON with spaces and another member
    # order; an implementation that re-serialises before verifying will reject it.
    "json_with_spaces_and_other_order": bv.b64(reseal(signed_by(sender, json.dumps(
        dict(reversed(list({**opened, "id": bv.b64(mid("i"))}.items()))), ensure_ascii=False, indent=2).encode()))),
}

must_reject = {
    # --- sealing and padding
    "bit_flipped": bv.b64(sealed[:100] + bytes([sealed[100] ^ 1]) + sealed[101:]),
    "length_prefix_too_large": bv.b64(raw_seal(struct.pack(">I", 5000) + signed_bytes + b"\0" * (4096 - 4 - len(signed_bytes)))),
    "padding_not_zero": bv.b64(raw_seal(struct.pack(">I", length) + signed_bytes + b"\0" * (4096 - 5 - length) + b"\x01")),
    "not_a_multiple_of_4096": bv.b64(raw_seal(struct.pack(">I", length) + signed_bytes)),
    "sixteen_blocks": bv.b64(raw_seal(struct.pack(">I", length) + signed_bytes + b"\0" * (16 * 4096 - 4 - length))),
    "padding_not_zero_in_the_middle": bv.b64(raw_seal(struct.pack(">I", length) + signed_bytes + b"\0" * 100 + b"\x01"
                                                     + b"\0" * (4096 - 4 - length - 101))),
    "byte_order_mark": bv.b64(reseal(b"\xef\xbb\xbf" + signed_bytes)),
    # --- signature and wrapper
    "signature_changed": bv.b64(reseal({"msg": signed["msg"], "sig": bv.b64(bytes(flipped_sig))})),
    "signed_by_another_key_than_from": bv.b64(reseal(signed_by(stranger, message_json))),
    "msg_not_canonical_base64url": bv.b64(reseal({"msg": loose, "sig": signed["sig"]})),
    "sig_not_canonical_base64url": bv.b64(reseal({"msg": signed["msg"], "sig": worsen(signed["sig"])})),
    "signature_by_small_order_key": bv.b64(reseal({
        "msg": bv.b64(message_json.replace(public(sender)["inbox_id"].encode(), bv.b64(SMALL_ORDER_KEY).encode())),
        "sig": bv.b64(SMALL_ORDER_KEY + bytes(32))})),
    "signature_with_non_canonical_s": bv.b64(reseal({"msg": signed["msg"], "sig": bv.b64(non_canonical_s(bv.unb64(signed["sig"])))})),
    # --- members and types (all correctly signed by the sender)
    "wrong_recipient": bv.b64(seal(_override={"to": bv.address(sender)})),
    "to_inbox_id_with_an_extra_character": bv.b64(seal(_override={"to": bv.inbox_id(recipient) + "A@bonvoyage.example"})),
    "to_host_with_a_trailing_line_feed": bv.b64(seal(_override={"to": bv.address(recipient) + "\n"})),
    "version_is_true": bv.b64(seal(_override={"v": True})),
    "version_is_text": bv.b64(seal(_override={"v": "1"})),
    "id_missing": bv.b64(reseal(signed_by(sender, without("id")))),
    "id_too_long": bv.b64(seal(_override={"id": "A" * 23})),
    "id_not_canonical_base64url": bv.b64(seal(_override={"id": worsen(opened["id"])})),
    "pair_missing": bv.b64(reseal(signed_by(sender, without("pair")))),
    "pair_not_canonical_base64url": bv.b64(seal(_override={"pair": worsen(opened["pair"])})),
    "created_is_text": bv.b64(seal(_override={"created": str(NOW)})),
    "created_is_not_whole": bv.b64(seal(_override={"created": NOW + 0.5})),
    "created_is_zero": bv.b64(seal(_override={"created": 0})),
    "expires_is_text": bv.b64(seal(_override={"expires": "never"})),
    "expires_is_not_whole": bv.b64(seal(_override={"expires": NOW + 3600.5})),
    "expires_is_zero": bv.b64(seal(_override={"expires": 0})),
    "from_name_is_a_number": bv.b64(seal(_override={"from_name": 42})),
    "type_is_a_number": bv.b64(seal(_override={"type": 7})),
    "type_is_missing": bv.b64(reseal(signed_by(sender, without("type")))),
    "from_is_a_number": bv.b64(seal(_override={"from": 12345})),
    "from_host_is_an_ip_address": bv.b64(reseal(signed_by(sender, message_json.replace(b"@relay.example", b"@192.168.1.10")))),
    "from_name_is_empty": bv.b64(seal(_override={"from_name": ""})),
    "from_name_is_41_characters": bv.b64(seal(_override={"from_name": "x" * 41})),
    "ticket_missing": bv.b64(reseal(signed_by(sender, without("ticket")))),
    "message_is_an_array": bv.b64(reseal(signed_by(sender, b"[1,2,3]"))),
    "seventeen_levels_of_nesting": bv.b64(seal(_override={"deep": json.loads("[" * 16 + "]" * 16)})),
    "unpaired_surrogate": bv.b64(reseal(signed_by(sender, message_json.replace(b"Dag Jan!", b"Dag \\ud800 Jan!")))),
    "nan_is_not_json": bv.b64(reseal(signed_by(sender, message_json[:-1] + b',"x":NaN}'))),
    # --- time
    "expired_one_second_ago": bv.b64(seal(expires=NOW - 1)),
    "created_601_seconds_ahead": bv.b64(seal(now=NOW + 601)),
    "created_8_days_and_a_second_ago": bv.b64(seal(now=NOW - 691201)),
}

may_reject = {
    "note": "The spec lets a receiver accept or reject these (section 1.2). Either is conformant.",
    "duplicate_member": bv.b64(reseal(signed_by(sender, message_json[:-1] + b',"v":1}'))),
    "integer_written_with_a_fraction": bv.b64(reseal(signed_by(sender, message_json.replace(b'"created":1795000000', b'"created":1795000000.0')))),
}

other_pair = bv.b64(hashlib.sha256(b"some-other-secret").digest()[:16])
KAJ = public(sender)["signing_public"]
EVE = public(stranger)["signing_public"]
second_pair = bv.b64(hashlib.sha256(b"vector-pair-2").digest()[:16])


def step(sealed_bytes, expect, state, pinned, why):
    return {"sealed": bv.b64(sealed_bytes), "expect": expect, "state_after": state, "pinned_after": pinned, "why": why}


contact_checks = {
    "note": "The recipient has ONE contact: created from `cards.valid` at time `contact.issued`, in state open. "
            "Handle the steps in order at time `now`. `expect` is what happens to the message: `discard`, `hold` (a valid "
            "ticket queued for a contact that is not confirmed), or `print`. A step with `action` instead of `sealed` is "
            "something the owner does. `state_after` and `pinned_after` describe the contact after the step.",
    "contact": {"issued": CARD_ISSUED, "expires": card_expires, "pairing_secret": card["pair"]},
    "steps": [
        step(seal(who=stranger, _override={"pair": other_pair}, message_id=mid("A")), "discard", "open", None,
             "a valid message from a stranger: the pairing secret matches no contact"),
        step(seal(who=stranger, _override={"type": "hologram"}, message_id=mid("B")), "discard", "open", None,
             "right pairing secret, but not a ticket: it does not pair, and nothing about it is recorded"),
        step(seal(who=stranger, ticket={"blocks": [{"type": "list", "items": [""] * 51}]}, message_id=mid("C")), "discard", "open", None,
             "right pairing secret, but the ticket is invalid: it does not pair either"),
        {**step(sealed, "hold", "pending", KAJ, "right pairing secret and a valid ticket: the key is pinned, the owner is told, the ticket is held"),
         "notice_fingerprint": public(sender)["fingerprint"]},
        step(sealed, "discard", "pending", KAJ, "same signing key and id as the previous message: a repeat"),
        step(seal(who=stranger, message_id=mid("D")), "discard", "pending", KAJ,
             "right pairing secret and a valid ticket, but the contact is pinned to another key: a second party has the card"),
        step(seal(message_id=mid("J")), "hold", "pending", KAJ, "a second ticket from the pinned key, still not confirmed: held"),
        {"action": "confirm", "expect": "print 2 held tickets", "state_after": "paired", "pinned_after": KAJ,
         "why": "the owner confirms: the contact is paired and its held tickets are printed"},
        step(seal(_override={"pair": other_pair}, message_id=mid("E")), "print", "paired", KAJ,
             "the pinned sender: the pairing secret is no longer looked at"),
        step(seal(_override={"type": "hologram"}, message_id=mid("F")), "discard", "paired", KAJ,
             "authentic, but an unknown message type is dropped without printing (and recorded as handled)"),
        step(seal(now=CARD_ISSUED - 601, message_id=mid("G")), "discard", "paired", KAJ,
             "created more than 600 seconds before the contact's card was issued"),
        step(seal(now=CARD_ISSUED - 600, message_id=mid("H")), "print", "paired", KAJ,
             "created exactly 600 seconds before the card was issued: still accepted"),
    ],
    "held_limit": {
        "note": "A fresh copy of the same open contact. The first message pairs it (pending); of the next six tickets from that key, "
                "four more are held (five in total) and two are discarded.",
        "sealed": [bv.b64(seal(message_id=bytes([200 + i]) * 16)) for i in range(7)],
        "expect": ["hold"] * 5 + ["discard"] * 2,
    },
    "expired_card": {
        "note": "A fresh, open copy of the same contact, handled at time `now`, which is after the card expired.",
        "now": card_expires + 1,
        "sealed": bv.b64(seal(now=card_expires + 1, message_id=mid("I"))),
        "expect": "discard", "state_after": "open", "pinned_after": None,
    },
    "two_contacts": {
        "note": "The recipient has TWO open contacts: `first` with the pairing secret of `cards.valid`, and `second` with "
                "`second_pairing_secret`. This recipient confirms automatically, so a pairing goes straight to paired. "
                "Each step says which contact the message belongs to.",
        "second_pairing_secret": second_pair,
        "steps": [
            {"sealed": bv.b64(seal(message_id=mid("K"))), "expect": "print", "contact": "first", "pinned": {"first": KAJ, "second": None},
             "why": "Kaj pairs with the first contact"},
            {"sealed": bv.b64(seal(_override={"pair": second_pair}, message_id=mid("L"))), "expect": "print", "contact": "first",
             "pinned": {"first": KAJ, "second": None},
             "why": "Kaj, already pinned, presents the second contact's secret: still the first contact, and the second stays open"},
            {"sealed": bv.b64(seal(who=stranger, _override={"pair": second_pair}, message_id=mid("K"))), "expect": "print", "contact": "second",
             "pinned": {"first": KAJ, "second": EVE},
             "why": "Eve pairs with the second contact, with an id Kaj already used: handled messages are remembered per signing key"},
            {"sealed": bv.b64(seal(who=stranger, _override={"pair": second_pair}, message_id=mid("K"))), "expect": "discard", "contact": None,
             "pinned": {"first": KAJ, "second": EVE}, "why": "the same message from Eve again: a repeat"},
        ],
    },
}


# --- hosts and cards
hosts = {
    "valid": ["bonvoyage.kaj.dev", "relay.example", "a.b.c.example", "relay.example:8443", "relay.example:1", "relay.example:65535",
              "xn--bcher-kva.example", "r3lay-2.example", ".".join(["a" * 61] * 4) + ".abcde:65535"],
    "must_reject": ["localhost", "localhost:8787", "printer", "router.lan.", "192.168.1.10", "192.168.1.10:9100", "127.1", "2130706433",
                    "0x7f000001", "0", "192.168.490", "relay.example:443", "relay.example:0", "relay.example:65536",
                    "relay.example:99999", "relay.example:080", "Relay.Example", "relay..example", "-relay.example", "relay-.example",
                    "relay.example/", "user@relay.example", "[::1]", "relay.123", "relay.ex4mple", "a" * 64 + ".example", "",
                    "relay.example\n", "relay.example:8\uff14\uff14\uff13", "relay.xn--p1ai", " relay.example",
                    ".".join(["a" * 60] * 5) + ".example"],
    "note": "localhost (with a port) is only a host in a client's development mode, which is off by default.",
}


def tamper(uri: str, old: str, new: str) -> str:
    assert old in uri, old
    return uri.replace(old, new, 1)


def resign(uri: str) -> str:
    """Re-sign a hand-edited card with the recipient's key, so that only its shape is wrong."""
    base, query = uri.split("?")
    host, inbox = base[len("bonvoyage://"):].split("/")
    f = dict(part.split("=", 1) for part in query.split("&") if not part.startswith("s="))
    name = bv.urllib.parse.unquote(f.get("n", ""))
    sig = SigningKey(bv.unb64(recipient["sign"])).sign(bv._card_signing_input(host, inbox, f["k"], f["t"], f["p"], f.get("e", ""), name)).signature
    return uri[:uri.index("&s=")] + "&s=" + bv.b64(sig)


named = identity(b"vector-recipient", "bonvoyage.example", "Jan & Co, café 100% + ♥")
minimal = identity(b"vector-recipient", "bonvoyage.example", "")
card_minimal = bv.make_card(minimal, token, pair)
card_named = bv.make_card(named, token, pair, expires=card_expires)
base, query = card_uri.split("?")
reordered = base + "?" + "&".join(reversed(query.split("&"))) + "&x=ignored"

cards = {
    "now": NOW,
    "valid": {"uri": card_uri, "relay": card["relay"], "inbox_id": card["inbox"], "encryption_key": bv.b64(card["key"]),
              "drop_token": card["token"], "pairing_secret": card["pair"], "expires": card_expires, "name": "Jan"},
    "signing_input": bv._card_signing_input(card["relay"], card["inbox"], bv.b64(card["key"]), card["token"], card["pair"],
                                            str(card_expires), "Jan").decode(),
    "also_valid": {
        "without_expiry_or_name": {"uri": card_minimal, "expires": None, "name": "",
                                   "signing_input": bv._card_signing_input(card["relay"], card["inbox"], bv.b64(card["key"]), card["token"], card["pair"], "", "").decode()},
        "name_with_special_characters": {"uri": card_named, "expires": card_expires, "name": "Jan & Co, café 100% + ♥"},
        "other_order_and_unknown_parameter": {"uri": reordered, "expires": card_expires, "name": "Jan"},
    },
    "must_reject": {
        "encryption_key_swapped": tamper(card_uri, "k=" + bv.b64(card["key"]), "k=" + public(stranger)["encryption_public"]),
        "relay_changed": tamper(card_uri, "bonvoyage.example", "evil.example"),
        "expiry_extended": tamper(card_uri, f"e={card_expires}", f"e={card_expires + 999999}"),
        "name_changed": tamper(card_uri, "n=Jan", "n=Mum"),
        "signature_missing": card_uri[:card_uri.index("&s=")],
        "signature_not_canonical": card_uri[:-1] + worsen(card_uri[-1:]),
        "token_repeated": card_uri + "&t=" + card["token"],
        "wrong_version": tamper(card_uri, "v=1", "v=2"),
        "fragment": card_uri + "#x",
        "user_in_host": tamper(card_uri, "bonvoyage.example", "user@bonvoyage.example"),
        "wrong_scheme": tamper(card_uri, "bonvoyage://", "https://"),
        "extra_path": tamper(card_uri, "?v=1", "/more?v=1"),
        # correctly signed by the recipient, wrong in shape:
        "host_is_an_ip_address": resign(tamper(card_uri, "bonvoyage.example", "192.168.1.10:9100")),
        "host_is_a_number": resign(tamper(card_uri, "bonvoyage.example", "2130706433")),
        "host_is_a_short_ip_form": resign(tamper(card_uri, "bonvoyage.example", "127.1")),
        "host_is_a_single_label": resign(tamper(card_uri, "bonvoyage.example", "printer")),
        "host_is_localhost": resign(tamper(card_uri, "bonvoyage.example", "localhost:9100")),
        "host_has_port_99999": resign(tamper(card_uri, "bonvoyage.example", "bonvoyage.example:99999")),
        "host_writes_port_443": resign(tamper(card_uri, "bonvoyage.example", "bonvoyage.example:443")),
        "host_in_upper_case": resign(tamper(card_uri, "bonvoyage.example", "Bonvoyage.Example")),
        "expiry_with_leading_zero": resign(tamper(card_uri, f"e={card_expires}", f"e=0{card_expires}")),
        "expiry_empty": tamper(card_minimal, "&s=", "&e=&s="),
        "name_empty": tamper(card_minimal, "&s=", "&n=&s="),
        "name_of_41_characters": resign(tamper(card_uri, "n=Jan", "n=" + "x" * 41)),
        "name_with_bad_percent_escape": resign(tamper(card_uri, "n=Jan", "n=Jan%2")),
        "name_is_not_utf8": resign(tamper(card_uri, "n=Jan", "n=Jan%FF")),
        "already_expired": bv.make_card(recipient, token, pair, expires=NOW - 1),
        "encryption_key_not_canonical": resign(tamper(card_uri, "k=" + bv.b64(card["key"]), "k=" + worsen(bv.b64(card["key"])))),
        "token_too_short": resign(tamper(card_uri, "t=" + card["token"], "t=" + card["token"][:-4])),
        "token_not_base64url": resign(tamper(card_uri, "t=" + card["token"], "t=" + card["token"][:-1] + "!")),
        "pairing_secret_too_short": resign(tamper(card_uri, "p=" + card["pair"], "p=" + card["pair"][:-2])),
        "pairing_secret_too_long": resign(tamper(card_uri, "p=" + card["pair"], "p=" + card["pair"] + "AA")),
        "pairing_secret_not_canonical": resign(tamper(card_uri, "p=" + card["pair"], "p=" + worsen(card["pair"]))),
        "expiry_beyond_range": resign(tamper(card_uri, f"e={card_expires}", f"e={2 ** 40}")),
        "expiry_in_other_digits": resign(tamper(card_uri, f"e={card_expires}", "e=1\u0667\u0669\u0665000000")),
        "host_with_a_trailing_line_feed": tamper(card_uri, "bonvoyage.example/", "bonvoyage.example%0A/"),
    },
}

# --- tickets
euro = "€"
tickets = {
    "valid": {
        "the_example": ticket,
        "at_the_limits": {"blocks": [{"type": "list", "items": ["x"] * 50}] * 5 + [{"type": "space", "lines": 5}] * 10},
        "two_small_images": {"blocks": [{"type": "image", "png": png(576, 800), "alt": "a"}, {"type": "image", "png": png(8, 800)}]},
        "8000_characters_outside_the_basic_plane": {"blocks": [{"type": "text", "text": "\U0001f600" * 8000}]},
        "qr_of_510_bytes": {"blocks": [{"type": "qr", "data": euro * 170}]},
        "wrongly_typed_dressing_is_ignored": {"blocks": [
            {"type": "text", "text": "x", "bold": "yes", "align": 5, "size": "gigantic", "underline": None},
            {"type": "list", "items": ["x"], "style": 7}, {"type": "qr", "data": "x", "caption": 7},
            {"type": "image", "png": png(8, 8), "alt": ["no"]}]},
        "100_unknown_blocks": {"blocks": [{"type": "hologram"}] * 100},
        "8000_characters_spread_over_all_text_members": {"blocks": [
            {"type": "text", "text": "a" * 2000}, {"type": "list", "items": ["b" * 2000]},
            {"type": "qr", "data": "x", "caption": "c" * 2000}, {"type": "image", "png": png(8, 8), "alt": "d" * 2000}]},
        "8_bit_greyscale_image": {"blocks": [{"type": "image", "png": png(8, 8, depth=8)}]},
        "empty": {"blocks": []},
    },
    "must_discard": {
        "101_blocks": {"blocks": [{"type": "divider"}] * 101},
        "101_unknown_blocks": {"blocks": [{"type": "hologram"}] * 101},
        "empty_list_items_flood": {"blocks": [{"type": "list", "items": [""] * 51}]},
        "301_lines_from_line_feeds": {"blocks": [{"type": "text", "text": "\n" * 300}]},
        "301_lines_from_lists": {"blocks": [{"type": "list", "items": [""] * 50}] * 6 + [{"type": "divider"}]},
        "8001_characters": {"blocks": [{"type": "text", "text": "a" * 8001}]},
        "8001_characters_outside_the_basic_plane": {"blocks": [{"type": "text", "text": "\U0001f600" * 8001}]},
        "space_of_6_lines": {"blocks": [{"type": "space", "lines": 6}]},
        "space_lines_as_text": {"blocks": [{"type": "space", "lines": "2"}]},
        "qr_of_513_bytes": {"blocks": [{"type": "qr", "data": euro * 171}]},
        "qr_without_data": {"blocks": [{"type": "qr", "data": ""}]},
        "qr_data_member_missing": {"blocks": [{"type": "qr", "caption": "x"}]},
        "qr_data_is_a_number": {"blocks": [{"type": "qr", "data": 42}]},
        "caption_pushes_past_8000_characters": {"blocks": [{"type": "text", "text": "a" * 7000}, {"type": "qr", "data": "x", "caption": "c" * 1001}]},
        "alt_pushes_past_8000_characters": {"blocks": [{"type": "text", "text": "a" * 7000}, {"type": "image", "png": png(8, 8), "alt": "d" * 1001}]},
        "list_items_is_text": {"blocks": [{"type": "list", "items": "abc"}]},
        "image_png_member_missing": {"blocks": [{"type": "image", "alt": "x"}]},
        "image_first_chunk_is_not_the_header": {"blocks": [{"type": "image", "png": png(8, 8, first=chunk(b"tEXt", b"hello\0world"))}]},
        "image_is_rgb": {"blocks": [{"type": "image", "png": png(8, 8, depth=8, colour=2)}]},
        "image_has_an_alpha_channel": {"blocks": [{"type": "image", "png": png(8, 8, depth=8, colour=4)}]},
        "image_is_16_bit": {"blocks": [{"type": "image", "png": png(8, 8, depth=16)}]},
        "image_is_interlaced": {"blocks": [{"type": "image", "png": png(8, 8, interlace=1)}]},
        "5_qr_codes": {"blocks": [{"type": "qr", "data": "x"}] * 5},
        "3_images": {"blocks": [{"type": "image", "png": png(8, 8)}] * 3},
        "image_too_wide": {"blocks": [{"type": "image", "png": png(577, 8)}]},
        "image_too_tall": {"blocks": [{"type": "image", "png": png(8, 1201)}]},
        "images_too_tall_together": {"blocks": [{"type": "image", "png": png(8, 900)}] * 2},
        "image_header_claims_huge_size": {"blocks": [{"type": "image", "png": png(8, 8, claim=(65535, 65535))}]},
        "image_header_claims_zero_width": {"blocks": [{"type": "image", "png": png(8, 8, claim=(0, 8))}]},
        "image_header_checksum_wrong": {"blocks": [{"type": "image", "png": png(8, 8, break_crc=True)}]},
        "image_is_not_a_png": {"blocks": [{"type": "image", "png": bv.b64(b"GIF89a" + b"\0" * 40)}]},
        "image_not_canonical_base64url": {"blocks": [{"type": "image", "png": worsen(bv.b64(
            bv.unb64(png(8, 8)) + b"\0" * (1 if len(bv.unb64(png(8, 8))) % 3 != 2 else 2)))}]},
        "block_is_not_an_object": {"blocks": ["text"]},
        "text_is_a_number": {"blocks": [{"type": "text", "text": 42}]},
        "text_is_missing": {"blocks": [{"type": "text"}]},
        "list_item_is_a_number": {"blocks": [{"type": "list", "items": ["a", 1]}]},
        "blocks_is_not_an_array": {"blocks": {"type": "text", "text": "x"}},
    },
    "may_discard": {"space_lines_written_with_a_fraction_json": '{"blocks":[{"type":"space","lines":2.0}]}'},
    "text_cleaning": [
        {"where": "text block", "input": "a\u001b@b\u001dV\u0000c\td\ne‮f g\u0007", "output": "a@bVc d\nef g"},
        {"where": "list item, caption, alt, names", "input": "a\u001bb\nc\td​e", "output": "ab c de"},
        {"where": "text block", "input": "a\u0085b\u007fc\rd e﻿f\U000e0001g\u009bh", "output": "abcd efgh",
         "note": "C1 controls, DEL, carriage return, paragraph separator, BOM, a format character outside the basic plane"},
        {"where": "anywhere", "input": "\U0001f468‍\U0001f469‍\U0001f467 می‌خ", "output": "\U0001f468‍\U0001f469‍\U0001f467 می‌خ",
         "note": "the joiners U+200D and U+200C are kept"},
    ],
}


def owner_vector(who: dict, method: str, path: str, body: bytes) -> dict:
    signing_input = f"bonvoyage-v1-request\n{method}\n{who['relay']}\n{path}\n{NOW}\n{hashlib.sha256(body).hexdigest()}"
    sig = SigningKey(bv.unb64(who["sign"])).sign(signing_input.encode()).signature
    return {"signing_secret_seed": who["sign"], "method": method, "host": who["relay"], "path": path, "time": NOW,
            "body": body.decode(), "signing_input": signing_input, "header": f"t={NOW},sig={bv.b64(sig)}"}


with_port = identity(b"vector-recipient", "relay.example:8443", "Jan")
inbox_path = f"/v1/inbox/{bv.inbox_id(recipient)}"

vectors = {
    "about": "Bonvoyage protocol v1 test vectors. All binary values are base64url without padding. See README.md.",
    "now": NOW,
    "sender": public(sender),
    "recipient": public(recipient),
    "stranger": public(stranger),
    "base64url": {
        "canonical": {"text": "AQID", "bytes_hex": "010203"},
        "must_reject": ["AQID=", "AQJ", "AQ+D", "AQ D", "AR", "A"],
        "note": "AR decodes to the same byte as AQ, and AQJ to the same bytes as AQI, but with non-zero unused bits.",
    },
    "hosts": hosts,
    "addresses": {
        "note": "What a client may connect to after resolving a relay's name (section 1.2).",
        "public": ["93.184.216.34", "1.1.1.1", "2a02:1810::1", "2606:4700:4700::1111", "64:ff9b::5db8:d822", "::ffff:93.184.216.34"],
        "must_refuse": ["0.0.0.0", "0.1.2.3", "10.0.0.5", "100.64.0.1", "127.0.0.1", "127.1.2.3", "169.254.1.1", "172.16.0.1", "172.31.255.255",
                        "192.0.0.8", "192.168.1.234", "198.18.0.1", "224.0.0.1", "240.0.0.1", "255.255.255.255",
                        "::", "::1", "fc00::1", "fd00::1", "fe80::1", "fec0::1", "ff02::1",
                        "::ffff:192.168.1.1", "::192.168.1.1", "::ffff:0:192.168.1.1", "64:ff9b::192.168.1.1", "64:ff9b::7f00:1",
                        "2002:c0a8:0101::1", "2002:7f00:0001::1", "2001:0:4136:e378:8000:63bf:3f57:fefe"],
        "teredo_note": "The last address is Teredo; the IPv4 address inside it is 192.168.1.1, stored with its bits inverted.",
    },
    "proof_of_work": {
        "inbox_id": public(recipient)["inbox_id"], "bits": 12, "nonce": bv.proof_of_work(public(recipient)["inbox_id"], 12),
        "input": "bonvoyage-v1-pow\n" + public(recipient)["inbox_id"] + "\n" + bv.proof_of_work(public(recipient)["inbox_id"], 12),
        "digest_hex": hashlib.sha256(("bonvoyage-v1-pow\n" + public(recipient)["inbox_id"] + "\n"
                                       + bv.proof_of_work(public(recipient)["inbox_id"], 12)).encode()).hexdigest(),
        "note": "`nonce` is the smallest one for 12 bits; any nonce whose digest starts with at least `bits` zero bits is valid.",
    },
    "drop_token": {"token": bv.b64(token), "token_id": bv.token_id(token)},
    "cards": cards,
    "message": {
        "message_json": message_json.decode(),
        "msg": signed["msg"],
        "sig": signed["sig"],
        "signed_message_json": signed_bytes.decode(),
        "padded_length": len(padded),
        "sealed": bv.b64(sealed),
        "sealed_length": len(sealed),
        "expect_plain_text": bv.render_text(opened["ticket"]),
    },
    "must_accept": must_accept,
    "must_reject": must_reject,
    "may_reject": may_reject,
    "contact_checks": contact_checks,
    "tickets": tickets,
    "owner_requests": [
        owner_vector(recipient, "PUT", inbox_path, json.dumps({"tokens": [bv.token_id(token)]}).encode()),
        owner_vector(recipient, "GET", inbox_path + "/messages", b""),
        owner_vector(with_port, "DELETE", inbox_path, b""),
    ],
    "relay_response": {
        "note": "A collect response a client must handle: it looks at the first 20 entries only, and of those skips every one without a valid relay message id.",
        "ids_in_response": ["ok-1", "../../inbox", "", "a" * 65, "ok_2", 7] + [f"n{i}" for i in range(30)],
        "ids_to_process": ["ok-1", "ok_2"] + [f"n{i}" for i in range(14)],
    },
}
out = pathlib.Path(__file__).parent / "v1.json"
out.write_text(json.dumps(vectors, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
assert bv.is_public_address("93.184.216.34")
print(f"wrote {out} ({out.stat().st_size} bytes): {len(must_reject)} messages to reject, {len(must_accept) - 1} to accept, "
      f"{len(cards['must_reject'])} bad cards, {len(tickets['must_discard'])} bad tickets, {len(hosts['must_reject'])} bad hosts")
