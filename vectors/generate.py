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
    return {"relay": relay, "name": name, "sign": bv.b64(sign), "enc": bv.b64(enc), "contacts": {}, "seen": {}, "queue": []}


def public(ident: dict) -> dict:
    return {
        "name": ident["name"],
        "signing_secret_seed": ident["sign"],
        "signing_public": bv.b64(bytes(SigningKey(bv.unb64(ident["sign"])).verify_key)),
        "encryption_secret": ident["enc"],
        "encryption_public": bv.b64(bytes(PrivateKey(bv.unb64(ident["enc"])).public_key)),
        "inbox_id": bv.inbox_id(ident),
        "address": bv.address(ident),
    }


def chunk(kind: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))


def png(width: int, height: int, claim: tuple[int, int] | None = None, break_crc: bool = False) -> str:
    """A 1-bit all-white PNG, base64url. `claim` writes other dimensions in the header (with a correct checksum)."""
    rows = (b"\0" + b"\xff" * ((width + 7) // 8)) * height
    header = chunk(b"IHDR", struct.pack(">IIBBBBB", *(claim or (width, height)), 1, 0, 0, 0, 0))
    if break_crc:
        header = header[:-1] + bytes([header[-1] ^ 1])
    return bv.b64(b"\x89PNG\r\n\x1a\n" + header + chunk(b"IDAT", zlib.compress(rows, 9)) + chunk(b"IEND", b""))


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
}

must_reject = {
    # --- sealing and padding
    "bit_flipped": bv.b64(sealed[:100] + bytes([sealed[100] ^ 1]) + sealed[101:]),
    "length_prefix_too_large": bv.b64(raw_seal(struct.pack(">I", 5000) + signed_bytes + b"\0" * (4096 - 4 - len(signed_bytes)))),
    "padding_not_zero": bv.b64(raw_seal(struct.pack(">I", length) + signed_bytes + b"\0" * (4096 - 5 - length) + b"\x01")),
    "not_a_multiple_of_4096": bv.b64(raw_seal(struct.pack(">I", length) + signed_bytes)),
    "sixteen_blocks": bv.b64(raw_seal(struct.pack(">I", length) + signed_bytes + b"\0" * (16 * 4096 - 4 - length))),
    # --- signature and wrapper
    "signature_changed": bv.b64(reseal({"msg": signed["msg"], "sig": bv.b64(bytes(flipped_sig))})),
    "signed_by_another_key_than_from": bv.b64(reseal(signed_by(stranger, message_json))),
    "msg_not_canonical_base64url": bv.b64(reseal({"msg": loose, "sig": signed["sig"]})),
    "sig_not_canonical_base64url": bv.b64(reseal({"msg": signed["msg"], "sig": worsen(signed["sig"])})),
    # --- members and types (all correctly signed by the sender)
    "wrong_recipient": bv.b64(seal(_override={"to": bv.address(sender)})),
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
contact_checks = {
    "note": "The recipient has ONE contact: created from `cards.valid` at time `contact.issued`, not yet paired. "
            "Handle the steps in order at time `now`. `pinned_after` is the signing key pinned to the contact after that step, or null.",
    "contact": {"issued": CARD_ISSUED, "expires": card_expires, "pairing_secret": card["pair"]},
    "steps": [
        {"sealed": bv.b64(seal(who=stranger, _override={"pair": other_pair}, message_id=mid("A"))), "expect": "discard", "pinned_after": None,
         "why": "a valid message from a stranger: the pairing secret matches no contact"},
        {"sealed": bv.b64(seal(who=stranger, _override={"type": "hologram"}, message_id=mid("B"))), "expect": "discard", "pinned_after": None,
         "why": "right pairing secret, but not a ticket: it must not pair, or a card thief could pair without anything printing"},
        {"sealed": bv.b64(seal(who=stranger, ticket={"blocks": [{"type": "list", "items": [""] * 51}]}, message_id=mid("C"))),
         "expect": "discard", "pinned_after": None, "why": "right pairing secret, but the ticket is invalid: it must not pair either"},
        {"sealed": bv.b64(sealed), "expect": "print", "pinned_after": public(sender)["signing_public"],
         "why": "right pairing secret and a valid ticket: the sender is paired and pinned"},
        {"sealed": bv.b64(sealed), "expect": "discard", "pinned_after": public(sender)["signing_public"],
         "why": "same signing key and id as the previous message: a repeat"},
        {"sealed": bv.b64(seal(who=stranger, message_id=mid("D"))), "expect": "discard", "pinned_after": public(sender)["signing_public"],
         "why": "right pairing secret and a valid ticket, but the contact is pinned to another key: the card reached someone else"},
        {"sealed": bv.b64(seal(_override={"pair": other_pair}, message_id=mid("E"))), "expect": "print", "pinned_after": public(sender)["signing_public"],
         "why": "the pinned sender: the pairing secret is no longer looked at"},
        {"sealed": bv.b64(seal(_override={"type": "hologram"}, message_id=mid("F"))), "expect": "discard", "pinned_after": public(sender)["signing_public"],
         "why": "authentic, but an unknown message type is dropped without printing"},
        {"sealed": bv.b64(seal(now=CARD_ISSUED - 601, message_id=mid("G"))), "expect": "discard", "pinned_after": public(sender)["signing_public"],
         "why": "created more than 600 seconds before the contact's card was issued"},
        {"sealed": bv.b64(seal(now=CARD_ISSUED - 600, message_id=mid("H"))), "expect": "print", "pinned_after": public(sender)["signing_public"],
         "why": "created exactly 600 seconds before the card was issued: still accepted"},
    ],
    "expired_card": {
        "note": "A fresh, unpaired copy of the same contact, handled at time `now`, which is after the card expired.",
        "now": card_expires + 1,
        "sealed": bv.b64(seal(now=card_expires + 1, message_id=mid("I"))),
        "expect": "discard", "pinned_after": None,
    },
}


# --- hosts and cards
hosts = {
    "valid": ["bonvoyage.kaj.dev", "relay.example", "a.b.c.example", "relay.example:8443", "relay.example:1", "relay.example:65535",
              "xn--bcher-kva.example", "r3lay-2.example"],
    "must_reject": ["localhost", "localhost:8787", "printer", "router.lan.", "192.168.1.10", "192.168.1.10:9100", "127.1", "2130706433",
                    "0x7f000001", "0", "192.168.490", "relay.example:443", "relay.example:0", "relay.example:65536",
                    "relay.example:99999", "relay.example:080", "Relay.Example", "relay..example", "-relay.example", "relay-.example",
                    "relay.example/", "user@relay.example", "[::1]", "relay.123", "relay.ex4mple", "a" * 64 + ".example", ""],
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
print(f"wrote {out} ({out.stat().st_size} bytes): {len(must_reject)} messages to reject, {len(must_accept) - 1} to accept, "
      f"{len(cards['must_reject'])} bad cards, {len(tickets['must_discard'])} bad tickets, {len(hosts['must_reject'])} bad hosts")
