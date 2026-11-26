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
    return {"relay": relay, "name": name, "sign": bv.b64(sign), "enc": bv.b64(enc), "contacts": {}, "seen": {}}


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


def png(width: int, height: int) -> str:
    """A valid 1-bit all-white PNG of the given size, base64url."""
    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
    rows = (b"\0" + b"\xff" * ((width + 7) // 8)) * height
    data = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 1, 0, 0, 0, 0)) \
        + chunk(b"IDAT", zlib.compress(rows, 9)) + chunk(b"IEND", b"")
    return bv.b64(data)


sender = identity(b"vector-sender", "relay.example", "Kaj")
recipient = identity(b"vector-recipient", "bonvoyage.example", "Jan")
stranger = identity(b"vector-stranger", "relay.example", "Eve")
token = hashlib.sha256(b"vector-token").digest()
pair = hashlib.sha256(b"vector-pair").digest()[:16]
card_expires = NOW + 7 * 24 * 3600
card_uri = bv.make_card(recipient, token, pair, expires=card_expires)
card = bv.parse_card(card_uri)
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


sealed = seal()
padded = SealedBox(enc_secret).decrypt(sealed)
length = int.from_bytes(padded[:4], "big")
signed_bytes = padded[4:4 + length]
signed = json.loads(signed_bytes)
_, opened = bv.open_message(recipient, sealed, now=NOW)


def reseal(signed_json: bytes | dict) -> bytes:
    data = signed_json if isinstance(signed_json, bytes) else json.dumps(signed_json, separators=(",", ":")).encode()
    return bv.seal_signed(data, card["key"])


def raw_seal(plaintext: bytes) -> bytes:
    return SealedBox(enc_secret.public_key).encrypt(plaintext)


def signed_by(who: dict, message_json: bytes) -> dict:
    sig = SigningKey(bv.unb64(who["sign"])).sign(bv.MESSAGE_CONTEXT + message_json).signature
    return {"msg": bv.b64(message_json), "sig": bv.b64(sig)}


message_json = bv.unb64(signed["msg"])
flipped_sig = bytearray(bv.unb64(signed["sig"]))
flipped_sig[0] ^= 1
loose = base64.urlsafe_b64encode(message_json).decode()  # keeps '=' padding: not canonical

must_reject = {
    # --- sealing and padding
    "bit_flipped": bv.b64(sealed[:100] + bytes([sealed[100] ^ 1]) + sealed[101:]),
    "length_prefix_too_large": bv.b64(raw_seal(struct.pack(">I", 5000) + signed_bytes + b"\0" * (4096 - 4 - len(signed_bytes)))),
    "padding_not_zero": bv.b64(raw_seal(struct.pack(">I", length) + signed_bytes + b"\0" * (4096 - 5 - length) + b"\x01")),
    "not_a_multiple_of_4096": bv.b64(raw_seal(struct.pack(">I", length) + signed_bytes)),
    # --- signature
    "signature_changed": bv.b64(reseal({"msg": signed["msg"], "sig": bv.b64(bytes(flipped_sig))})),
    "signed_by_another_key_than_from": bv.b64(reseal(signed_by(stranger, message_json))),
    "msg_not_canonical_base64url": bv.b64(reseal({"msg": loose, "sig": signed["sig"]})),
    # --- members and types (all correctly signed by the sender)
    "wrong_recipient": bv.b64(seal(_override={"to": bv.address(sender)})),
    "version_is_true": bv.b64(seal(_override={"v": True})),
    "version_is_text": bv.b64(seal(_override={"v": "1"})),
    "id_missing": bv.b64(reseal(signed_by(sender, json.dumps({k: v for k, v in opened.items() if k != "id"}).encode()))),
    "id_too_long": bv.b64(seal(_override={"id": "A" * 23})),
    "created_is_text": bv.b64(seal(_override={"created": str(NOW)})),
    "created_is_a_fraction": bv.b64(seal(_override={"created": NOW + 0.5})),
    "from_is_a_number": bv.b64(seal(_override={"from": 12345})),
    "pair_missing": bv.b64(reseal(signed_by(sender, json.dumps({k: v for k, v in opened.items() if k != "pair"}).encode()))),
    "ticket_missing": bv.b64(reseal(signed_by(sender, json.dumps({k: v for k, v in opened.items() if k != "ticket"}).encode()))),
    "message_is_an_array": bv.b64(reseal(signed_by(sender, b'[1,2,3]'))),
    "duplicate_member": bv.b64(reseal(signed_by(sender, message_json[:-1] + b',"v":1}'))),
    "nested_too_deep": bv.b64(seal(_override={"extra": json.loads("[" * 20 + "]" * 20)})),
    "unpaired_surrogate": bv.b64(reseal(signed_by(sender, message_json.replace(b"Dag Jan!", b"Dag \\ud800 Jan!")))),
    # --- time
    "expired": bv.b64(seal(expires=NOW - 1)),
    "from_the_future": bv.b64(seal(now=NOW + 601)),
    "too_old": bv.b64(seal(now=NOW - 691201)),
}

# Accepted by the checks of 5.4 steps 1-6, but each one must still not print for the stated reason.
other_pair = bv.b64(hashlib.sha256(b"some-other-secret").digest()[:16])
contact_checks = {
    "note": "The recipient has ONE contact, created from `contact_card`, not yet paired. Handle these in order.",
    "steps": [
        {"sealed": bv.b64(seal(who=stranger, _override={"pair": other_pair}, message_id=b"A" * 16)),
         "expect": "discard", "why": "valid message from a stranger: the pairing secret matches no contact"},
        {"sealed": bv.b64(sealed), "expect": "print", "why": "the pairing secret matches: the sender is paired and pinned"},
        {"sealed": bv.b64(sealed), "expect": "discard", "why": "same signing key and id as the previous message: a repeat"},
        {"sealed": bv.b64(seal(who=stranger, message_id=b"B" * 16)),
         "expect": "discard", "why": "right pairing secret, but the contact is already pinned to another key: the card leaked"},
        {"sealed": bv.b64(seal(_override={"pair": other_pair}, message_id=b"C" * 16)),
         "expect": "print", "why": "the pinned sender: the pairing secret is no longer looked at"},
        {"sealed": bv.b64(seal(_override={"type": "hologram"}, message_id=b"D" * 16)),
         "expect": "discard", "why": "authentic, but an unknown message type is dropped without printing"},
    ],
}

# --- cards
def tamper(uri: str, old: str, new: str) -> str:
    assert old in uri
    return uri.replace(old, new, 1)


cards = {
    "valid": {"uri": card_uri, "relay": card["relay"], "inbox_id": card["inbox"], "encryption_key": bv.b64(card["key"]),
              "drop_token": card["token"], "pairing_secret": card["pair"], "expires": card_expires, "name": "Jan"},
    "signing_input": bv._card_signing_input(card["relay"], card["inbox"], bv.b64(card["key"]), card["token"], card["pair"],
                                            str(card_expires), "Jan").decode(),
    "must_reject": {
        "encryption_key_swapped": tamper(card_uri, "k=" + bv.b64(card["key"]), "k=" + public(stranger)["encryption_public"]),
        "relay_changed": tamper(card_uri, "bonvoyage.example", "evil.example"),
        "expiry_extended": tamper(card_uri, f"e={card_expires}", f"e={card_expires + 999999}"),
        "name_changed": tamper(card_uri, "n=Jan", "n=Mum"),
        "signature_missing": card_uri[:card_uri.index("&s=")],
        "token_repeated": card_uri + "&t=" + card["token"],
        "wrong_version": tamper(card_uri, "v=1", "v=2"),
        "ip_address_host": tamper(card_uri, "bonvoyage.example", "192.168.1.10:9100"),
        "localhost_with_path": tamper(card_uri, "bonvoyage.example/", "localhost:9100/../../"),
        "user_in_host": tamper(card_uri, "bonvoyage.example", "user@bonvoyage.example"),
        "wrong_scheme": tamper(card_uri, "bonvoyage://", "https://"),
        "upper_case_host": tamper(card_uri, "bonvoyage.example", "Bonvoyage.Example"),
    },
}

# --- tickets
tickets = {
    "valid": {
        "the_example": ticket,
        "at_the_limits": {"blocks": [{"type": "list", "items": ["x"] * 50}] * 5 + [{"type": "space", "lines": 5}] * 10},
        "two_small_images": {"blocks": [{"type": "image", "png": png(576, 800), "alt": "a"}, {"type": "image", "png": png(8, 800)}]},
    },
    "must_discard": {
        "101_blocks": {"blocks": [{"type": "divider"}] * 101},
        "empty_list_items_flood": {"blocks": [{"type": "list", "items": [""] * 51}]},
        "301_lines_from_line_feeds": {"blocks": [{"type": "text", "text": "\n" * 300}]},
        "301_lines_from_lists": {"blocks": [{"type": "list", "items": [""] * 50}] * 6 + [{"type": "divider"}]},
        "8001_characters": {"blocks": [{"type": "text", "text": "a" * 8001}]},
        "space_of_6_lines": {"blocks": [{"type": "space", "lines": 6}]},
        "qr_data_too_long": {"blocks": [{"type": "qr", "data": "a" * 513}]},
        "5_qr_codes": {"blocks": [{"type": "qr", "data": "x"}] * 5},
        "3_images": {"blocks": [{"type": "image", "png": png(8, 8)}] * 3},
        "image_too_wide": {"blocks": [{"type": "image", "png": png(577, 8)}]},
        "image_too_tall": {"blocks": [{"type": "image", "png": png(8, 1201)}]},
        "images_too_tall_together": {"blocks": [{"type": "image", "png": png(8, 900)}] * 2},
        "image_claims_huge_size": {"blocks": [{"type": "image", "png": bv.b64(
            bv.unb64(png(8, 8))[:16] + struct.pack(">II", 65535, 65535) + bv.unb64(png(8, 8))[24:])}]},
        "image_is_not_a_png": {"blocks": [{"type": "image", "png": bv.b64(b"GIF89a" + b"\0" * 40)}]},
        "block_is_not_an_object": {"blocks": ["text"]},
        "text_is_a_number": {"blocks": [{"type": "text", "text": 42}]},
        "list_item_is_a_number": {"blocks": [{"type": "list", "items": ["a", 1]}]},
        "blocks_is_not_an_array": {"blocks": {"type": "text", "text": "x"}},
    },
    "text_cleaning": [
        {"where": "text block", "input": "a\u001b@b\u001dV\u0000c\td\ne‮f g\u0007", "output": "a@bVc d\nef g"},
        {"where": "list item, caption, alt, names", "input": "a\u001bb\nc\td​e", "output": "ab c de"},
    ],
}

body = json.dumps({"tokens": [bv.token_id(token)]}).encode()
path = f"/v1/inbox/{bv.inbox_id(recipient)}"
request_input = f"bonvoyage-v1-request\nPUT\n{recipient['relay']}\n{path}\n{NOW}\n{hashlib.sha256(body).hexdigest()}"
request_sig = SigningKey(bv.unb64(recipient["sign"])).sign(request_input.encode()).signature

vectors = {
    "about": "Bonvoyage protocol v1 test vectors. All binary values are base64url without padding. See README.md.",
    "now": NOW,
    "sender": public(sender),
    "recipient": public(recipient),
    "stranger": public(stranger),
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
    "must_reject": must_reject,
    "contact_checks": contact_checks,
    "tickets": tickets,
    "owner_request": {
        "signed_by": "recipient", "method": "PUT", "host": recipient["relay"], "path": path, "time": NOW,
        "body": body.decode(), "signing_input": request_input,
        "header": f"t={NOW},sig={bv.b64(request_sig)}",
    },
    "base64url": {
        "canonical": {"text": "AQID", "bytes_hex": "010203"},
        "must_reject": ["AQID=", "AQJ", "AQ+D", "AQ D", "AR", "A"],
        "note": "AR decodes to the same byte as AQ, and AQJ to the same bytes as AQI, but with non-zero unused bits.",
    },
}
out = pathlib.Path(__file__).parent / "v1.json"
out.write_text(json.dumps(vectors, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
print(f"wrote {out} ({out.stat().st_size} bytes, {len(must_reject)} messages to reject, "
      f"{len(cards['must_reject'])} cards, {len(tickets['must_discard'])} tickets)")
