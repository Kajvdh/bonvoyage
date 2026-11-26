#!/usr/bin/env python3
"""Regenerates vectors/v1.json from fixed keys, using the reference client.

Everything is deterministic except `sealed`: sealing uses a fresh random key
every time, so implementations check that they can OPEN the given sealed
message, and that what they seal themselves can be opened with `recipient`.
"""
import hashlib
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent / "examples"))
import bonvoyage as bv  # noqa: E402
from nacl.public import PrivateKey  # noqa: E402
from nacl.signing import SigningKey  # noqa: E402


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


sender = identity(b"vector-sender", "relay.example", "Kaj")
recipient = identity(b"vector-recipient", "bonvoyage.example", "Jan")
token = hashlib.sha256(b"vector-token").digest()
created = 1795000000
ticket = {"blocks": [
    {"type": "text", "text": "Dag Jan! ♥", "size": "large", "align": "center", "bold": True},
    {"type": "divider"},
    {"type": "list", "style": "check", "items": ["koffie", "café € 2,50"]},
    {"type": "qr", "data": "https://example.com", "caption": "voorbeeld"},
    {"type": "hologram", "note": "unknown block types are skipped"},
]}
enc_public = bytes(PrivateKey(bv.unb64(recipient["enc"])).public_key)
sealed = bv.seal_message(sender, bv.address(recipient), enc_public, ticket, now=created, message_id=bytes(range(16)))
opened = bv.open_message(recipient, sealed, now=created)

# Recover the intermediate values of SPEC 5.2 and 5.3 for implementers to compare.
from nacl.public import SealedBox  # noqa: E402
padded = SealedBox(PrivateKey(bv.unb64(recipient["enc"]))).decrypt(sealed)
length = int.from_bytes(padded[:4], "big")
signed = json.loads(padded[4:4 + length])

body = json.dumps({"tokens": [bv.token_id(token)]}).encode()
path = f"/v1/inbox/{bv.inbox_id(recipient)}"
request_input = f"bonvoyage-v1-request\nPUT\n{path}\n{created}\n{hashlib.sha256(body).hexdigest()}"
request_sig = SigningKey(bv.unb64(recipient["sign"])).sign(request_input.encode()).signature

vectors = {
    "about": "Bonvoyage protocol v1 test vectors. All binary values are base64url without padding.",
    "sender": public(sender),
    "recipient": public(recipient),
    "drop_token": {"token": bv.b64(token), "token_id": bv.token_id(token)},
    "contact_card": {"issued_by": "recipient", "uri": bv.make_card(recipient, token)},
    "message": {
        "message_json": bv.unb64(signed["msg"]).decode(),
        "msg": signed["msg"],
        "sig": signed["sig"],
        "signed_message_json": padded[4:4 + length].decode(),
        "padded_length": len(padded),
        "sealed": bv.b64(sealed),
        "sealed_length": len(sealed),
        "opened_at": created,
        "expect_plain_text": bv.render_text(opened["ticket"]),
    },
    "owner_request": {
        "signed_by": "recipient", "method": "PUT", "path": path, "time": created,
        "body": body.decode(), "signing_input": request_input,
        "header": f"t={created},sig={bv.b64(request_sig)}",
    },
    "must_reject": {
        "note": "Each is the valid sealed message above with one change; open_message must refuse all of them.",
        "wrong_recipient_address": bv.b64(bv.seal_message(sender, "A" * 43 + "@elsewhere.example", enc_public, ticket, now=created)),
        "expired": bv.b64(bv.seal_message(sender, bv.address(recipient), enc_public, ticket, now=created, expires=created - 1)),
        "from_the_future": bv.b64(bv.seal_message(sender, bv.address(recipient), enc_public, ticket, now=created + 3600)),
        "bit_flipped": bv.b64(sealed[:100] + bytes([sealed[100] ^ 1]) + sealed[101:]),
    },
}
out = pathlib.Path(__file__).parent / "v1.json"
out.write_text(json.dumps(vectors, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
print(f"wrote {out} ({out.stat().st_size} bytes)")
