#!/usr/bin/env python3
"""Bonvoyage reference client: the protocol of SPEC.md in one file.

It is meant to be read next to the spec, and to try the protocol by hand:

    python bonvoyage.py init  me.json  --relay bonvoyage.kaj.dev --name Kaj
    python bonvoyage.py card  me.json  Jan          # give the printed URI to Jan
    python bonvoyage.py send  me.json  '<card URI from someone>' 'Hallo!'
    python bonvoyage.py receive me.json

Needs PyNaCl (libsodium). It shows received tickets as text; a real client
hands them to its printer and applies the rest of the policy in SPEC section 8
(quiet hours, a daily limit per contact, approval of a new contact).
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import struct
import sys
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import zlib

from nacl.exceptions import BadSignatureError, CryptoError
from nacl.public import PrivateKey, PublicKey, SealedBox
from nacl.signing import SigningKey, VerifyKey

MESSAGE_CONTEXT = b"bonvoyage-v1-message\n"
REQUEST_CONTEXT = "bonvoyage-v1-request\n"
CARD_CONTEXT = "bonvoyage-v1-card\n"
BLOCK = 4096
SEAL_OVERHEAD = 48
MAX_SEALED = SEAL_OVERHEAD + 15 * BLOCK
MAX_AGE = 691200          # a message older than this is discarded (SPEC 5.4 step 6)
FUTURE_SKEW = 600
REMEMBER = 692000         # how long handled messages are remembered (step 7)
CARD_LIFETIME = 7 * 24 * 3600
MAX_RESPONSE = 4 * 1024 * 1024
MAX_DEPTH = 16
NAME_MAX = 40

B64 = re.compile(r"[A-Za-z0-9_-]*")
HOST = re.compile(r"(?=.{1,253}(?::|$))(?!\d+(\.\d+){3}(?::|$))[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*(:[1-9]\d{0,4})?")
INBOX = re.compile(r"[A-Za-z0-9_-]{43}")
SHORT = re.compile(r"[A-Za-z0-9_-]{22}")
RELAY_MESSAGE_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")


class Discard(ValueError):
    """A message, card or ticket that must not be used."""


# --- encodings (SPEC 1.2) ------------------------------------------------------

def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64(text, length: int | None = None) -> bytes:
    """Canonical base64url only."""
    if not isinstance(text, str) or not B64.fullmatch(text):
        raise Discard("not base64url")
    try:
        data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except ValueError as e:
        raise Discard("not base64url") from e
    if b64(data) != text or (length is not None and len(data) != length):
        raise Discard("not canonical base64url of the expected length")
    return data


def _depth(value, level: int = 1) -> None:
    if level > MAX_DEPTH:
        raise Discard("JSON nested too deeply")
    for child in (value.values() if isinstance(value, dict) else value if isinstance(value, list) else ()):
        _depth(child, level + 1)


def parse_json(data: bytes):
    """Strict JSON: valid UTF-8, no duplicate member names, no unpaired surrogates, bounded depth."""
    def no_duplicates(pairs):
        keys = [k for k, _ in pairs]
        if len(set(keys)) != len(keys):
            raise Discard("duplicate member name")
        return dict(pairs)
    try:
        text = data.decode("utf-8")
        value = json.loads(text, object_pairs_hook=no_duplicates)
        json.dumps(value, ensure_ascii=False).encode("utf-8")  # fails on an unpaired surrogate
    except (UnicodeError, ValueError, RecursionError) as e:
        if isinstance(e, Discard):
            raise
        raise Discard("not valid JSON") from e
    _depth(value)
    return value


def is_int(value, low: int, high: int) -> bool:
    return type(value) is int and low <= value < high  # `type is`: True and 1.0 are not integers here


def parse_address(text) -> tuple[bytes, str, str]:
    """(signing key, inbox ID, host). The host is a hint, not authenticated (SPEC 3.1)."""
    if not isinstance(text, str) or text.count("@") != 1:
        raise Discard("not an address")
    inbox, host = text.split("@")
    if not INBOX.fullmatch(inbox) or not HOST.fullmatch(host):
        raise Discard("not an address")
    return unb64(inbox, 32), inbox, host


# --- identity, tokens and cards (SPEC 2, 3, 4) ---------------------------------

def new_identity(relay: str, name: str = "") -> dict:
    if not HOST.fullmatch(relay):
        raise ValueError("relay must be a host name, optionally with a port")
    return {"relay": relay, "name": name, "sign": b64(bytes(SigningKey.generate())),
            "enc": b64(bytes(PrivateKey.generate())), "contacts": {}, "seen": {}}


def inbox_id(identity: dict) -> str:
    return b64(bytes(SigningKey(unb64(identity["sign"])).verify_key))


def address(identity: dict) -> str:
    return f"{inbox_id(identity)}@{identity['relay']}"


def token_id(token: bytes) -> str:
    return hashlib.sha256(token).hexdigest()


def _card_signing_input(host, inbox, k, t, p, e, name) -> bytes:
    return (CARD_CONTEXT + "\n".join([host, inbox, k, t, p, e, name])).encode()


def make_card(identity: dict, token: bytes, pair: bytes, expires: int | None = None) -> str:
    """A contact card URI (SPEC 3.2), signed by this identity."""
    enc_public = bytes(PrivateKey(unb64(identity["enc"])).public_key)
    name = clean_text(identity.get("name", ""))[:NAME_MAX]
    fields = {"v": "1", "k": b64(enc_public), "t": b64(token), "p": b64(pair)}
    if expires:
        fields["e"] = str(expires)
    if name:
        fields["n"] = name
    signing_input = _card_signing_input(identity["relay"], inbox_id(identity), fields["k"], fields["t"], fields["p"],
                                        fields.get("e", ""), name)
    fields["s"] = b64(SigningKey(unb64(identity["sign"])).sign(signing_input).signature)
    query = "&".join(f"{k}={urllib.parse.quote(v, safe='')}" for k, v in fields.items())
    return f"bonvoyage://{identity['relay']}/{inbox_id(identity)}?{query}"


def parse_card(uri: str) -> dict:
    """Check a card someone gave you. Raises Discard for anything that is not exactly a valid card."""
    match = re.fullmatch(r"bonvoyage://([^/?#@]+)/([^/?#]+)\?([^#]*)", uri if isinstance(uri, str) else "")
    if not match:
        raise Discard("not a Bonvoyage contact card")
    host, inbox, query = match.groups()
    if not HOST.fullmatch(host) or not INBOX.fullmatch(inbox):
        raise Discard("card has an invalid host or inbox ID")
    fields: dict[str, str] = {}
    for part in query.split("&"):
        key, sep, value = part.partition("=")
        if key in ("v", "k", "t", "p", "e", "n", "s"):
            if key in fields or not sep:
                raise Discard(f"card parameter {key} is repeated or empty")
            fields[key] = value
    if fields.get("v") != "1" or not all(k in fields for k in ("k", "t", "p", "s")):
        raise Discard("card is missing a field or has an unknown version")
    expires = fields.get("e", "")
    if expires and not re.fullmatch(r"[1-9]\d{0,12}", expires):
        raise Discard("card expiry is not a number")
    try:
        name = urllib.parse.unquote(fields.get("n", ""), errors="strict")
    except UnicodeDecodeError as e:
        raise Discard("card name is not UTF-8") from e
    if len(name) > NAME_MAX:
        raise Discard("card name is too long")
    signing_key = unb64(inbox, 32)
    key, pair = unb64(fields["k"], 32), unb64(fields["p"], 16)
    unb64(fields["t"], 32)
    try:
        VerifyKey(signing_key).verify(_card_signing_input(host, inbox, fields["k"], fields["t"], fields["p"], expires, name),
                                      unb64(fields["s"], 64))
    except (BadSignatureError, CryptoError, ValueError) as e:
        raise Discard("card signature does not match the inbox") from e
    return {"relay": host, "inbox": inbox, "address": f"{inbox}@{host}", "key": key, "token": fields["t"],
            "pair": fields["p"], "expires": int(expires) if expires else None, "name": clean_text(name)}


def issue_card(identity: dict, contact_name: str, *, now: int | None = None, lifetime: int = CARD_LIFETIME) -> str:
    """Create a contact with its own token and pairing secret, and return the card to hand over.
    The caller registers the new token with the relay (see `register`) and saves the identity."""
    now = int(time.time()) if now is None else now
    token, pair = os.urandom(32), os.urandom(16)
    identity["contacts"][token_id(token)] = {"name": contact_name, "pair": b64(pair), "expires": now + lifetime, "key": None}
    return make_card(identity, token, pair, expires=now + lifetime)


# --- messages (SPEC 5) ---------------------------------------------------------

def seal_message(identity: dict, card: dict, ticket: dict, *, expires: int | None = None, now: int | None = None,
                 message_id: bytes | None = None, _override: dict | None = None) -> bytes:
    """Build, sign, pad and seal a ticket for the issuer of `card`."""
    message = {
        "v": 1, "id": b64(message_id or os.urandom(16)), "type": "ticket",
        "from": address(identity), "to": card["address"], "pair": card["pair"],
        "created": int(time.time()) if now is None else now, "ticket": ticket,
    }
    if identity.get("name"):
        message["from_name"] = identity["name"][:NAME_MAX]
    if expires:
        message["expires"] = expires
    message.update(_override or {})  # only the test vectors use this, to build messages that must be refused
    m = json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode()
    signature = SigningKey(unb64(identity["sign"])).sign(MESSAGE_CONTEXT + m).signature
    return seal_signed(json.dumps({"msg": b64(m), "sig": b64(signature)}, separators=(",", ":")).encode(), card["key"])


def seal_signed(signed: bytes, recipient_key: bytes) -> bytes:
    padded = struct.pack(">I", len(signed)) + signed
    padded += b"\0" * (-len(padded) % BLOCK)
    if len(padded) + SEAL_OVERHEAD > MAX_SEALED:
        raise ValueError("ticket is too large")
    return SealedBox(PublicKey(recipient_key)).encrypt(padded)


def open_message(identity: dict, sealed: bytes, *, now: int | None = None) -> tuple[bytes, dict]:
    """Steps 1 to 6 of SPEC 5.4. Returns (sender's signing key, message) or raises Discard.
    The caller continues with the repeat check, the contact, recording and the ticket."""
    now = int(time.time()) if now is None else now
    # 1. open
    if len(sealed) < SEAL_OVERHEAD + BLOCK or len(sealed) > MAX_SEALED or (len(sealed) - SEAL_OVERHEAD) % BLOCK:
        raise Discard("not a sealed message")
    try:
        padded = SealedBox(PrivateKey(unb64(identity["enc"]))).decrypt(sealed)
    except CryptoError as e:
        raise Discard("cannot be opened with this key") from e
    # 2. unpad
    (length,) = struct.unpack(">I", padded[:4])
    if length > len(padded) - 4 or any(padded[4 + length:]):
        raise Discard("bad padding")
    # 3. unwrap
    signed = parse_json(padded[4:4 + length])
    if not isinstance(signed, dict):
        raise Discard("signed message is not an object")
    m, signature = unb64(signed.get("msg")), unb64(signed.get("sig"), 64)
    # 4. verify
    message = parse_json(m)
    if not isinstance(message, dict):
        raise Discard("message is not an object")
    sender_key, _, _ = parse_address(message.get("from"))
    try:
        VerifyKey(sender_key).verify(MESSAGE_CONTEXT + m, signature)
    except (BadSignatureError, CryptoError, ValueError) as e:
        raise Discard("signature does not verify") from e
    # 5. validate
    if type(message.get("v")) is not int or message["v"] != 1:
        raise Discard("unsupported version")
    if not isinstance(message.get("id"), str) or not SHORT.fullmatch(message["id"]):
        raise Discard("bad id")
    unb64(message["id"], 16)
    if not isinstance(message.get("type"), str):
        raise Discard("bad type")
    _, to_inbox, _ = parse_address(message.get("to"))
    if not hmac.compare_digest(to_inbox, inbox_id(identity)):
        raise Discard("not addressed to this printer")
    if not isinstance(message.get("pair"), str) or not SHORT.fullmatch(message["pair"]):
        raise Discard("bad pairing secret")
    unb64(message["pair"], 16)
    if not is_int(message.get("created"), 1, 2 ** 40):
        raise Discard("bad created")
    if "expires" in message and not is_int(message["expires"], 1, 2 ** 40):
        raise Discard("bad expires")
    if "from_name" in message and not (isinstance(message["from_name"], str) and len(message["from_name"]) <= NAME_MAX):
        raise Discard("bad from_name")
    if message["type"] == "ticket" and not isinstance(message.get("ticket"), dict):
        raise Discard("ticket is missing")
    # 6. time
    if message["created"] > now + FUTURE_SKEW:
        raise Discard("created in the future")
    if message["created"] < now - MAX_AGE:
        raise Discard("too old")
    if "expires" in message and message["expires"] < now:
        raise Discard("expired")
    return sender_key, message


def find_contact(identity: dict, sender_key: bytes, pair: str, now: int) -> tuple[dict, bool]:
    """SPEC 3.3. Returns (contact, newly_paired) or raises Discard."""
    key = b64(sender_key)
    for contact in identity["contacts"].values():
        if contact.get("key") == key:
            return contact, False
    matched = None
    for contact in identity["contacts"].values():  # no early exit: compare against every contact
        if hmac.compare_digest(contact["pair"].encode(), pair.encode()):
            matched = contact
    if matched is None:
        raise Discard("from nobody this printer knows")
    if matched.get("key"):
        raise Discard(f"ALERT: the card issued to {matched['name']} was used by someone else")
    if matched["expires"] < now:
        raise Discard(f"the card issued to {matched['name']} has expired for pairing")
    return matched, True


# --- relay (SPEC 6) ------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


_opener = urllib.request.build_opener(_NoRedirect)


def _base(host: str) -> str:
    if not HOST.fullmatch(host):
        raise ValueError("not a relay host")
    # Plain HTTP only to localhost, and only when development mode is switched on (SPEC 3.1).
    if os.environ.get("BONVOYAGE_DEV") == "1" and host.split(":")[0] == "localhost":
        return "http://" + host
    return "https://" + host


def _http(method: str, url: str, body: bytes | None, headers: dict) -> tuple[int, bytes]:
    request = urllib.request.Request(url, data=body, method=method, headers={"User-Agent": "bonvoyage", **headers})
    try:
        with _opener.open(request, timeout=15) as response:
            status, raw = response.status, response.read(MAX_RESPONSE + 1)
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read(MAX_RESPONSE + 1)
    if len(raw) > MAX_RESPONSE:
        raise RuntimeError("relay response is too large")
    return status, raw


def owner_request(identity: dict, method: str, path: str, body: dict | None = None, *, now: int | None = None,
                  _retry: bool = True):
    data = b"" if body is None else json.dumps(body).encode()
    t = str(int(time.time()) if now is None else now)
    signing_input = f"{REQUEST_CONTEXT}{method}\n{identity['relay']}\n{path}\n{t}\n{hashlib.sha256(data).hexdigest()}".encode()
    signature = SigningKey(unb64(identity["sign"])).sign(signing_input).signature
    status, raw = _http(method, _base(identity["relay"]) + path, data if body is not None else None,
                        {"Bonvoyage-Auth": f"t={t},sig={b64(signature)}"})
    if status == 409 and _retry and now is None:
        # The same request in the same second has the same signature, which a relay accepts only once
        # (SPEC 6.2). Sign again with a later time.
        time.sleep(1.1)
        return owner_request(identity, method, path, body, _retry=False)
    try:
        return status, (json.loads(raw) if raw else None)
    except ValueError:
        return status, None


def register(identity: dict) -> None:
    """Create the inbox, or replace its list of accepted tokens."""
    status, answer = owner_request(identity, "PUT", f"/v1/inbox/{inbox_id(identity)}", {"tokens": sorted(identity["contacts"])})
    if status != 200:
        raise RuntimeError(f"relay refused the inbox: {status} {answer}")


def drop(card: dict, sealed: bytes) -> None:
    status, raw = _http("POST", f"{_base(card['relay'])}/v1/inbox/{card['inbox']}/messages", sealed,
                        {"Authorization": f"Bearer {card['token']}"})
    if status != 201:
        raise RuntimeError(f"relay refused the message: {status} {raw[:200].decode(errors='replace')}")


def receive(identity: dict, *, now: int | None = None, persist=None) -> list[tuple[dict, dict]]:
    """Collect and handle waiting messages (SPEC 5.4). Returns (contact, message) pairs whose ticket may be printed.

    `persist` is called after a message is recorded as handled and before it is returned, so that a
    crash cannot make a ticket print twice (step 9). Every collected message is deleted from the relay.
    """
    now = int(time.time()) if now is None else now
    me = inbox_id(identity)
    status, answer = owner_request(identity, "GET", f"/v1/inbox/{me}/messages")
    if status != 200 or not isinstance(answer, dict) or not isinstance(answer.get("messages"), list):
        raise RuntimeError(f"cannot collect: {status}")
    identity["seen"] = {k: t for k, t in identity["seen"].items() if t > now - REMEMBER}
    accepted = []
    for item in answer["messages"][:20]:
        relay_id = item.get("id") if isinstance(item, dict) else None
        if not isinstance(relay_id, str) or not RELAY_MESSAGE_ID.fullmatch(relay_id):
            continue  # not something we can even ask the relay to delete
        try:
            sender_key, message = open_message(identity, unb64(item.get("body")), now=now)   # steps 1-6
            seen_key = f"{b64(sender_key)}:{message['id']}"
            if seen_key in identity["seen"]:                                                  # step 7
                raise Discard("already handled")
            contact, paired = find_contact(identity, sender_key, message["pair"], now)        # step 8
            identity["seen"][seen_key] = now                                                  # step 9
            if paired:
                contact["key"] = b64(sender_key)
                print(f"paired with {contact['name']} (key {b64(sender_key)[:8]}...)", file=sys.stderr)
            if persist:
                persist()
            if message["type"] == "ticket":                                                   # step 10
                validate_ticket(message["ticket"])
                accepted.append((contact, message))
        except Discard as e:
            print(f"discarded a message: {e}", file=sys.stderr)
        except Exception as e:  # any error at all means: discard and carry on (SPEC 5.4)
            print(f"discarded a message: unexpected {type(e).__name__}", file=sys.stderr)
        owner_request(identity, "DELETE", f"/v1/inbox/{me}/messages/{relay_id}")              # step 11
    return accepted


# --- tickets (SPEC 7) ----------------------------------------------------------

LIMITS = {"blocks": 100, "characters": 8000, "lines": 300, "list_items": 50, "qr_blocks": 4, "qr_bytes": 512,
          "images": 2, "image_width": 576, "image_height": 1200, "images_height": 1600}


def png_size(data: bytes) -> tuple[int, int]:
    """Width and height from a PNG header, without decoding any pixels (SPEC 7.4)."""
    if len(data) < 33 or data[:8] != b"\x89PNG\r\n\x1a\n" or data[12:16] != b"IHDR" or data[8:12] != b"\x00\x00\x00\r":
        raise Discard("image is not a PNG")
    if zlib.crc32(data[12:29]) != struct.unpack(">I", data[29:33])[0]:
        raise Discard("image header is damaged")
    return struct.unpack(">II", data[16:24])


def validate_ticket(ticket) -> None:
    """Enforce the structure and every limit of SPEC 7.1 and 7.2. Raises Discard for the whole ticket."""
    if not isinstance(ticket, dict) or not isinstance(ticket.get("blocks"), list):
        raise Discard("ticket has no blocks")
    blocks = ticket["blocks"]
    if len(blocks) > LIMITS["blocks"]:
        raise Discard("too many blocks")
    characters = lines = qrs = images = images_height = 0

    def text_of(block, member, required=False) -> str:
        value = block.get(member, None if required else "")
        if not isinstance(value, str):
            raise Discard(f"{member} is not text")
        return value

    for block in blocks:
        if not isinstance(block, dict):
            raise Discard("a block is not an object")
        kind = block.get("type")
        if kind == "text":
            text = text_of(block, "text", required=True)
            characters += len(text)
            lines += 1 + text.count("\n")
        elif kind == "divider":
            lines += 1
        elif kind == "list":
            items = block.get("items")
            if not isinstance(items, list) or not all(isinstance(i, str) for i in items):
                raise Discard("list items are not text")
            if len(items) > LIMITS["list_items"]:
                raise Discard("too many list items")
            characters += sum(len(i) for i in items)
            lines += len(items)
        elif kind == "space":
            count = block.get("lines", 1)
            if not is_int(count, 1, 6):
                raise Discard("space lines out of range")
            lines += count
        elif kind == "qr":
            qrs += 1
            if len(text_of(block, "data", required=True).encode()) > LIMITS["qr_bytes"]:
                raise Discard("QR data is too long")
            characters += len(text_of(block, "caption"))
        elif kind == "image":
            images += 1
            width, height = png_size(unb64(block.get("png")))
            if not 0 < width <= LIMITS["image_width"] or not 0 < height <= LIMITS["image_height"]:
                raise Discard("image dimensions out of range")
            images_height += height
            characters += len(text_of(block, "alt"))
    if (characters > LIMITS["characters"] or lines > LIMITS["lines"] or qrs > LIMITS["qr_blocks"]
            or images > LIMITS["images"] or images_height > LIMITS["images_height"]):
        raise Discard("ticket exceeds a limit")


def clean_text(text: str, keep_line_feeds: bool = False) -> str:
    """SPEC 7.3: nothing that could act as a control code reaches the printer."""
    out = []
    for ch in text:
        if ch == "\n":
            out.append("\n" if keep_line_feeds else " ")
        elif ch in "\t  ":
            out.append(" ")
        elif unicodedata.category(ch) not in ("Cc", "Cf"):
            out.append(ch)
    return "".join(out)


def render_text(ticket: dict, width: int = 48, max_lines: int = 250) -> str:
    """The minimum every recipient must manage, as plain text. Call validate_ticket first.
    `max_lines` is this recipient's own bound on printed length (SPEC 7.2)."""
    import textwrap
    out: list[str] = []
    for block in ticket["blocks"]:
        kind = block.get("type")
        if kind == "text":
            align = {"center": str.center, "right": str.rjust}.get(block.get("align"), str.ljust)
            for paragraph in clean_text(block["text"], keep_line_feeds=True).split("\n"):
                out += [align(line, width).rstrip() for line in textwrap.wrap(paragraph, width) or [""]]
        elif kind == "divider":
            out.append("-" * width)
        elif kind == "list":
            mark_for = {"check": lambda n: "[ ] ", "number": lambda n: f"{n}. "}.get(block.get("style"), lambda n: "- ")
            for n, item in enumerate(block["items"], 1):
                mark = mark_for(n)
                lines = textwrap.wrap(clean_text(item), width - len(mark)) or [""]
                out += [mark + lines[0]] + [" " * len(mark) + line for line in lines[1:]]
        elif kind == "space":
            out += [""] * block.get("lines", 1)
        elif kind == "qr":
            out.append(f"[QR] {clean_text(block.get('caption', ''))}".rstrip())
        elif kind == "image":
            out.append(f"[{clean_text(block.get('alt', '')) or 'image'}]")
    if len(out) > max_lines:
        out = out[:max_lines] + ["[... cut off: ticket too long ...]"]
    return "\n".join(out)


# --- command line ----------------------------------------------------------------

def _load(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _save(path: str, identity: dict) -> None:
    temporary = path + ".tmp"
    with open(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w", encoding="utf-8") as f:
        json.dump(identity, f, indent=1)
        f.flush()
        os.fsync(f.fileno())
    os.replace(temporary, path)


def main() -> None:
    parser = argparse.ArgumentParser(description="Bonvoyage reference client")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("init", help="create an identity and its inbox")
    p.add_argument("file"), p.add_argument("--relay", required=True), p.add_argument("--name", default="")
    p = sub.add_parser("card", help="issue a contact card for someone")
    p.add_argument("file"), p.add_argument("contact")
    p = sub.add_parser("send", help="send a text ticket to the issuer of a card")
    p.add_argument("file"), p.add_argument("card"), p.add_argument("text")
    p = sub.add_parser("receive", help="collect and show waiting tickets")
    p.add_argument("file")
    args = parser.parse_args()

    try:
        if args.command == "init":
            identity = new_identity(args.relay, args.name)
            register(identity)
            _save(args.file, identity)
            print(address(identity))
            return
        identity = _load(args.file)
        if args.command == "card":
            card = issue_card(identity, args.contact)
            register(identity)
            _save(args.file, identity)
            print(card)
        elif args.command == "send":
            card = parse_card(args.card)
            ticket = {"blocks": [{"type": "text", "text": args.text}]}
            validate_ticket(ticket)
            drop(card, seal_message(identity, card, ticket))
            print(f"sent to {card['name'] or card['address']}")
        elif args.command == "receive":
            for contact, message in receive(identity, persist=lambda: _save(args.file, identity)):
                # The label is OUR name for the contact, never the name the sender claims (SPEC 8).
                print(f"--- from {clean_text(contact['name'])} ---")
                print(render_text(message["ticket"]))
            _save(args.file, identity)
    except (Discard, RuntimeError, ValueError) as e:
        sys.exit(f"error: {e}")


if __name__ == "__main__":
    main()
