#!/usr/bin/env python3
"""Bonvoyage reference client: the protocol of SPEC.md in one file.

It is meant to be read next to the spec, and to try the protocol by hand:

    python bonvoyage.py init  me.json  --relay bonvoyage.kaj.dev --name Kaj
    python bonvoyage.py card  me.json  Jan          # give the printed URI to Jan
    python bonvoyage.py send  me.json  '<card URI from someone>' 'Hallo!'
    python bonvoyage.py receive me.json

Needs PyNaCl (libsodium). It prints received tickets as text; a real client
hands them to its printer and applies the policy of SPEC section 8.
"""
import argparse
import base64
import hashlib
import json
import os
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from nacl.exceptions import BadSignatureError, CryptoError
from nacl.public import PrivateKey, PublicKey, SealedBox
from nacl.signing import SigningKey, VerifyKey

MESSAGE_CONTEXT = b"bonvoyage-v1-message\n"
REQUEST_CONTEXT = "bonvoyage-v1-request\n"
BLOCK = 4096
MAX_SEALED = 65536


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# --- identity, addresses, cards (SPEC 2, 3, 4) -------------------------------

def new_identity(relay: str, name: str = "") -> dict:
    return {"relay": relay, "name": name, "sign": b64(bytes(SigningKey.generate())),
            "enc": b64(bytes(PrivateKey.generate())), "contacts": {}, "seen": {}}


def inbox_id(identity: dict) -> str:
    return b64(bytes(SigningKey(unb64(identity["sign"])).verify_key))


def address(identity: dict) -> str:
    return f"{inbox_id(identity)}@{identity['relay']}"


def token_id(token: bytes) -> str:
    return hashlib.sha256(token).hexdigest()


def make_card(identity: dict, token: bytes) -> str:
    enc_public = bytes(PrivateKey(unb64(identity["enc"])).public_key)
    query = {"k": b64(enc_public), "t": b64(token)}
    if identity.get("name"):
        query["n"] = identity["name"]
    return f"bonvoyage://{identity['relay']}/{inbox_id(identity)}?{urllib.parse.urlencode(query)}"


def parse_card(uri: str) -> dict:
    parts = urllib.parse.urlsplit(uri)
    query = urllib.parse.parse_qs(parts.query)
    if parts.scheme != "bonvoyage" or "k" not in query or "t" not in query:
        raise ValueError("not a Bonvoyage contact card")
    inbox = parts.path.lstrip("/")
    return {"relay": parts.netloc, "inbox": inbox, "address": f"{inbox}@{parts.netloc}",
            "key": unb64(query["k"][0]), "token": query["t"][0], "name": query.get("n", [""])[0]}


# --- messages (SPEC 5) --------------------------------------------------------

def seal_message(identity: dict, to_address: str, to_key: bytes, ticket: dict, *, expires: int | None = None,
                 now: int | None = None, message_id: bytes | None = None) -> bytes:
    message = {
        "v": 1, "id": b64(message_id or os.urandom(16)), "type": "ticket",
        "from": address(identity), "to": to_address, "created": now if now is not None else int(time.time()), "ticket": ticket,
    }
    if identity.get("name"):
        message["from_name"] = identity["name"]
    if expires:
        message["expires"] = expires
    m = json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode()
    signature = SigningKey(unb64(identity["sign"])).sign(MESSAGE_CONTEXT + m).signature
    signed = json.dumps({"msg": b64(m), "sig": b64(signature)}, separators=(",", ":")).encode()
    padded = struct.pack(">I", len(signed)) + signed
    padded += b"\0" * (-len(padded) % BLOCK)
    sealed = SealedBox(PublicKey(to_key)).encrypt(padded)
    if len(sealed) > MAX_SEALED:
        raise ValueError("ticket is too large")
    return sealed


def open_message(identity: dict, sealed: bytes, *, now: int | None = None) -> dict:
    """Steps 1 to 5 and the time checks of SPEC 5.4. Raises ValueError when the message must be discarded.
    The caller still checks the sender against the token (3.3), duplicates, and its own policy."""
    now = now if now is not None else int(time.time())
    try:
        padded = SealedBox(PrivateKey(unb64(identity["enc"]))).decrypt(sealed)
        (length,) = struct.unpack(">I", padded[:4])
        if length > len(padded) - 4:
            raise ValueError("bad length")
        signed = json.loads(padded[4:4 + length])
        m = unb64(signed["msg"])
        message = json.loads(m)
        if message.get("v") != 1:
            raise ValueError("unsupported version")
        if message.get("to") != address(identity):
            raise ValueError("not addressed to this printer")
        sender_inbox = message["from"].split("@", 1)[0]
        VerifyKey(unb64(sender_inbox)).verify(MESSAGE_CONTEXT + m, unb64(signed["sig"]))
    except (CryptoError, BadSignatureError, KeyError, TypeError, struct.error, UnicodeDecodeError) as e:
        raise ValueError(f"cannot open message: {type(e).__name__}") from e
    except json.JSONDecodeError as e:
        raise ValueError("cannot open message: not JSON") from e
    if message.get("created", 0) > now + 600:
        raise ValueError("created in the future")
    if message.get("expires") and message["expires"] < now:
        raise ValueError("expired")
    return message


# --- relay (SPEC 6) -----------------------------------------------------------

def _base(relay: str) -> str:
    local = relay.split(":")[0] in ("localhost", "127.0.0.1")
    return ("http://" if local else "https://") + relay


def _http(method: str, url: str, body: bytes | None, headers: dict) -> tuple[int, bytes]:
    request = urllib.request.Request(url, data=body, method=method, headers={"User-Agent": "bonvoyage-reference", **headers})
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def owner_request(identity: dict, method: str, path: str, body: dict | None = None, *, now: int | None = None):
    data = b"" if body is None else json.dumps(body).encode()
    t = str(now if now is not None else int(time.time()))
    signing_input = f"{REQUEST_CONTEXT}{method}\n{path}\n{t}\n{hashlib.sha256(data).hexdigest()}".encode()
    signature = SigningKey(unb64(identity["sign"])).sign(signing_input).signature
    headers = {"Bonvoyage-Auth": f"t={t},sig={b64(signature)}"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    status, raw = _http(method, _base(identity["relay"]) + path, data if body is not None else None, headers)
    return status, (json.loads(raw) if raw else None)


def register(identity: dict) -> None:
    tokens = sorted(identity["contacts"])
    status, answer = owner_request(identity, "PUT", f"/v1/inbox/{inbox_id(identity)}", {"tokens": tokens})
    if status != 200:
        raise RuntimeError(f"relay refused the inbox: {status} {answer}")


def drop(card: dict, sealed: bytes) -> None:
    status, raw = _http("POST", f"{_base(card['relay'])}/v1/inbox/{card['inbox']}/messages", sealed,
                        {"Authorization": f"Bearer {card['token']}", "Content-Type": "application/octet-stream"})
    if status != 201:
        raise RuntimeError(f"relay refused the message: {status} {raw.decode(errors='replace')}")


def receive(identity: dict, *, now: int | None = None) -> list[tuple[dict, dict]]:
    """Collect, check and delete waiting messages. Returns (contact, message) pairs that may be printed."""
    me = inbox_id(identity)
    status, answer = owner_request(identity, "GET", f"/v1/inbox/{me}/messages", now=now)
    if status != 200:
        raise RuntimeError(f"cannot collect: {status} {answer}")
    accepted = []
    for item in answer["messages"]:
        try:
            message = open_message(identity, unb64(item["body"]), now=now)
            contact = identity["contacts"].get(item["token"])
            if contact is None:
                raise ValueError("arrived with a token that is no longer known")
            sender = message["from"]
            if contact.get("pinned") not in (None, sender):  # SPEC 3.3
                raise ValueError("signed by a different key than this contact's")
            if message["id"] in identity["seen"]:
                raise ValueError("duplicate")
            contact["pinned"] = sender
            identity["seen"][message["id"]] = message["created"]
            if message.get("type") == "ticket":
                accepted.append((contact, message))
        except ValueError as e:
            print(f"discarded a message: {e}", file=sys.stderr)
        owner_request(identity, "DELETE", f"/v1/inbox/{me}/messages/{item['id']}", now=now)
    horizon = (now if now is not None else int(time.time())) - 14 * 24 * 3600
    identity["seen"] = {k: v for k, v in identity["seen"].items() if v > horizon}
    return accepted


# --- tickets as plain text (SPEC 7) -------------------------------------------

def render_text(ticket: dict, width: int = 48) -> str:
    """The minimum every recipient must manage: text, divider, list and space."""
    import textwrap
    out: list[str] = []
    for block in ticket.get("blocks", [])[:100]:
        kind = block.get("type")
        if kind == "text":
            align = {"center": str.center, "right": str.rjust}.get(block.get("align"), str.ljust)
            for paragraph in str(block.get("text", "")).split("\n"):
                out += [align(line, width).rstrip() for line in textwrap.wrap(paragraph, width) or [""]]
        elif kind == "divider":
            out.append("-" * width)
        elif kind == "list":
            marks = {"check": "[ ] ", "number": None}.get(block.get("style"), "- ")
            for n, item in enumerate(block.get("items", []), 1):
                mark = marks or f"{n}. "
                lines = textwrap.wrap(str(item), width - len(mark)) or [""]
                out += [mark + lines[0]] + [" " * len(mark) + line for line in lines[1:]]
        elif kind == "space":
            out += [""] * max(1, min(5, int(block.get("lines", 1) or 1)))
        elif kind == "qr":
            out.append(f"[QR] {block.get('caption') or ''}".rstrip())
        elif kind == "image":
            out.append(f"[{block.get('alt') or 'image'}]")
    return "\n".join(out)


# --- command line --------------------------------------------------------------

def _load(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _save(path: str, identity: dict) -> None:
    with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w", encoding="utf-8") as f:
        json.dump(identity, f, indent=1)


def main() -> None:
    parser = argparse.ArgumentParser(description="Bonvoyage reference client")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("init", help="create an identity and its inbox")
    p.add_argument("file"), p.add_argument("--relay", required=True), p.add_argument("--name", default="")
    p = sub.add_parser("card", help="issue a contact card for someone")
    p.add_argument("file"), p.add_argument("contact")
    p = sub.add_parser("send", help="send a text ticket to the holder of a card")
    p.add_argument("file"), p.add_argument("card"), p.add_argument("text")
    p = sub.add_parser("receive", help="collect and show waiting tickets")
    p.add_argument("file")
    args = parser.parse_args()

    if args.command == "init":
        identity = new_identity(args.relay, args.name)
        register(identity)
        _save(args.file, identity)
        print(address(identity))
        return
    identity = _load(args.file)
    if args.command == "card":
        token = os.urandom(32)
        identity["contacts"][token_id(token)] = {"name": args.contact}
        register(identity)
        _save(args.file, identity)
        print(make_card(identity, token))
    elif args.command == "send":
        card = parse_card(args.card)
        ticket = {"blocks": [{"type": "text", "text": args.text}]}
        drop(card, seal_message(identity, card["address"], card["key"], ticket))
        print(f"sent to {card['name'] or card['address']}")
    elif args.command == "receive":
        for contact, message in receive(identity):
            print(f"--- from {contact['name']} ---")
            print(render_text(message["ticket"]))
        _save(args.file, identity)


if __name__ == "__main__":
    main()
