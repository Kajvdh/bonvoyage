#!/usr/bin/env python3
"""Bonvoyage reference client: the protocol of SPEC.md in one file.

It is meant to be read next to the spec, and to try the protocol by hand:

    python bonvoyage.py init    me.json --relay bonvoyage.kaj.dev --name Kaj
    python bonvoyage.py card    me.json Jan        # a card for Jan: give him the line it prints
    python bonvoyage.py add     me.json Jan '<card URI that Jan gave you>'
    python bonvoyage.py send    me.json Jan 'Hallo!'
    python bonvoyage.py receive me.json            # shows tickets, and asks about new contacts
    python bonvoyage.py confirm me.json Jan        # after comparing fingerprints with Jan
    python bonvoyage.py fingerprint me.json

Needs PyNaCl (libsodium). It shows received tickets as text; a real client
hands them to its printer and applies the rest of the policy in SPEC section 8
(quiet hours, a daily limit per contact), and backs off when a relay answers
429, 500 or 503 (SPEC 6).
"""
import argparse
import base64
import fcntl
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import struct
import sys
import tempfile
import threading
import time
import unicodedata
import urllib.parse
import zlib
from email.utils import parsedate_to_datetime

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
REQUEST_DEADLINE = 60     # seconds for a whole request, not per read
CLOCK_SKEW = 300
MAX_DEPTH = 16
NAME_MAX = 40
TIME_MAX = 2 ** 40

B64 = re.compile(r"[A-Za-z0-9_-]*")
LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
HOST = re.compile(rf"(?=[^:]{{1,253}}(?::|$))(?:{LABEL}\.)+[a-z]{{1,63}}(?::(?!443$)([1-9][0-9]{{0,4}}))?")
DEV_HOST = re.compile(r"localhost(?::([1-9][0-9]{0,4}))?")
INBOX = re.compile(r"[A-Za-z0-9_-]{43}")
SHORT = re.compile(r"[A-Za-z0-9_-]{22}")
RELAY_MESSAGE_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")
DECIMAL = re.compile(r"[1-9][0-9]{0,12}")
HELD_MAX = 5              # tickets held for a contact that is not confirmed yet (SPEC 3.3)
UNRESERVED = "-._~"


class Discard(ValueError):
    """A message, card or ticket that must not be used."""


def dev_mode() -> bool:
    """Development mode (SPEC 3.1): off unless the person running the client switches it on."""
    return os.environ.get("BONVOYAGE_DEV") == "1"


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


def _check_depth(value, level: int = 1) -> None:
    """An array or object is one level, plus one for each array or object around it."""
    if isinstance(value, (dict, list)):
        if level > MAX_DEPTH:
            raise Discard("JSON nested too deeply")
        for child in (value.values() if isinstance(value, dict) else value):
            _check_depth(child, level + 1)


def _scan_depth(data: bytes) -> None:
    """Refuse deep nesting before any parser sees the bytes (SPEC 1.2): count brackets outside strings."""
    depth, in_string, escaped = 0, False, False
    for byte in data:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:      # backslash
                escaped = True
            elif byte == 0x22:      # closing quote
                in_string = False
        elif byte == 0x22:
            in_string = True
        elif byte in (0x5B, 0x7B):  # [ {
            depth += 1
            if depth > MAX_DEPTH:
                raise Discard("JSON nested too deeply")
        elif byte in (0x5D, 0x7D):  # ] }
            depth -= 1


def parse_json(data: bytes):
    """Strict JSON: valid UTF-8, RFC 8259 only, no unpaired surrogates, bounded nesting.
    This parser also rejects duplicate member names, which the spec allows a receiver to do."""
    def no_duplicates(pairs):
        keys = [k for k, _ in pairs]
        if len(set(keys)) != len(keys):
            raise Discard("duplicate member name")
        return dict(pairs)

    def not_json(name):
        raise Discard(f"{name} is not JSON")

    if data.startswith(b"\xef\xbb\xbf"):
        raise Discard("a byte order mark is not JSON")
    _scan_depth(data)
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=no_duplicates, parse_constant=not_json)
        json.dumps(value, ensure_ascii=False).encode("utf-8")  # fails on an unpaired surrogate
    except Discard:
        raise
    except (UnicodeError, ValueError, RecursionError) as e:
        raise Discard("not valid JSON") from e
    _check_depth(value)
    return value


def is_int(value, low: int, high: int) -> bool:
    """A whole number written as an integer. (1.0 is refused, which the spec allows.)"""
    return type(value) is int and low <= value < high


def is_host(text, allow_dev: bool | None = None) -> bool:
    """SPEC 1.2: a DNS name whose last label is letters only, optional port 1-65535 that is not 443."""
    if not isinstance(text, str):
        return False
    allow_dev = dev_mode() if allow_dev is None else allow_dev
    match = HOST.fullmatch(text) or (DEV_HOST.fullmatch(text) if allow_dev else None)
    return bool(match) and (match.group(1) is None or int(match.group(1)) <= 65535)


def parse_address(text) -> tuple[bytes, str, str]:
    """(signing key, inbox ID, host). The host is a hint, not authenticated (SPEC 3.1)."""
    if not isinstance(text, str) or text.count("@") != 1:
        raise Discard("not an address")
    inbox, host = text.split("@")
    if not INBOX.fullmatch(inbox) or not is_host(host):
        raise Discard("not an address")
    return unb64(inbox, 32), inbox, host


def clean_text(text: str, keep_line_feeds: bool = False) -> str:
    """SPEC 7.3: nothing that could act as a control code reaches the printer."""
    out = []
    for ch in text:
        if ch == "\n":
            out.append("\n" if keep_line_feeds else " ")
        elif ch in "\t  ":
            out.append(" ")
        elif ch in "‌‍" or unicodedata.category(ch) not in ("Cc", "Cf"):
            out.append(ch)
    return "".join(out)


# --- identity, tokens and cards (SPEC 2, 3, 4) ---------------------------------

def new_identity(relay: str, name: str = "") -> dict:
    if not is_host(relay):
        raise ValueError("relay must be a host name like relay.example, optionally with a port")
    return {"relay": relay, "name": name, "sign": b64(bytes(SigningKey.generate())),
            "enc": b64(bytes(PrivateKey.generate())), "contacts": {}, "cards": {}, "seen": {}, "queue": []}


def inbox_id(identity: dict) -> str:
    return b64(bytes(SigningKey(unb64(identity["sign"])).verify_key))


def address(identity: dict) -> str:
    return f"{inbox_id(identity)}@{identity['relay']}"


def token_id(token: bytes) -> str:
    return hashlib.sha256(token).hexdigest()


def fingerprint(signing_key: bytes) -> str:
    """SPEC 3.4: twelve digits that two people can compare, for example '4821 0937 5512'."""
    number = int.from_bytes(hashlib.sha256(b"bonvoyage-v1-fingerprint\n" + signing_key).digest()[:5], "big") % 10 ** 12
    digits = f"{number:012d}"
    return f"{digits[:4]} {digits[4:8]} {digits[8:]}"


def leading_zero_bits(digest: bytes) -> int:
    bits = 0
    for byte in digest:
        if byte == 0:
            bits += 8
            continue
        return bits + 8 - byte.bit_length()
    return bits


def proof_of_work(inbox: str, bits: int) -> str:
    """SPEC 6.3: the smallest nonce whose hash starts with `bits` zero bits. Takes about 2^bits tries."""
    prefix = f"bonvoyage-v1-pow\n{inbox}\n".encode()
    nonce = 0
    while leading_zero_bits(hashlib.sha256(prefix + str(nonce).encode()).digest()) < bits:
        nonce += 1
    return str(nonce)


def _card_signing_input(host, inbox, k, t, p, e, name) -> bytes:
    return (CARD_CONTEXT + "\n".join([host, inbox, k, t, p, e, name])).encode()


def make_card(identity: dict, token: bytes, pair: bytes, expires: int | None = None) -> str:
    """A contact card URI (SPEC 3.2), signed by this identity. Parameters in the recommended order."""
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
    query = "&".join(f"{k}={urllib.parse.quote(v, safe=UNRESERVED)}" for k, v in fields.items())
    return f"bonvoyage://{identity['relay']}/{inbox_id(identity)}?{query}"


def _percent_decode(text: str) -> str:
    """Strict: every % is followed by two hex digits, the result is UTF-8, and + is a plus sign."""
    if re.search(r"%(?![0-9A-Fa-f]{2})", text):
        raise Discard("invalid percent-escape")
    try:
        return urllib.parse.unquote_to_bytes(text).decode("utf-8")
    except UnicodeDecodeError as e:
        raise Discard("name is not UTF-8") from e


def unwrap_card(text: str) -> str:
    """A card as people paste it: the bare URI, or the web link a phone shows (https://host/card/#bonvoyage://...)."""
    text = text.strip()
    if text.startswith("https://") and "#" in text:
        text = urllib.parse.unquote(text.split("#", 1)[1])
    return text


def parse_card(uri: str, *, now: int | None = None) -> dict:
    """Check a card someone gave you. Raises Discard for anything that is not exactly a valid card."""
    now = int(time.time()) if now is None else now
    uri = unwrap_card(uri) if isinstance(uri, str) else uri
    match = re.fullmatch(r"bonvoyage://([^/?#@]+)/([^/?#]+)\?([^#]*)", uri if isinstance(uri, str) else "")
    if not match:
        raise Discard("not a Bonvoyage contact card")
    host, inbox, query = match.groups()
    if not is_host(host) or not INBOX.fullmatch(inbox):
        raise Discard("card has an invalid host or inbox ID")
    fields: dict[str, str] = {}
    for part in query.split("&"):
        key, sep, value = part.partition("=")
        if key in ("v", "k", "t", "p", "e", "n", "s"):
            if key in fields or not sep or not value:
                raise Discard(f"card parameter {key} is repeated or empty")
            fields[key] = value
    if fields.get("v") != "1" or not all(k in fields for k in ("k", "t", "p", "s")):
        raise Discard("card is missing a field or has an unknown version")
    expires = fields.get("e", "")
    if expires and not (DECIMAL.fullmatch(expires) and int(expires) < TIME_MAX):
        raise Discard("card expiry is not a valid time")
    name = _percent_decode(fields["n"]) if "n" in fields else ""
    if "n" in fields and not 1 <= len(name) <= NAME_MAX:
        raise Discard("card name has the wrong length")
    signing_key = unb64(inbox, 32)
    key, _ = unb64(fields["k"], 32), unb64(fields["p"], 16)
    unb64(fields["t"], 32)
    try:
        VerifyKey(signing_key).verify(_card_signing_input(host, inbox, fields["k"], fields["t"], fields["p"], expires, name),
                                      unb64(fields["s"], 64))
    except (BadSignatureError, CryptoError, ValueError) as e:
        raise Discard("card signature does not match the inbox") from e
    if expires and int(expires) < now:
        raise Discard("card has expired; ask for a new one")
    return {"relay": host, "inbox": inbox, "address": f"{inbox}@{host}", "key": key, "token": fields["t"],
            "pair": fields["p"], "expires": int(expires) if expires else None, "name": clean_text(name)}


def issue_card(identity: dict, contact_name: str, *, now: int | None = None, lifetime: int = CARD_LIFETIME) -> str:
    """Create an open contact with its own token and pairing secret, and return the card to hand over.
    The caller registers the new token with the relay (see `register`) and saves the identity."""
    now = int(time.time()) if now is None else now
    token, pair = os.urandom(32), os.urandom(16)
    identity["contacts"][token_id(token)] = {"name": contact_name, "pair": b64(pair), "created": now,
                                             "expires": now + lifetime, "state": "open", "key": None}
    return make_card(identity, token, pair, expires=now + lifetime)


def replace_token(identity: dict, old_token_id: str) -> str:
    """A fresh token for a contact that is already pinned (SPEC 4). The card carries a random pairing
    secret that is not stored anywhere, so the card cannot pair anyone."""
    contact = identity["contacts"].pop(old_token_id)
    if not contact.get("key"):
        raise ValueError("only a pending or paired contact gets a replacement token")
    token = os.urandom(32)
    identity["contacts"][token_id(token)] = contact
    return make_card(identity, token, os.urandom(16))


def prune_contacts(identity: dict, now: int) -> None:
    """Open contacts whose card has expired can never pair: drop them, and with them their tokens."""
    for key in [k for k, c in identity["contacts"].items() if c.get("state", "open") == "open" and c["expires"] < now]:
        del identity["contacts"][key]


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
    key = card["key"] if isinstance(card["key"], bytes) else unb64(card["key"], 32)
    return seal_signed(sign_message(identity, m), key)


def sign_message(identity: dict, m: bytes) -> bytes:
    """The signed-message JSON for the exact message bytes `m` (SPEC 5.2)."""
    signature = SigningKey(unb64(identity["sign"])).sign(MESSAGE_CONTEXT + m).signature
    return json.dumps({"msg": b64(m), "sig": b64(signature)}, separators=(",", ":")).encode()


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
    if not is_int(message.get("created"), 1, TIME_MAX):
        raise Discard("bad created")
    if "expires" in message and not is_int(message["expires"], 1, TIME_MAX):
        raise Discard("bad expires")
    if "from_name" in message and not (isinstance(message["from_name"], str) and 1 <= len(message["from_name"]) <= NAME_MAX):
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


class CardMisuse(Discard):
    """The card of a pending or paired contact was used by a second party (SPEC 3.3)."""

    def __init__(self, contact: dict):
        super().__init__(f"the card issued to {contact['name']} was used by a second party; compare fingerprints")
        self.contact = contact


class LocalFailure(RuntimeError):
    """Our own fault (disk, state), not the message's: stop without deleting anything (SPEC 5.4)."""


def find_contact(identity: dict, sender_key: bytes, message: dict, now: int) -> tuple[dict, bool]:
    """SPEC 3.3. Returns (contact, is_candidate) or raises Discard. Nothing is changed here."""
    key = b64(sender_key)
    # Rule 1 first: a key that is pinned anywhere is that contact, whatever secret the message carries.
    contact = next((c for c in identity["contacts"].values() if c.get("key") == key), None)
    candidate = False
    if contact is None:
        matched = None
        for c in identity["contacts"].values():  # no early exit: compare against every contact
            if hmac.compare_digest(c["pair"].encode(), message["pair"].encode()):
                matched = c
        if matched is None:
            raise Discard("from nobody this printer knows")
        if matched["state"] != "open":
            raise CardMisuse(matched)
        if matched["expires"] < now:
            raise Discard(f"the card issued to {matched['name']} has expired for pairing")
        contact, candidate = matched, True
    if message["created"] < contact["created"] - FUTURE_SKEW:
        raise Discard("older than this contact")
    return contact, candidate


def handle_message(identity: dict, sealed: bytes, now: int, persist=None, auto_confirm: bool = False) -> dict | None:
    """Steps 1 to 10 of SPEC 5.4 for one sealed message. Returns the queue entry for a ticket, or None
    for an authentic message that prints nothing. Raises Discard for a message that must be dropped.

    A queue entry is {"contact", "message", "held"}: held tickets belong to a contact the owner has
    not confirmed yet. When the message pairs a contact, the entry also has "notice": the text the
    owner must be shown (SPEC 3.3).
    """
    sender_key, message = open_message(identity, sealed, now=now)                     # steps 1-6
    seen_key = f"{b64(sender_key)}:{message['id']}"
    if seen_key in identity["seen"]:                                                   # step 7
        raise Discard("already handled")
    contact, candidate = find_contact(identity, sender_key, message, now)             # step 8
    problem = None                                                                     # step 9
    if message["type"] != "ticket":
        problem = "not a ticket"
    else:
        try:
            validate_ticket(message["ticket"])
        except Discard as e:
            problem = str(e)
    if problem and candidate:
        raise Discard(f"a first message must be a valid ticket to pair ({problem})")
    held = sum(1 for q in identity["queue"] if q["held"] and q["contact"] == contact["name"])
    if not problem and not candidate and contact["state"] == "pending" and held >= HELD_MAX:
        problem = "too many tickets held for a contact that is not confirmed"

    # Step 10, one durable step: the record, the pin and state, and the ticket in the queue.
    entry = None
    identity["seen"][seen_key] = now
    if not problem:
        if candidate:
            contact["key"] = b64(sender_key)
            contact["state"] = "paired" if auto_confirm else "pending"
        entry = {"contact": contact["name"], "message": message, "held": contact["state"] == "pending"}
        if candidate:
            entry["notice"] = pairing_notice(contact, message)
        identity["queue"].append(entry)
    if persist:
        try:
            persist()
        except Exception as e:
            raise LocalFailure(f"cannot save state: {type(e).__name__}") from e
    if problem:
        raise Discard(problem)
    return entry


def pairing_notice(contact: dict, message: dict) -> str:
    """What the owner is shown when a contact is paired: fixed words, OUR name, and the fingerprint."""
    lines = [f"NEW CONTACT: someone used the card you issued to {clean_text(contact['name'])}.",
             f"Fingerprint of their printer: {fingerprint(unb64(contact['key'], 32))}"]
    if message.get("from_name"):
        lines.append(f"They call themselves (unverified): {clean_text(message['from_name'])}")
    lines.append("Compare the fingerprint with them, then confirm or decline." if contact["state"] == "pending"
                 else "This client confirms new contacts automatically.")
    return "\n".join(lines)


def confirm(identity: dict, contact_name: str) -> int:
    """pending -> paired (SPEC 3.3). Returns how many held tickets were released."""
    contact = next((c for c in identity["contacts"].values() if c["name"] == contact_name and c["state"] == "pending"), None)
    if contact is None:
        raise ValueError(f"no contact named {contact_name} is waiting for confirmation")
    contact["state"] = "paired"
    released = [q for q in identity["queue"] if q["held"] and q["contact"] == contact_name]
    for q in released:
        q["held"] = False
    return len(released)


def remove_contact(identity: dict, contact_name: str) -> None:
    """Decline or remove: the contact, its pinned key, its secret and its waiting tickets all go."""
    gone = [k for k, c in identity["contacts"].items() if c["name"] == contact_name]
    if not gone:
        raise ValueError(f"no contact named {contact_name}")
    for key in gone:
        del identity["contacts"][key]
    identity["queue"] = [q for q in identity["queue"] if q["contact"] != contact_name]


# --- relay (SPEC 6) ------------------------------------------------------------

def _embedded_ipv4(ip: ipaddress.IPv6Address):
    """The IPv4 address an IPv6 address carries, if it is one of the transition forms (SPEC 1.2)."""
    n = int(ip)
    for network, shift in (("::ffff:0:0/96", 0), ("::/96", 0), ("::ffff:0:0:0/96", 0), ("64:ff9b::/96", 0),
                           ("64:ff9b:1::/48", 0), ("2002::/16", 80)):
        if ip in ipaddress.ip_network(network):
            return ipaddress.IPv4Address((n >> shift) & 0xFFFFFFFF)
    if ip in ipaddress.ip_network("2001::/32"):  # Teredo: the client's address is stored inverted in the last 32 bits
        return ipaddress.IPv4Address(~n & 0xFFFFFFFF)
    return None


def is_public_address(text: str) -> bool:
    """SPEC 1.2: a globally reachable unicast address, judging IPv6 transition forms by the IPv4 inside."""
    try:
        ip = ipaddress.ip_address(text.split("%")[0])
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address):
        if ip in (ipaddress.IPv6Address("::"), ipaddress.IPv6Address("::1")):
            return False
        inner = _embedded_ipv4(ip)
        if inner is not None:
            ip = inner
        elif ip.is_multicast or ip.is_site_local or ip.is_link_local or ip.is_private:
            return False
    return ip.is_global and not ip.is_multicast and not ip.is_reserved


def _public_address(host: str, port: int) -> str:
    """Resolve once and insist that every address is public. Returns the one to connect to."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise RuntimeError(f"cannot resolve {host}") from e
    addresses = [info[4][0] for info in infos]
    if not addresses or not all(is_public_address(a) for a in addresses):
        raise RuntimeError(f"{host} resolves to an address that is not public; refusing to connect")
    return addresses[0]


def _http(method: str, host: str, path: str, body: bytes | None, headers: dict, *, deadline: float = REQUEST_DEADLINE) -> tuple[int, bytes, dict]:
    """One request with a deadline for the whole exchange, no redirects, and a bounded response."""
    if not is_host(host):
        raise RuntimeError("not a relay host")
    name, _, port = host.partition(":")
    if DEV_HOST.fullmatch(host) and dev_mode():  # plain HTTP to localhost, development only (SPEC 3.1)
        connection = http.client.HTTPConnection(name, int(port or 80), timeout=10)
    else:
        target = _public_address(name, int(port or 443))
        connection = http.client.HTTPSConnection(name, int(port or 443), timeout=10, context=ssl.create_default_context())
        # Connect to the address that was checked; the certificate is still verified against the name.
        connection._create_connection = lambda _address, *args, **kwargs: socket.create_connection((target, int(port or 443)), *args, **kwargs)

    # The deadline covers everything, however slowly the other side sends: when it passes, the
    # connection is torn down from a timer, which makes whatever read is blocked fail.
    expired = threading.Event()

    def give_up():
        expired.set()
        sock = connection.sock
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()
    timer = threading.Timer(deadline, give_up)
    timer.daemon = True
    timer.start()
    try:
        connection.request(method, path, body=body, headers={"User-Agent": "bonvoyage", "Host": host, **headers})
        response = connection.getresponse()  # http.client never follows redirects
        chunks, size = [], 0
        while True:
            chunk = response.read1(65536)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_RESPONSE:
                raise RuntimeError("relay response is too large")
            chunks.append(chunk)
        if expired.is_set():
            raise RuntimeError("relay took too long")
        return response.status, b"".join(chunks), {k.lower(): v for k, v in response.getheaders()}
    except (OSError, http.client.HTTPException, ValueError) as e:
        raise RuntimeError("relay took too long" if expired.is_set() else f"cannot reach {host}: {type(e).__name__}") from e
    finally:
        timer.cancel()
        connection.close()


def _relay_json(raw: bytes):
    try:
        return parse_json(raw) if raw else None
    except Discard:
        return None


def owner_request(identity: dict, method: str, path: str, body: dict | None = None, *, now: int | None = None,
                  extra: dict | None = None, _retry: bool = True):
    """A signed request to our own relay. Returns (status, parsed body or None, response headers)."""
    data = b"" if body is None else json.dumps(body).encode()
    t = str(int(time.time()) if now is None else now)
    signing_input = f"{REQUEST_CONTEXT}{method}\n{identity['relay']}\n{path}\n{t}\n{hashlib.sha256(data).hexdigest()}".encode()
    signature = SigningKey(unb64(identity["sign"])).sign(signing_input).signature
    status, raw, headers = _http(method, identity["relay"], path, data if body is not None else None,
                                 {"Bonvoyage-Auth": f"t={t},sig={b64(signature)}", **(extra or {})})
    if status == 409 and _retry and now is None:
        # An inbox change must carry a later time than the previous one (SPEC 6.2). Sign again, a second later.
        time.sleep(1.1)
        return owner_request(identity, method, path, body, extra=extra, _retry=False)
    return status, _relay_json(raw), headers


def relay_info(host: str) -> tuple[dict, dict]:
    status, raw, headers = _http("GET", host, "/v1", None, {})
    info = _relay_json(raw)
    if status != 200 or not isinstance(info, dict):
        raise RuntimeError(f"{host} does not answer like a Bonvoyage relay")
    return info, headers


def register(identity: dict, *, now: int | None = None) -> None:
    """Create the inbox, or replace its list of accepted tokens. Does the relay's proof of work when
    the inbox is new (SPEC 6.3) and remembers the answer."""
    prune_contacts(identity, int(time.time()) if now is None else now)
    me = inbox_id(identity)
    body = {"tokens": sorted(identity["contacts"])}
    extra = {"Bonvoyage-Pow": identity["pow"]["nonce"]} if identity.get("pow") else {}
    status, answer, _ = owner_request(identity, "PUT", f"/v1/inbox/{me}", body, extra=extra)
    if status == 403:
        info, _ = relay_info(identity["relay"])
        bits = info.get("pow_bits")
        if is_int(bits, 1, 33) and (identity.get("pow") or {}).get("bits", 0) < bits:
            print(f"doing proof of work for a new inbox ({bits} bits, a few seconds)...", file=sys.stderr)
            identity["pow"] = {"bits": bits, "nonce": proof_of_work(me, bits)}
            status, answer, _ = owner_request(identity, "PUT", f"/v1/inbox/{me}", body, extra={"Bonvoyage-Pow": identity["pow"]["nonce"]})
    if status != 200:
        detail = clean_text(str(answer.get("error", "")))[:80] if isinstance(answer, dict) else ""
        raise RuntimeError(f"relay refused the inbox: {status} {detail}".strip())


def drop(card: dict, sealed: bytes) -> None:
    status, _, _ = _http("POST", card["relay"], f"/v1/inbox/{card['inbox']}/messages", sealed,
                         {"Authorization": f"Bearer {card['token']}"})
    if status != 201:
        # Only the status: a relay named in a card is not trusted with what ends up in our logs.
        raise RuntimeError(f"relay refused the message: {status}")


def clock_is_right(headers: dict, now: int) -> bool:
    """SPEC 5.4 "Clocks": no Date header, or one that differs too much, means: do not handle anything."""
    try:
        relay_time = parsedate_to_datetime(headers.get("date", "")).timestamp()
    except (TypeError, ValueError):
        return False
    return abs(relay_time - now) <= CLOCK_SKEW


def receive(identity: dict, *, now: int | None = None, persist=None, auto_confirm: bool = False) -> list[dict]:
    """Collect and handle waiting messages (SPEC 5.4). Returns the new queue entries; they are also in
    identity["queue"], which is what a client prints from.

    `persist` saves the identity. It is called once per accepted message, after the message is
    recorded and queued and before it is deleted from the relay, so a crash loses neither the record
    nor the ticket. If it fails, receiving stops and nothing is deleted.
    """
    real_now = int(time.time())
    now = real_now if now is None else now
    me = inbox_id(identity)
    status, answer, headers = owner_request(identity, "GET", f"/v1/inbox/{me}/messages")
    if status == 404:
        register(identity)  # the relay removed an unused inbox (SPEC 6.3): create it again and carry on
        return []
    if status != 200 or not isinstance(answer, dict) or not isinstance(answer.get("messages"), list):
        raise RuntimeError(f"cannot collect: {status}")
    if not clock_is_right(headers, real_now):
        raise RuntimeError("this computer's clock differs from the relay's by more than 5 minutes (or the relay sent no Date); "
                           "nothing was handled")
    identity["seen"] = {k: t for k, t in identity["seen"].items() if t > now - REMEMBER}
    accepted = []
    for item in answer["messages"][:20]:
        relay_id = item.get("id") if isinstance(item, dict) else None
        if not isinstance(relay_id, str) or not RELAY_MESSAGE_ID.fullmatch(relay_id):
            continue  # not something we can even ask the relay to delete
        try:
            entry = handle_message(identity, unb64(item.get("body")), now, persist, auto_confirm)
            if entry:
                accepted.append(entry)
        except LocalFailure:
            raise  # our own problem: the message stays at the relay
        except CardMisuse as e:
            # Tell the owner at most once a day per contact, and never on paper (SPEC 3.3).
            if now - e.contact.get("alerted", 0) >= 86400:
                e.contact["alerted"] = now
                print(f"ALERT: {e}", file=sys.stderr)
                if persist:
                    persist()
        except Discard as e:
            print(f"discarded a message: {e}", file=sys.stderr)
        except Exception as e:  # an error caused by the message: discard and carry on
            print(f"discarded a message: unexpected {type(e).__name__}", file=sys.stderr)
        try:
            owner_request(identity, "DELETE", f"/v1/inbox/{me}/messages/{relay_id}")   # step 11
        except RuntimeError:
            pass  # not fatal: the relay offers it again and the repeat check discards it
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
    width, height, depth, colour, _compression, _filter, interlace = struct.unpack(">IIBBBBB", data[16:29])
    if colour != 0 or depth not in (1, 8) or interlace != 0:
        raise Discard("image must be plain greyscale, 1 or 8 bits, not interlaced")
    return width, height


def _dressing(block: dict, member: str) -> str:
    """caption and alt only dress a block up: a wrong type counts as absent (SPEC 7.1)."""
    value = block.get(member)
    return value if isinstance(value, str) else ""


def validate_ticket(ticket) -> None:
    """Enforce the structure and every limit of SPEC 7.1, 7.2 and 7.4. Raises Discard for the whole ticket."""
    if not isinstance(ticket, dict) or not isinstance(ticket.get("blocks"), list):
        raise Discard("ticket has no blocks")
    blocks = ticket["blocks"]
    if len(blocks) > LIMITS["blocks"]:
        raise Discard("too many blocks")
    characters = lines = qrs = images = images_height = 0
    for block in blocks:
        if not isinstance(block, dict):
            raise Discard("a block is not an object")
        kind = block.get("type")
        if kind == "text":
            if not isinstance(block.get("text"), str):
                raise Discard("text is not text")
            characters += len(block["text"])
            lines += 1 + block["text"].count("\n")
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
            data = block.get("data")
            if not isinstance(data, str) or not 1 <= len(data.encode()) <= LIMITS["qr_bytes"]:
                raise Discard("QR data is missing or too long")
            characters += len(_dressing(block, "caption"))
        elif kind == "image":
            images += 1
            width, height = png_size(unb64(block.get("png")))
            if not 0 < width <= LIMITS["image_width"] or not 0 < height <= LIMITS["image_height"]:
                raise Discard("image dimensions out of range")
            images_height += height
            characters += len(_dressing(block, "alt"))
    if (characters > LIMITS["characters"] or lines > LIMITS["lines"] or qrs > LIMITS["qr_blocks"]
            or images > LIMITS["images"] or images_height > LIMITS["images_height"]):
        raise Discard("ticket exceeds a limit")


def render_text(ticket: dict, width: int = 48, max_lines: int = 250) -> str:
    """The minimum every recipient must manage, as plain text. Call validate_ticket first.
    The whole ticket is laid out before anything is returned, and `max_lines` is this recipient's
    own bound on printed length (SPEC 7.2)."""
    import textwrap
    out: list[str] = []
    for block in ticket["blocks"]:
        kind = block.get("type")
        if kind == "text":
            align = {"center": str.center, "right": str.rjust}.get(block.get("align") if isinstance(block.get("align"), str) else None, str.ljust)
            for paragraph in clean_text(block["text"], keep_line_feeds=True).split("\n"):
                out += [align(line, width).rstrip() for line in textwrap.wrap(paragraph, width) or [""]]
        elif kind == "divider":
            out.append("-" * width)
        elif kind == "list":
            style = block.get("style") if isinstance(block.get("style"), str) else None
            mark_for = {"check": lambda n: "[ ] ", "number": lambda n: f"{n}. "}.get(style, lambda n: "- ")
            for n, item in enumerate(block["items"], 1):
                mark = mark_for(n)
                lines = textwrap.wrap(clean_text(item), width - len(mark)) or [""]
                out += [mark + lines[0]] + [" " * len(mark) + line for line in lines[1:]]
        elif kind == "space":
            out += [""] * block.get("lines", 1)
        elif kind == "qr":
            out.append(f"[QR] {clean_text(_dressing(block, 'caption'))}".rstrip())
        elif kind == "image":
            out.append(f"[{clean_text(_dressing(block, 'alt')) or 'image'}]")
    if len(out) > max_lines:
        out = out[:max_lines] + ["[... cut off: ticket too long ...]"]
    return "\n".join(out)


# --- command line ----------------------------------------------------------------

def _load(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        identity = json.load(f)
    identity.setdefault("queue", [])
    identity.setdefault("cards", {})
    return identity


def _save(path: str, identity: dict) -> None:
    """Write through a fresh, private temporary file, rename it over the old one, and make that stick."""
    directory = os.path.dirname(os.path.abspath(path))
    handle, temporary = tempfile.mkstemp(dir=directory, prefix=".bonvoyage-")  # created exclusively, mode 0600
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as f:
            json.dump(identity, f, indent=1)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary, path)
        folder = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(folder)
        finally:
            os.close(folder)
    except BaseException:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise


def _show_queue(path: str, identity: dict) -> None:
    """Print what may be printed. Tickets of a contact that is not confirmed stay in the queue."""
    for entry in list(identity["queue"]):
        if entry.get("notice"):
            print(entry.pop("notice"))
            _save(path, identity)
        if entry["held"]:
            continue
        # The label is OUR name for the contact, never the name the sender claims (SPEC 8).
        print(f"--- from {clean_text(entry['contact'])} ---")
        print(render_text(entry["message"]["ticket"]))
        identity["queue"].remove(entry)
        _save(path, identity)
    held = sorted({q["contact"] for q in identity["queue"] if q["held"]})
    for name in held:
        print(f"(tickets from {clean_text(name)} are waiting: run 'confirm' or 'decline' for that contact)")


def main() -> None:
    parser = argparse.ArgumentParser(description="Bonvoyage reference client")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("init", help="create an identity and its inbox")
    p.add_argument("file"), p.add_argument("--relay", required=True), p.add_argument("--name", default="")
    p = sub.add_parser("card", help="issue a contact card for someone who will send to you")
    p.add_argument("file"), p.add_argument("contact")
    p = sub.add_parser("add", help="take in a card someone gave you, under a name of your choosing")
    p.add_argument("file"), p.add_argument("name"), p.add_argument("card")
    p = sub.add_parser("send", help="send a text ticket to someone whose card you added")
    p.add_argument("file"), p.add_argument("name"), p.add_argument("text")
    p = sub.add_parser("receive", help="collect and show waiting tickets")
    p.add_argument("file")
    p = sub.add_parser("confirm", help="accept a new contact after comparing fingerprints")
    p.add_argument("file"), p.add_argument("contact")
    p = sub.add_parser("decline", help="refuse a new contact, or remove an existing one")
    p.add_argument("file"), p.add_argument("contact")
    p = sub.add_parser("fingerprint", help="show the fingerprint of your own printer")
    p.add_argument("file")
    args = parser.parse_args()

    # One command at a time per identity file: two at once could lose a pairing or the record of handled messages.
    lock = open(args.file + ".lock", "w")
    fcntl.flock(lock, fcntl.LOCK_EX)
    try:
        if args.command == "init":
            if os.path.exists(args.file):
                sys.exit(f"error: {args.file} already exists; it holds private keys, so it is not overwritten")
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
        elif args.command == "add":
            card = parse_card(args.card)  # checked once, now; its expiry is not looked at again (SPEC 3.2)
            identity["cards"][args.name] = {**card, "key": b64(card["key"])}
            _save(args.file, identity)
            print(f"added {args.name}. Send a first ticket soon: the card stops working for pairing"
                  + (f" on {time.strftime('%d %b %Y', time.localtime(card['expires']))}." if card["expires"] else " after a while."))
        elif args.command == "send":
            card = identity["cards"].get(args.name)
            if card is None:
                sys.exit(f"error: no card for {args.name}; use 'add' first")
            ticket = {"blocks": [{"type": "text", "text": args.text}]}
            validate_ticket(ticket)
            sealed = seal_message(identity, card, ticket)
            lock.close()  # the relay in a card is someone else's: never hold up receiving while talking to it (SPEC 6)
            drop(card, sealed)
            print(f"sent to {args.name}")
        elif args.command == "receive":
            try:
                receive(identity, persist=lambda: _save(args.file, identity))
            finally:
                _show_queue(args.file, identity)  # whatever happened, show what was accepted
        elif args.command == "confirm":
            released = confirm(identity, args.contact)
            _save(args.file, identity)
            print(f"{args.contact} is now a contact ({released} waiting ticket(s) released)")
            _show_queue(args.file, identity)
        elif args.command == "decline":
            remove_contact(identity, args.contact)
            register(identity)
            _save(args.file, identity)
            print(f"{args.contact} was removed")
        elif args.command == "fingerprint":
            print(fingerprint(unb64(inbox_id(identity), 32)))
    except (Discard, RuntimeError, ValueError) as e:
        sys.exit(f"error: {e}")
    finally:
        lock.close()


if __name__ == "__main__":
    main()
