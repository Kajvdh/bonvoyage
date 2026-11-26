#!/usr/bin/env python3
"""Bonvoyage playground: virtual ticket printers in your browser.

Create a few virtual printers, hand cards from one to another (or to a real
client you are building), send tickets and watch them come out on a paper roll
on screen. Each virtual printer is a real Bonvoyage identity on a real relay,
driven by the reference client in ../examples/bonvoyage.py.

    uv run --with pynacl python playground/app.py          # then open http://localhost:8790
    BONVOYAGE_DEV=1 uv run --with pynacl python playground/app.py   # also allows a relay on localhost

It listens on localhost only. Identities (private keys) are kept in playground/data/.
"""
import json
import os
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE.parent / "examples"))
import bonvoyage as bv  # noqa: E402

DATA = HERE / "data"
PORT = int(os.environ.get("PORT", "8790"))
DEFAULT_RELAY = os.environ.get("PLAYGROUND_RELAY", "bonvoyage.kaj.dev")
POLL_FLOOR = 60        # SPEC 6.5: a client never collects more often than once a minute
PAPER_MAX = 40
lock = threading.RLock()
printers: dict[str, dict] = {}


class Problem(Exception):
    pass


def path_of(pid: str) -> Path:
    return DATA / f"{pid}.json"


def save(pid: str) -> None:
    bv._save(str(path_of(pid)), printers[pid])


def load_all() -> None:
    DATA.mkdir(exist_ok=True)
    for file in sorted(DATA.glob("*.json")):
        identity = bv._load(str(file))
        identity.setdefault("paper", [])
        identity.setdefault("collected", 0)
        printers[file.stem] = identity


def roll(identity: dict, kind: str, title: str, body: str) -> None:
    identity["paper"].append({"kind": kind, "title": title, "body": body, "at": int(time.time())})
    del identity["paper"][:-PAPER_MAX]


def flush(pid: str) -> None:
    """Move what may be printed from the queue onto the paper roll."""
    identity = printers[pid]
    for entry in list(identity["queue"]):
        notice = entry.pop("notice", None)
        if notice:
            roll(identity, "notice", "NEW CONTACT", notice)
        if entry["held"]:
            continue
        roll(identity, "ticket", f"from {bv.clean_text(entry['contact'])}", bv.render_text(entry["message"]["ticket"], width=42))
        identity["queue"].remove(entry)
    save(pid)


def view(pid: str) -> dict:
    identity = printers[pid]
    local = identity["relay"].startswith("localhost")
    wait = 0 if local else max(0, POLL_FLOOR - (int(time.time()) - identity.get("collected", 0)))
    return {
        "id": pid, "name": identity["name"], "relay": identity["relay"], "address": bv.address(identity),
        "fingerprint": bv.fingerprint(bv.unb64(bv.inbox_id(identity), 32)),
        "contacts": [{"name": c["name"], "state": c["state"],
                      "fingerprint": bv.fingerprint(bv.unb64(c["key"], 32)) if c.get("key") else None,
                      "held": sum(1 for q in identity["queue"] if q["held"] and q["contact"] == c["name"])}
                     for c in identity["contacts"].values()],
        "recipients": sorted(identity["cards"]),
        "paper": identity["paper"][::-1],
        "collect_in": wait,
    }


def get(pid: str) -> dict:
    if pid not in printers:
        raise Problem("no such printer")
    return printers[pid]


def need(body: dict, field: str, limit: int = 4000) -> str:
    value = body.get(field)
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise Problem(f"'{field}' is missing")
    return value.strip()


def typed_ticket(text: str) -> dict:
    """Plain text becomes paragraphs and '- ' lines a tick list; text starting with { is taken as a raw ticket."""
    if text.lstrip().startswith("{"):
        try:
            return json.loads(text)
        except ValueError as e:
            raise Problem(f"that looks like JSON but is not: {e}") from e
    blocks: list[dict] = []
    for line in text.splitlines():
        item = line.strip()
        if not item:
            continue
        if item[0] in "-*" and item[1:].strip():
            if blocks and blocks[-1]["type"] == "list":
                blocks[-1]["items"].append(item[1:].strip())
            else:
                blocks.append({"type": "list", "style": "check", "items": [item[1:].strip()]})
        elif blocks and blocks[-1]["type"] == "text":
            blocks[-1]["text"] += "\n" + item
        else:
            blocks.append({"type": "text", "text": item})
    return {"blocks": blocks}


# --- actions -------------------------------------------------------------------

def create(body: dict) -> dict:
    name = need(body, "name", 40)
    relay = (body.get("relay") or DEFAULT_RELAY).strip().lower()
    pid = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or "printer"
    while pid in printers:
        pid += "-2"
    identity = bv.new_identity(relay, name)
    identity.update(paper=[], collected=0)
    bv.register(identity)  # includes the relay's proof of work
    with lock:
        printers[pid] = identity
        roll(identity, "info", "PRINTER READY", f"{name}\nfingerprint {bv.fingerprint(bv.unb64(bv.inbox_id(identity), 32))}")
        save(pid)
    return view(pid)


def act(pid: str, action: str, body: dict) -> dict:
    with lock:
        identity = get(pid)
        if action == "card":
            contact = need(body, "contact", 40)
            if any(c["name"] == contact for c in identity["contacts"].values()):
                raise Problem(f"there is already a contact named {contact}")
            before = dict(identity["contacts"])
            uri = bv.issue_card(identity, contact)
            try:
                bv.register(identity)
            except Exception:
                identity["contacts"] = before
                raise
            save(pid)
            return {**view(pid), "card": uri}
        if action == "add":
            card = bv.parse_card(need(body, "card"))
            identity["cards"][need(body, "name", 40)] = {**card, "key": bv.b64(card["key"])}
            save(pid)
        elif action == "confirm":
            bv.confirm(identity, need(body, "contact", 40))
            flush(pid)
        elif action == "decline":
            bv.remove_contact(identity, need(body, "contact", 40))
            save(pid)
            time.sleep(1.1)  # an inbox change needs a later time than the previous one
            bv.register(identity)
            save(pid)
        elif action == "collect":
            if view(pid)["collect_in"]:
                raise Problem(f"a client collects at most once a minute; wait {view(pid)['collect_in']} s")
            identity["collected"] = int(time.time())
            try:
                bv.receive(identity, persist=lambda: save(pid))
            finally:
                flush(pid)
        elif action == "clear":
            identity["paper"] = []
            save(pid)
        elif action == "send":
            to = need(body, "to", 40)
            card = identity["cards"].get(to)
            if card is None:
                raise Problem(f"{identity['name']} has no card of {to}")
            ticket = typed_ticket(need(body, "text", 60000))
            bv.validate_ticket(ticket)
            sealed = bv.seal_message(identity, card, ticket)
        else:
            raise Problem("unknown action")
    if action == "send":
        bv.drop(card, sealed)  # outside the lock: this talks to someone else's relay
    return view(pid)


def remove(pid: str) -> dict:
    with lock:
        identity = get(pid)
        try:
            bv.owner_request(identity, "DELETE", f"/v1/inbox/{bv.inbox_id(identity)}")
        except Exception:
            pass  # the relay forgets an unused inbox by itself
        del printers[pid]
        path_of(pid).unlink(missing_ok=True)
        Path(str(path_of(pid)) + ".lock").unlink(missing_ok=True)
    return {"removed": pid}


# --- http ------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, status: int, payload, content_type="application/json"):
        data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _guarded(self, work):
        try:
            self._send(200, work())
        except (Problem, bv.Discard, ValueError) as e:
            self._send(400, {"error": str(e)})
        except RuntimeError as e:
            self._send(502, {"error": str(e)})
        except Exception as e:
            self._send(500, {"error": f"{type(e).__name__}: {e}"})

    def _same_origin(self) -> bool:
        """Only this page may change things: a website you happen to visit must not drive your printers."""
        origin = self.headers.get("Origin")
        return self.headers.get("Host", "") in (f"localhost:{PORT}", f"127.0.0.1:{PORT}") and origin in (None, f"http://localhost:{PORT}", f"http://127.0.0.1:{PORT}")

    def do_GET(self):
        if self.path == "/":
            self._send(200, (HERE / "index.html").read_bytes(), "text/html; charset=utf-8")
        elif self.path == "/api/printers":
            with lock:
                self._send(200, {"printers": [view(p) for p in printers], "default_relay": DEFAULT_RELAY, "dev": bv.dev_mode()})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._same_origin():
            return self._send(403, {"error": "requests must come from the playground page"})
        length = int(self.headers.get("Content-Length") or 0)
        if length > 200000:
            return self._send(413, {"error": "too large"})
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return self._send(400, {"error": "body is not JSON"})
        parts = self.path.strip("/").split("/")
        if parts == ["api", "printers"]:
            self._guarded(lambda: create(body))
        elif len(parts) == 4 and parts[:2] == ["api", "printers"]:
            self._guarded(lambda: act(parts[2], parts[3], body))
        else:
            self._send(404, {"error": "not found"})

    def do_DELETE(self):
        if not self._same_origin():
            return self._send(403, {"error": "requests must come from the playground page"})
        parts = self.path.strip("/").split("/")
        if len(parts) == 3 and parts[:2] == ["api", "printers"]:
            self._guarded(lambda: remove(parts[2]))
        else:
            self._send(404, {"error": "not found"})


if __name__ == "__main__":
    load_all()
    print(f"Bonvoyage playground: http://localhost:{PORT}   (relay: {DEFAULT_RELAY}; {len(printers)} printer(s) loaded)")
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
