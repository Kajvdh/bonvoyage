# Bonvoyage playground

Virtual ticket printers in your browser, for trying the protocol and for
testing a client you are building.

    uv run --with pynacl python playground/app.py      # or: pip install pynacl && python playground/app.py

Then open http://localhost:8790.

Each virtual printer is a real Bonvoyage identity with a real inbox on a
relay (by default `bonvoyage.kaj.dev`), driven by the reference client in
`../examples/bonvoyage.py`. That means virtual printers can pair with each
other, and just as well with a real printer somewhere else.

## What you can do

- **Add virtual printers.** Creating one takes a second or two: the relay asks
  for a little proof of work per inbox.
- **Issue a card** on one printer, for a named contact. Copy the
  `bonvoyage://` line.
- **Add that card** on another printer, under a name of your choosing. That
  printer can now send to the first.
- **Send a ticket.** Plain text; lines starting with `-` become a tick list.
  Text that starts with `{` is sent as a raw ticket, which is how you try
  odd or invalid tickets against your own client.
- **Collect.** A printer collects when you press the button, at most once a
  minute as the spec requires (no limit against a relay on localhost).
- **Pair.** The first ticket from a new contact shows a "NEW CONTACT" slip
  with a fingerprint and is held. Compare it with the sender's fingerprint,
  shown at the top of their column, then confirm or decline.
- **Read the paper roll** of each printer: what a real one would have printed.

## Testing your own client against it

1. In your client, issue a card. Paste it into a virtual printer ("Add").
2. Send from the virtual printer. Your client should announce a new contact
   and show the virtual printer's fingerprint.
3. Confirm in your client; the ticket prints.
4. The other way round: issue a card on the virtual printer, take it in with
   your client, send, press Collect, confirm.

## Notes

- It listens on localhost only and refuses requests that do not come from its
  own page.
- Identities, with their private keys, are in `playground/data/` (not in git).
  "remove" deletes a printer's keys and its inbox.
- `PLAYGROUND_RELAY=relay.example` chooses another default relay.
  `BONVOYAGE_DEV=1` allows a relay on `localhost:<port>` over plain HTTP.
- The public relay allows 20 new inboxes per address per hour.
