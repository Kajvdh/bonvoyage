-- Owner requests that change an inbox must carry a later time than the last accepted one.
ALTER TABLE inboxes ADD COLUMN last_auth INTEGER NOT NULL DEFAULT 0;
-- An inbox is "established" once its owner has collected on several different days.
ALTER TABLE inboxes ADD COLUMN collect_days INTEGER NOT NULL DEFAULT 0;
ALTER TABLE inboxes ADD COLUMN last_collect_day INTEGER NOT NULL DEFAULT 0;

-- The last accepted request time of a deleted inbox, kept for the replay window.
CREATE TABLE IF NOT EXISTS tombstones (
  id TEXT PRIMARY KEY,
  t INTEGER NOT NULL,
  deleted INTEGER NOT NULL
);

-- Short-lived per-address counters (new inboxes per hour). `key` is a hash; rows live at most an hour.
CREATE TABLE IF NOT EXISTS counters (
  key TEXT PRIMARY KEY,
  window INTEGER NOT NULL,
  n INTEGER NOT NULL
);

-- Running totals, recomputed regularly, so that a drop does not have to count every message.
CREATE TABLE IF NOT EXISTS stats (
  key TEXT PRIMARY KEY,
  n INTEGER NOT NULL,
  computed INTEGER NOT NULL
);

DROP TABLE IF EXISTS auth_seen;

-- Fewer indexes on messages: every index entry is a billed row write on D1.
CREATE TABLE messages_new (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  id TEXT NOT NULL,
  inbox TEXT NOT NULL,
  token TEXT NOT NULL,
  received INTEGER NOT NULL,
  body TEXT NOT NULL
);
INSERT INTO messages_new (seq, id, inbox, token, received, body)
  SELECT seq, id, inbox, token, received, body FROM messages ORDER BY seq;
DROP TABLE messages;
ALTER TABLE messages_new RENAME TO messages;
CREATE INDEX messages_inbox ON messages (inbox, seq);
