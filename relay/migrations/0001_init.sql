CREATE TABLE IF NOT EXISTS inboxes (
  id TEXT PRIMARY KEY,              -- base64url public signing key
  tokens TEXT NOT NULL,             -- JSON array of token IDs (hex SHA-256)
  created INTEGER NOT NULL,
  last_seen INTEGER NOT NULL        -- last time the owner collected or updated
);

CREATE TABLE IF NOT EXISTS messages (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  id TEXT NOT NULL UNIQUE,          -- relay message id
  inbox TEXT NOT NULL,
  token TEXT NOT NULL,              -- token ID the message arrived with
  received INTEGER NOT NULL,
  body TEXT NOT NULL                -- sealed message, base64url; opaque to the relay
);

CREATE INDEX IF NOT EXISTS messages_inbox ON messages (inbox, seq);
CREATE INDEX IF NOT EXISTS messages_received ON messages (received);
