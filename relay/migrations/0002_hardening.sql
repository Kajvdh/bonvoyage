-- When the owner last collected; NULL means never (such inboxes expire quickly).
ALTER TABLE inboxes ADD COLUMN last_collected INTEGER;

-- Signatures of accepted inbox PUT/DELETE requests, kept for the replay window.
CREATE TABLE IF NOT EXISTS auth_seen (
  sig TEXT PRIMARY KEY,             -- hex SHA-256 of the signature
  t INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS messages_token ON messages (inbox, token);
CREATE INDEX IF NOT EXISTS inboxes_created ON inboxes (created);
