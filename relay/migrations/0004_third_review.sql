-- The "established inbox" distinction is gone: when the relay is full it makes room instead.
ALTER TABLE inboxes DROP COLUMN collect_days;
ALTER TABLE inboxes DROP COLUMN last_collect_day;
DROP INDEX IF EXISTS inboxes_created;
-- Finding the inbox that has been unused the longest must not scan every inbox.
CREATE INDEX IF NOT EXISTS inboxes_last_seen ON inboxes (last_seen);
DELETE FROM stats;
