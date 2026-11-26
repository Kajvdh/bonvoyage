// Storage for self-hosting: SQLite through Node's built-in node:sqlite.
import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";

const SCHEMA = new URL("../migrations/0001_init.sql", import.meta.url);

export class NodeStore {
  constructor(path = ":memory:") {
    this.db = new DatabaseSync(path);
    this.db.exec("PRAGMA journal_mode = WAL");
    this.db.exec(readFileSync(SCHEMA, "utf8"));
  }

  async getInbox(id) {
    const row = this.db.prepare("SELECT tokens FROM inboxes WHERE id = ?").get(id);
    return row ? { tokens: JSON.parse(row.tokens) } : null;
  }

  async countInboxes() {
    return this.db.prepare("SELECT COUNT(*) AS n FROM inboxes").get().n;
  }

  async putInbox(id, tokens, now) {
    this.db.prepare(
      "INSERT INTO inboxes (id, tokens, created, last_seen) VALUES (?, ?, ?, ?) " +
      "ON CONFLICT (id) DO UPDATE SET tokens = excluded.tokens, last_seen = excluded.last_seen",
    ).run(id, JSON.stringify(tokens), now, now);
  }

  async touchInbox(id, now) {
    this.db.prepare("UPDATE inboxes SET last_seen = ? WHERE id = ?").run(now, id);
  }

  async deleteInbox(id) {
    this.db.prepare("DELETE FROM messages WHERE inbox = ?").run(id);
    this.db.prepare("DELETE FROM inboxes WHERE id = ?").run(id);
  }

  async countMessages(inbox) {
    return this.db.prepare("SELECT COUNT(*) AS n FROM messages WHERE inbox = ?").get(inbox).n;
  }

  async addMessage(inbox, id, token, body, now) {
    this.db.prepare("INSERT INTO messages (id, inbox, token, received, body) VALUES (?, ?, ?, ?, ?)")
      .run(id, inbox, token, now, body);
  }

  async listMessages(inbox, limit) {
    return this.db.prepare("SELECT id, received, token, body FROM messages WHERE inbox = ? ORDER BY seq LIMIT ?")
      .all(inbox, limit).map((row) => ({ ...row }));
  }

  async deleteMessage(inbox, id) {
    this.db.prepare("DELETE FROM messages WHERE inbox = ? AND id = ?").run(inbox, id);
  }

  /** Delete messages received before `before`; for one inbox, or for all when inbox is null. */
  async purgeMessages(before, inbox) {
    if (inbox) this.db.prepare("DELETE FROM messages WHERE received < ? AND inbox = ?").run(before, inbox);
    else this.db.prepare("DELETE FROM messages WHERE received < ?").run(before);
  }

  async purgeInboxes(before) {
    this.db.prepare("DELETE FROM messages WHERE inbox IN (SELECT id FROM inboxes WHERE last_seen < ?)").run(before);
    this.db.prepare("DELETE FROM inboxes WHERE last_seen < ?").run(before);
  }
}
