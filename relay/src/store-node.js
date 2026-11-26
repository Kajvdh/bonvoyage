// Storage for self-hosting: SQLite through Node's built-in node:sqlite.
import { readdirSync, readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";

const MIGRATIONS = new URL("../migrations/", import.meta.url);

export class NodeStore {
  constructor(path = ":memory:") {
    this.db = new DatabaseSync(path);
    this.db.exec("PRAGMA journal_mode = WAL");
    // Apply migrations that this database has not seen, in file-name order.
    const files = readdirSync(MIGRATIONS).filter((f) => f.endsWith(".sql")).sort();
    const done = this.db.prepare("PRAGMA user_version").get().user_version;
    files.slice(done).forEach((file, i) => {
      this.db.exec(readFileSync(new URL(file, MIGRATIONS), "utf8"));
      this.db.exec(`PRAGMA user_version = ${done + i + 1}`);
    });
  }

  async getInbox(id) {
    const row = this.db.prepare("SELECT tokens FROM inboxes WHERE id = ?").get(id);
    return row ? { tokens: JSON.parse(row.tokens) } : null;
  }

  async countInboxes() {
    return this.db.prepare("SELECT COUNT(*) AS n FROM inboxes").get().n;
  }

  async countInboxesSince(since) {
    return this.db.prepare("SELECT COUNT(*) AS n FROM inboxes WHERE created >= ?").get(since).n;
  }

  async putInbox(id, tokens, now) {
    this.db.prepare(
      "INSERT INTO inboxes (id, tokens, created, last_seen) VALUES (?, ?, ?, ?) " +
      "ON CONFLICT (id) DO UPDATE SET tokens = excluded.tokens, last_seen = excluded.last_seen",
    ).run(id, JSON.stringify(tokens), now, now);
  }

  async markCollected(id, now) {
    this.db.prepare("UPDATE inboxes SET last_seen = ?, last_collected = ? WHERE id = ?").run(now, now, id);
  }

  async deleteInbox(id) {
    this.db.prepare("DELETE FROM messages WHERE inbox = ?").run(id);
    this.db.prepare("DELETE FROM inboxes WHERE id = ?").run(id);
  }

  /** Messages waiting in an inbox; with a token ID, only those that arrived with it. */
  async countMessages(inbox, token) {
    if (token) return this.db.prepare("SELECT COUNT(*) AS n FROM messages WHERE inbox = ? AND token = ?").get(inbox, token).n;
    return this.db.prepare("SELECT COUNT(*) AS n FROM messages WHERE inbox = ?").get(inbox).n;
  }

  async countAllMessages() {
    return this.db.prepare("SELECT COUNT(*) AS n FROM messages").get().n;
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

  /** Remove inboxes not used since `inactiveBefore`, and never-collected ones created before `unusedBefore`. */
  async purgeInboxes(inactiveBefore, unusedBefore) {
    const stale = "last_seen < ? OR (last_collected IS NULL AND created < ?)";
    this.db.prepare(`DELETE FROM messages WHERE inbox IN (SELECT id FROM inboxes WHERE ${stale})`).run(inactiveBefore, unusedBefore);
    this.db.prepare(`DELETE FROM inboxes WHERE ${stale}`).run(inactiveBefore, unusedBefore);
  }

  /** Record an accepted signature. Returns false when it was already recorded. */
  async rememberAuth(signatureHash, now) {
    return this.db.prepare("INSERT OR IGNORE INTO auth_seen (sig, t) VALUES (?, ?)").run(signatureHash, now).changes === 1;
  }

  async purgeAuth(before) {
    this.db.prepare("DELETE FROM auth_seen WHERE t < ?").run(before);
  }
}
