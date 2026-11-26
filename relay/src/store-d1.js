// Storage for Cloudflare Workers: a D1 database bound as `DB`.
export class D1Store {
  constructor(db) {
    this.db = db;
  }

  async getInbox(id) {
    const row = await this.db.prepare("SELECT tokens FROM inboxes WHERE id = ?").bind(id).first();
    return row ? { tokens: JSON.parse(row.tokens) } : null;
  }

  async countInboxes() {
    return (await this.db.prepare("SELECT COUNT(*) AS n FROM inboxes").first()).n;
  }

  async putInbox(id, tokens, now) {
    await this.db.prepare(
      "INSERT INTO inboxes (id, tokens, created, last_seen) VALUES (?, ?, ?, ?) " +
      "ON CONFLICT (id) DO UPDATE SET tokens = excluded.tokens, last_seen = excluded.last_seen",
    ).bind(id, JSON.stringify(tokens), now, now).run();
  }

  async touchInbox(id, now) {
    await this.db.prepare("UPDATE inboxes SET last_seen = ? WHERE id = ?").bind(now, id).run();
  }

  async deleteInbox(id) {
    await this.db.batch([
      this.db.prepare("DELETE FROM messages WHERE inbox = ?").bind(id),
      this.db.prepare("DELETE FROM inboxes WHERE id = ?").bind(id),
    ]);
  }

  async countMessages(inbox) {
    return (await this.db.prepare("SELECT COUNT(*) AS n FROM messages WHERE inbox = ?").bind(inbox).first()).n;
  }

  async addMessage(inbox, id, token, body, now) {
    await this.db.prepare("INSERT INTO messages (id, inbox, token, received, body) VALUES (?, ?, ?, ?, ?)")
      .bind(id, inbox, token, now, body).run();
  }

  async listMessages(inbox, limit) {
    const { results } = await this.db
      .prepare("SELECT id, received, token, body FROM messages WHERE inbox = ? ORDER BY seq LIMIT ?")
      .bind(inbox, limit).all();
    return results;
  }

  async deleteMessage(inbox, id) {
    await this.db.prepare("DELETE FROM messages WHERE inbox = ? AND id = ?").bind(inbox, id).run();
  }

  async purgeMessages(before, inbox) {
    if (inbox) {
      await this.db.prepare("DELETE FROM messages WHERE received < ? AND inbox = ?").bind(before, inbox).run();
    } else {
      await this.db.prepare("DELETE FROM messages WHERE received < ?").bind(before).run();
    }
  }

  async purgeInboxes(before) {
    await this.db.batch([
      this.db.prepare("DELETE FROM messages WHERE inbox IN (SELECT id FROM inboxes WHERE last_seen < ?)").bind(before),
      this.db.prepare("DELETE FROM inboxes WHERE last_seen < ?").bind(before),
    ]);
  }
}
