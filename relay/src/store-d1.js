// Storage for Cloudflare Workers: a D1 database bound as `DB`.
export class D1Store {
  constructor(db) {
    this.db = db;
  }

  async getInbox(id) {
    const row = await this.db.prepare("SELECT tokens, last_collected FROM inboxes WHERE id = ?").bind(id).first();
    return row ? { tokens: JSON.parse(row.tokens), lastCollected: row.last_collected } : null;
  }

  async countInboxes() {
    return (await this.db.prepare("SELECT COUNT(*) AS n FROM inboxes").first()).n;
  }

  async countInboxesSince(since) {
    return (await this.db.prepare("SELECT COUNT(*) AS n FROM inboxes WHERE created >= ?").bind(since).first()).n;
  }

  async putInbox(id, tokens, now) {
    await this.db.prepare(
      "INSERT INTO inboxes (id, tokens, created, last_seen) VALUES (?, ?, ?, ?) " +
      "ON CONFLICT (id) DO UPDATE SET tokens = excluded.tokens, last_seen = excluded.last_seen",
    ).bind(id, JSON.stringify(tokens), now, now).run();
  }

  async markCollected(id, now) {
    await this.db.prepare("UPDATE inboxes SET last_seen = ?, last_collected = ? WHERE id = ?").bind(now, now, id).run();
  }

  async deleteInbox(id) {
    await this.db.batch([
      this.db.prepare("DELETE FROM messages WHERE inbox = ?").bind(id),
      this.db.prepare("DELETE FROM inboxes WHERE id = ?").bind(id),
    ]);
  }

  async countMessages(inbox, token) {
    const query = token
      ? this.db.prepare("SELECT COUNT(*) AS n FROM messages WHERE inbox = ? AND token = ?").bind(inbox, token)
      : this.db.prepare("SELECT COUNT(*) AS n FROM messages WHERE inbox = ?").bind(inbox);
    return (await query.first()).n;
  }

  async countAllMessages() {
    return (await this.db.prepare("SELECT COUNT(*) AS n FROM messages").first()).n;
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

  async purgeInboxes(inactiveBefore, unusedBefore) {
    const stale = "last_seen < ? OR (last_collected IS NULL AND created < ?)";
    await this.db.batch([
      this.db.prepare(`DELETE FROM messages WHERE inbox IN (SELECT id FROM inboxes WHERE ${stale})`).bind(inactiveBefore, unusedBefore),
      this.db.prepare(`DELETE FROM inboxes WHERE ${stale}`).bind(inactiveBefore, unusedBefore),
    ]);
  }

  async rememberAuth(signatureHash, now) {
    const result = await this.db.prepare("INSERT OR IGNORE INTO auth_seen (sig, t) VALUES (?, ?)").bind(signatureHash, now).run();
    return result.meta.changes === 1;
  }

  async purgeAuth(before) {
    await this.db.prepare("DELETE FROM auth_seen WHERE t < ?").bind(before).run();
  }
}
