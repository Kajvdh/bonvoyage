// SQL shared by both storage backends. `run` executes a statement that changes rows and
// returns how many; `get` returns one row or null; `all` returns rows.
export function queries({ run, get, all }) {
  const STALE = (days) => `last_seen < ?1 OR (collect_days < ${Number(days)} AND created < ?2)`;
  return {
    async getInbox(id) {
      const row = await get("SELECT tokens, last_collected, last_auth, collect_days FROM inboxes WHERE id = ?1", [id]);
      return row ? { tokens: JSON.parse(row.tokens), lastCollected: row.last_collected, lastAuth: row.last_auth, collectDays: row.collect_days } : null;
    },

    async getTombstone(id) {
      return (await get("SELECT t FROM tombstones WHERE id = ?1", [id]))?.t ?? 0;
    },

    async countInboxes() {
      return (await get("SELECT COUNT(*) AS n FROM inboxes", [])).n;
    },

    async countInboxesSince(since) {
      return (await get("SELECT COUNT(*) AS n FROM inboxes WHERE created >= ?1", [since])).n;
    },

    async putInbox(id, tokens, now, time) {
      await run(
        "INSERT INTO inboxes (id, tokens, created, last_seen, last_auth) VALUES (?1, ?2, ?3, ?3, ?4) " +
        "ON CONFLICT (id) DO UPDATE SET tokens = excluded.tokens, last_seen = excluded.last_seen, last_auth = excluded.last_auth",
        [id, JSON.stringify(tokens), now, time]);
    },

    /** Record a collection; `day` counts towards the inbox becoming established, once per day. */
    async markCollected(id, now, day) {
      await run(
        "UPDATE inboxes SET last_seen = ?2, last_collected = ?2, " +
        "collect_days = collect_days + (last_collect_day <> ?3), last_collect_day = ?3 WHERE id = ?1",
        [id, now, day]);
    },

    async deleteInbox(id, time, now) {
      await run("DELETE FROM messages WHERE inbox = ?1", [id]);
      await run("DELETE FROM inboxes WHERE id = ?1", [id]);
      await run("INSERT INTO tombstones (id, t, deleted) VALUES (?1, ?2, ?3) ON CONFLICT (id) DO UPDATE SET t = excluded.t, deleted = excluded.deleted",
        [id, time, now]);
    },

    /** Store a message unless the inbox is gone or one of its quotas is reached. One statement: no race. */
    async addMessage({ inbox, id, token, body, now, notBefore, inboxLimit, tokenLimit }) {
      return (await run(
        "INSERT INTO messages (id, inbox, token, received, body) SELECT ?1, ?2, ?3, ?4, ?5 " +
        "WHERE EXISTS (SELECT 1 FROM inboxes WHERE id = ?2) " +
        "AND (SELECT COUNT(*) FROM messages WHERE inbox = ?2 AND received >= ?6) < ?7 " +
        "AND (SELECT COUNT(*) FROM messages WHERE inbox = ?2 AND token = ?3 AND received >= ?6) < ?8",
        [id, inbox, token, now, body, notBefore, inboxLimit, tokenLimit])) === 1;
    },

    async listMessages(inbox, limit) {
      return all("SELECT id, received, token, body FROM messages WHERE inbox = ?1 ORDER BY seq LIMIT ?2", [inbox, limit]);
    },

    async deleteMessage(inbox, id) {
      await run("DELETE FROM messages WHERE inbox = ?1 AND id = ?2", [inbox, id]);
    },

    /** Delete messages received before `before`; for one inbox, or for all when inbox is null. */
    async purgeMessages(before, inbox) {
      if (inbox) await run("DELETE FROM messages WHERE inbox = ?2 AND received < ?1", [before, inbox]);
      else await run("DELETE FROM messages WHERE received < ?1", [before]);
    },

    /** Remove inboxes unused since `inactiveBefore`, and ones created before `youngBefore` that never became established. */
    async purgeInboxes(inactiveBefore, youngBefore, days) {
      await run(`DELETE FROM messages WHERE inbox IN (SELECT id FROM inboxes WHERE ${STALE(days)})`, [inactiveBefore, youngBefore]);
      await run(`DELETE FROM inboxes WHERE ${STALE(days)}`, [inactiveBefore, youngBefore]);
    },

    async purgeShortLived(tombstonesBefore, currentHour) {
      await run("DELETE FROM tombstones WHERE deleted < ?1", [tombstonesBefore]);
      await run("DELETE FROM counters WHERE window < ?1", [currentHour]);
    },

    /** Count one more event for `key` in this window and return the new count. */
    async bumpCounter(key, window) {
      await run(
        "INSERT INTO counters (key, window, n) VALUES (?1, ?2, 1) " +
        "ON CONFLICT (key) DO UPDATE SET n = CASE WHEN window = excluded.window THEN n + 1 ELSE 1 END, window = excluded.window",
        [key, window]);
      return (await get("SELECT n FROM counters WHERE key = ?1", [key])).n;
    },

    /** Running totals: all waiting messages, and those in inboxes that are not established. */
    async getStats() {
      const rows = await all("SELECT key, n, computed FROM stats", []);
      const of = (key) => rows.find((r) => r.key === key) ?? { n: 0, computed: 0 };
      return { messages: of("messages").n, newMessages: of("new").n, computed: of("messages").computed };
    },

    async recomputeStats(now, days) {
      const messages = (await get("SELECT COUNT(*) AS n FROM messages", [])).n;
      const fresh = (await get(
        `SELECT COUNT(*) AS n FROM messages WHERE inbox IN (SELECT id FROM inboxes WHERE collect_days < ${Number(days)})`, [])).n;
      const upsert = "INSERT INTO stats (key, n, computed) VALUES (?1, ?2, ?3) ON CONFLICT (key) DO UPDATE SET n = excluded.n, computed = excluded.computed";
      await run(upsert, ["messages", messages, now]);
      await run(upsert, ["new", fresh, now]);
      return { messages, newMessages: fresh, computed: now };
    },

    async bumpStats(alsoNew) {
      await run(alsoNew ? "UPDATE stats SET n = n + 1" : "UPDATE stats SET n = n + 1 WHERE key = 'messages'", []);
    },
  };
}
