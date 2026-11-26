// SQL shared by both storage backends. `run` executes a statement that changes rows and
// returns how many; `get` returns one row or null; `all` returns rows.
export function queries({ run, get, all }) {
  const UPSERT_STAT = "INSERT INTO stats (key, n, computed) VALUES (?1, ?2, ?3) ON CONFLICT (key) DO UPDATE SET n = excluded.n, computed = excluded.computed";
  const bump = (key, by) => run("UPDATE stats SET n = MAX(0, n + ?2) WHERE key = ?1", [key, by]);

  return {
    async getInbox(id) {
      const row = await get("SELECT tokens, last_collected, last_auth FROM inboxes WHERE id = ?1", [id]);
      return row ? { tokens: JSON.parse(row.tokens), lastCollected: row.last_collected, lastAuth: row.last_auth } : null;
    },

    async getTombstone(id) {
      return (await get("SELECT t FROM tombstones WHERE id = ?1", [id]))?.t ?? 0;
    },

    async countInboxesSince(since) {
      return (await get("SELECT COUNT(*) AS n FROM inboxes WHERE created >= ?1", [since])).n;
    },

    /**
     * Create an inbox or replace its settings, but only if `time` is later than the last accepted
     * request for it (also when that request deleted it). One statement, so two requests cannot
     * both pass a check and then overwrite each other. Returns "created", "updated" or "stale".
     */
    async putInbox(id, tokens, now, time) {
      const existed = Boolean(await get("SELECT 1 AS x FROM inboxes WHERE id = ?1", [id]));
      const changed = await run(
        "INSERT INTO inboxes (id, tokens, created, last_seen, last_auth) SELECT ?1, ?2, ?3, ?3, ?4 " +
        "WHERE NOT EXISTS (SELECT 1 FROM tombstones WHERE id = ?1 AND t >= ?4) " +
        "ON CONFLICT (id) DO UPDATE SET tokens = excluded.tokens, last_seen = excluded.last_seen, last_auth = excluded.last_auth " +
        "WHERE excluded.last_auth > inboxes.last_auth",
        [id, JSON.stringify(tokens), now, time]);
      if (changed !== 1) return "stale";
      if (!existed) await bump("inboxes", 1);
      return existed ? "updated" : "created";
    },

    async markCollected(id, now) {
      await run("UPDATE inboxes SET last_seen = ?2, last_collected = ?2 WHERE id = ?1", [id, now]);
    },

    /** Delete an inbox if `time` is later than its last accepted request. Returns false when it is not. */
    async deleteInbox(id, time, now) {
      const gone = await run("DELETE FROM inboxes WHERE id = ?1 AND last_auth < ?2", [id, time]);
      if (gone !== 1) {
        if (await get("SELECT 1 AS x FROM inboxes WHERE id = ?1", [id])) return false;
        if ((await this.getTombstone(id)) >= time) return false;
      } else {
        await bump("inboxes", -1);
      }
      const removed = await run("DELETE FROM messages WHERE inbox = ?1", [id]);
      if (removed) await bump("messages", -removed);
      await run("INSERT INTO tombstones (id, t, deleted) VALUES (?1, ?2, ?3) ON CONFLICT (id) DO UPDATE SET t = excluded.t, deleted = excluded.deleted",
        [id, time, now]);
      return true;
    },

    /** Remove the inbox that has gone unused the longest, if that is longer ago than `idleBefore`. */
    async evictIdleInbox(idleBefore) {
      const row = await get("SELECT id FROM inboxes WHERE last_seen < ?1 ORDER BY last_seen LIMIT 1", [idleBefore]);
      if (!row) return false;
      const removed = await run("DELETE FROM messages WHERE inbox = ?1", [row.id]);
      await run("DELETE FROM inboxes WHERE id = ?1", [row.id]);
      await bump("inboxes", -1);
      if (removed) await bump("messages", -removed);
      return true;
    },

    /** Store a message unless the inbox is gone or one of its quotas is reached. One statement: no race. */
    async addMessage({ inbox, id, token, body, now, notBefore, inboxLimit, tokenLimit }) {
      const stored = (await run(
        "INSERT INTO messages (id, inbox, token, received, body) SELECT ?1, ?2, ?3, ?4, ?5 " +
        "WHERE EXISTS (SELECT 1 FROM inboxes WHERE id = ?2) " +
        "AND (SELECT COUNT(*) FROM messages WHERE inbox = ?2 AND received >= ?6) < ?7 " +
        "AND (SELECT COUNT(*) FROM messages WHERE inbox = ?2 AND token = ?3 AND received >= ?6) < ?8",
        [id, inbox, token, now, body, notBefore, inboxLimit, tokenLimit])) === 1;
      if (stored) await bump("messages", 1);
      return stored;
    },

    /** Make room: drop the oldest message of the inbox that holds the most. */
    async evictMessage() {
      const row = await get("SELECT inbox FROM messages GROUP BY inbox ORDER BY COUNT(*) DESC, MIN(seq) LIMIT 1", []);
      if (!row) return false;
      const removed = await run("DELETE FROM messages WHERE seq = (SELECT MIN(seq) FROM messages WHERE inbox = ?1)", [row.inbox]);
      if (removed) await bump("messages", -removed);
      return removed === 1;
    },

    async listMessages(inbox, limit) {
      return all("SELECT id, received, token, body FROM messages WHERE inbox = ?1 ORDER BY seq LIMIT ?2", [inbox, limit]);
    },

    async deleteMessage(inbox, id) {
      const removed = await run("DELETE FROM messages WHERE inbox = ?1 AND id = ?2", [inbox, id]);
      if (removed) await bump("messages", -removed);
    },

    /** Delete messages received before `before`; for one inbox, or for all when inbox is null. */
    async purgeMessages(before, inbox) {
      const removed = inbox
        ? await run("DELETE FROM messages WHERE inbox = ?2 AND received < ?1", [before, inbox])
        : await run("DELETE FROM messages WHERE received < ?1", [before]);
      if (removed) await bump("messages", -removed);
    },

    /** Remove inboxes unused since `inactiveBefore`, and never-collected ones created before `unusedBefore`. */
    async purgeInboxes(inactiveBefore, unusedBefore) {
      const stale = "last_seen < ?1 OR (last_collected IS NULL AND created < ?2)";
      await run(`DELETE FROM messages WHERE inbox IN (SELECT id FROM inboxes WHERE ${stale})`, [inactiveBefore, unusedBefore]);
      await run(`DELETE FROM inboxes WHERE ${stale}`, [inactiveBefore, unusedBefore]);
    },

    async purgeShortLived(tombstonesBefore, currentHour) {
      await run("DELETE FROM tombstones WHERE deleted < ?1", [tombstonesBefore]);
      await run("DELETE FROM counters WHERE window < ?1", [currentHour]);
    },

    /** Count one more event for `key` in this window and return the new count. Older windows are dropped on the way. */
    async bumpCounter(key, window) {
      await run("DELETE FROM counters WHERE window < ?1", [window]);
      await run(
        "INSERT INTO counters (key, window, n) VALUES (?1, ?2, 1) " +
        "ON CONFLICT (key) DO UPDATE SET n = CASE WHEN window = excluded.window THEN n + 1 ELSE 1 END, window = excluded.window",
        [key, window]);
      return (await get("SELECT n FROM counters WHERE key = ?1", [key])).n;
    },

    /** Running totals of inboxes and waiting messages, kept by the statements above. */
    async getStats() {
      const rows = await all("SELECT key, n FROM stats", []);
      if (rows.length < 2) return null;
      const of = (key) => rows.find((r) => r.key === key)?.n ?? 0;
      return { inboxes: of("inboxes"), messages: of("messages") };
    },

    /** Count for real. Done at first use and by the cleanup job, which corrects any drift. */
    async recomputeStats(now) {
      const inboxes = (await get("SELECT COUNT(*) AS n FROM inboxes", [])).n;
      const messages = (await get("SELECT COUNT(*) AS n FROM messages", [])).n;
      await run(UPSERT_STAT, ["inboxes", inboxes, now]);
      await run(UPSERT_STAT, ["messages", messages, now]);
      return { inboxes, messages };
    },
  };
}
