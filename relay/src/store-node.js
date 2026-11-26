// Storage for self-hosting: SQLite through Node's built-in node:sqlite.
import { readdirSync, readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { queries } from "./queries.js";

const MIGRATIONS = new URL("../migrations/", import.meta.url);

export class NodeStore {
  constructor(path = ":memory:") {
    const db = new DatabaseSync(path);
    db.exec("PRAGMA journal_mode = WAL");
    // Apply migrations that this database has not seen, in file-name order.
    const files = readdirSync(MIGRATIONS).filter((f) => f.endsWith(".sql")).sort();
    const done = db.prepare("PRAGMA user_version").get().user_version;
    files.slice(done).forEach((file, i) => {
      // All or nothing: an interrupted migration must not leave a half-changed database behind.
      db.exec("BEGIN");
      try {
        db.exec(readFileSync(new URL(file, MIGRATIONS), "utf8"));
        db.exec(`PRAGMA user_version = ${done + i + 1}`);
        db.exec("COMMIT");
      } catch (error) {
        db.exec("ROLLBACK");
        throw error;
      }
    });
    Object.assign(this, queries({
      run: async (sql, args) => Number(db.prepare(sql).run(...args).changes),
      get: async (sql, args) => db.prepare(sql).get(...args) ?? null,
      all: async (sql, args) => db.prepare(sql).all(...args).map((row) => ({ ...row })),
    }));
  }
}
