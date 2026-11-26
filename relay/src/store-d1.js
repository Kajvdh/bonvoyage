// Storage for Cloudflare Workers: a D1 database bound as `DB`.
import { queries } from "./queries.js";

export class D1Store {
  constructor(db) {
    Object.assign(this, queries({
      run: async (sql, args) => (await db.prepare(sql).bind(...args).run()).meta.changes,
      get: async (sql, args) => db.prepare(sql).bind(...args).first(),
      all: async (sql, args) => (await db.prepare(sql).bind(...args).all()).results,
    }));
  }
}
