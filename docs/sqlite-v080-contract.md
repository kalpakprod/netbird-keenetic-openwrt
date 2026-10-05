// Port of netbird management/server/store (v0.80.0), BSD-3-Clause
// SQLite contract for the Zig port: what NetBird v0.80.0 actually uses.
// Reference: upstream-v080 at fca64287cf51a85552a41b022013abbfdb335452.
// This is a feasibility contract, not an implementation. File-header parsing
// alone proves nothing about database compatibility.

# SQLite v0.80.0 contract (management store)

## 1. Driver stack (source-backed)

- `go.mod:145-148`: `gorm.io/driver/sqlite v1.5.7`, `gorm.io/driver/postgres v1.5.7`,
  `gorm.io/driver/mysql v1.5.7`, `gorm.io/gorm v1.25.12`.
- `vendor/gorm.io/driver/sqlite/sqlite.go:10`: `import _ "github.com/mattn/go-sqlite3"`.
- `vendor/github.com/mattn/go-sqlite3/sqlite3.go:7-8`: `//go:build cgo`. The SQLite
  driver is CGO. Bundled engine: `SQLITE_VERSION "3.51.3"`
  (`vendor/github.com/mattn/go-sqlite3/sqlite3-binding.h:150`).
- `vendor/gorm.io/driver/sqlite/sqlite.go:61-75`: on open the driver runs
  `select sqlite_version()`; if >= 3.35.0 it registers `ON CONFLICT`/`RETURNING`
  callbacks. Bundled 3.51.3 satisfies this, so NetBird relies on
  `INSERT ... ON CONFLICT ... RETURNING` and `UPDATE ... RETURNING`.
- Consequence for the no-C rule: every SQLite path in the Go server links C
  (mattn binding). A Zig port must either write a pure-Zig SQLite engine or
  keep SQLite out of the Zig binary. There is no third option; `std` has no
  SQLite (`grep -rln sqlite $ziglib` returns nothing) and no pure-Zig reuse
  candidate exists in this worktree (`src/`, `tools/`, `docs/` contain no
  database engine; W02 `docs/release-v080-inventory.md` names SQLite only as
  the CGO conflict D-01).

## 2. Open parameters (exact)

Main store (`management/server/store/sql_store.go:183-226`, `NewSqliteStore`):

- File: `store.db` (`storeSqliteFileName`, sql_store.go:45), override
  `NB_STORE_ENGINE_SQLITE_FILE`; relative path joined under `dataDir`.
- DSN defaults injected when the user provides no query string:
  `_busy_timeout=30000` (30 s lock wait on the single Go-side connection) and,
  on non-Windows, `cache=shared`. User `?_busy_timeout`/`?_timeout` overrides
  the default. mattn applies DSN PRAGMAs on every fresh connection, so the
  value survives pool recycling (comment sql_store.go:198-205).
- `NewSqlStore` (sql_store.go:77-142) forces `MaxOpenConns = MaxIdleConns = 1`
  for `types.SqliteStoreEngine` (sql_store.go:96-102), `ConnMaxLifetime 1h`,
  `ConnMaxIdleTime 3m`. SQLite is single-connection by construction.
- Driver name `sqlite3`, placeholder dialect `?` (see section 6).

Activity store (`management/server/activity/store/sql_store.go:242-278`,
`initDatabase`): file `events.db` (`eventSinkDB`), override
`NB_ACTIVITY_EVENT_SQLITE_FILE`; engine selectable via
`NB_ACTIVITY_EVENT_STORE_ENGINE` (default sqlite, postgres supported, section 8).
Note: unlike the main store it injects no `_busy_timeout` default.

Network-map read store
(`management/internals/network_map_db/sqlite/sqlite_store.go:32-76`,
`NewSqliteStore`): same DSN composition (`_busy_timeout=30000`,
`cache=shared`, `:memory:` supported), but uses raw `database/sql`
(`sql.Open("sqlite3", connStr)`), not GORM. Read-only transactions:
`BeginTx` uses `sql.TxOptions{ReadOnly: true, Isolation: LevelRepeatableRead}`.

Embedded Dex IdP (`idp/dex/sqlite_cgo.go` vs `idp/dex/sqlite_nocgo.go`):
CGO builds use upstream `sql.SQLite3{File: file}`; non-CGO builds get a stub
whose `Open()` returns "SQLite not available". Upstream itself already ships
the no-C SQLite gap as a hard error.

## 3. Journal / WAL / locking / crash recovery (what is actually used)

- No `journal_mode`, `synchronous`, `locking_mode`, `VACUUM`, checkpoint, fsync,
  or backup API appears anywhere in `management/`, `signal/`, `relay/`
  (case-insensitive grep for those terms over non-vendor, non-test Go files
  returns only firewall-rule and prose false positives). The store runs SQLite
  defaults: rollback-journal mode, atomic commit for crash recovery.
- Locking actually used:
  - Process/mutex level: `globalAccountLock sync.Mutex` (`AcquireGlobalLock`,
    sql_store.go) plus single DB connection. SQLite never sees concurrent
    writers from one server process.
  - `PRAGMA defer_foreign_keys = ON` on SQLite, and only in the IdP user-ID
    migration transaction (`sql_store_idp_migration.go:60-61`). Plain
    `ExecuteInTransaction` issues no SQLite PRAGMA at all (sql_store.go:449-523).
  - `_busy_timeout=30000` via DSN (section 2) is the only lock-wait tuning.
- Row-level `clause.Locking` (`FOR UPDATE`/`SHARE`/...) is a Postgres/MySQL
  feature in this codebase: the SQLite dialect drops it silently
  (`vendor/gorm.io/driver/sqlite/sqlite.go:123-129`, `"FOR"` builder returns
  without emitting for `clause.Locking`). Callers pass `LockingStrengthNone`
  almost everywhere (e.g. `account.go`); `LockingStrengthUpdate` appears only
  inside transactions where SQLite ignores the clause. A Zig engine must
  reproduce the *ignored* semantics, not the SQL text: never emit `FOR UPDATE`
  to SQLite, and never rely on it for correctness on SQLite.

## 4. Transaction shape

- `ExecuteInTransaction` (sql_store.go:449-523): `Begin` on a 5-minute timeout
  context (`transactionTimeout`, env `NB_STORE_TRANSACTION_TIMEOUT`, default
  5m, sql_store.go:88-94); Postgres-only `SET LOCAL statement_timeout`,
  `lock_timeout`; MySQL-only `SET FOREIGN_KEY_CHECKS = 0/1`; then
  `operation(withTx(tx))`, rollback on error/panic, `Commit`, warn on timeout.
- `transaction()` helper (sql_store.go) wraps `db.Transaction` with the same
  MySQL FK-checks toggle. SQLite takes the plain path in both.
- Canonical write `SaveAccount` (sql_store_account.go): one transaction doing
  `Delete(policies)`, `Delete(users)`, `Delete(account)` with
  `Select(clause.Associations)`, then `Create(account)` with
  `FullSaveAssociations` + `OnConflict{UpdateAll: true}`. I.e. full-account
  delete-plus-upsert, not differential writes. 14 `Transaction(`/`Begin(`
  call sites in non-test `store/` + activity + network_map_db/sqlite code
  (plus ~130 further Commit/Rollback/close/`Clauses` touch points in the same
  files); `SqlStore` exposes 301 methods (32 `sql_store_*.go` files, tests
  excluded).
- Error mapping the Zig layer must reproduce
  (`vendor/gorm.io/driver/sqlite/error_translator.go`): extended codes 1555
  and 2067 map to `gorm.ErrDuplicatedKey`, 787 to `gorm.ErrForeignKeyViolated`.

## 5. Schema: tables and column encoding

AutoMigrate list (sql_store.go:119-133), ~40 models, all required for a
compatible `store.db`:

- Core: `types.SetupKey`, `nbpeer.Peer`, `types.User`, `PersonalAccessToken`,
  `ProxyAccessToken`, `types.Group`, `types.GroupPeer`, `types.Account`,
  `types.Policy`, `types.PolicyRule`, `route.Route`, `dns.NameServerGroup`,
  `installation`, `types.ExtraSettings`, `posture.Checks`,
  `nbpeer.NetworkAddress`.
- Networks: `networkTypes.Network`, `routerTypes.NetworkRouter`,
  `resourceTypes.NetworkResource`, `types.AccountOnboarding`, `types.Job`,
  `zones.Zone`, `records.Record`, `types.UserInviteRecord`.
- Reverse proxy: `rpservice.Service`, `rpservice.Target`, `domain.Domain`,
  `accesslogs.AccessLogEntry`, `proxy.Proxy`.
- Agent network: `Provider`, `Policy`, `Guardrail`, `Settings`, `Consumption`,
  `AccountBudgetRule`, `AgentNetworkAccessLog(+Group)`, `AgentNetworkUsage(+Group)`.
- Activity `events.db`: `activity.Event`, `activity.DeletedUser` plus
  `LEFT JOIN deleted_users` name/email resolution in `Get`
  (activity/sql_store.go `Get`).

Column encodings a Zig engine must reproduce byte-for-byte:

- ~40 `gorm:"serializer:json"` fields (peer meta, policy rule
  sources/destinations/ports/ranges/groups, groups, JWT allow groups,
  `net.IPNet`/`netip.Prefix`/`netip.Addr`, `net.IPNet` in account network).
  Stored as TEXT JSON; queries never index inside them (except the migrated
  peer `ip` index, section 7).
- `jobs.parameters`/`jobs.result` are `json.RawMessage` with `type:json`;
  `JobStatus`/`JobType` are `varchar(50)` indexed.
- TEXT primary keys everywhere (`Id string gorm:"primaryKey"`); the MySQL-only
  `` `key` `` quoting (`mysqlKeyQueryCondition`, sql_store.go) must not leak
  into SQLite SQL.
- GORM associations materialize as join tables / foreign keys with
  `FullSaveAssociations` + `OnConflict{UpdateAll: true}`; `Preload(...)` chains
  (e.g. `getAccountGorm`: `UsersG.PATsG`, `Policies.Rules`, `Services.Targets`,
  16 preloads) must be emulated, typically as N+1 SELECTs in dependency order.

## 6. Query dialect actually exercised on SQLite

- Placeholders are `?` on every SQLite path (GORM sqlite dialect; raw
  network-map queries e.g. `where account_id=?` in `network_map_db/sqlite/*.go`;
  16 query files: policy, peer, group, user, route, service, network(s),
  network_router, network_resource, dns, dns_setting, nameserver, domain,
  account_setting, posture). The Postgres twins use `$1` (pgx) and
  `s.pool.Query` (e.g. `sql_store_peer.go:184-198` `getPeers` with an explicit
  40-column SELECT). MySQL/Postgres-only SQL (`SET LOCAL`, `FOREIGN_KEY_CHECKS`,
  backticks, `CREATE DATABASE ... TEMPLATE`, `DROP DATABASE ... WITH (FORCE)`)
  must never be sent to SQLite.
- SQLite-significant GORM features in use: `OnConflict{UpdateAll:true}` /
  `OnConflict{DoNothing:true}` / column-targeted upserts (activity deleted-user
  upsert on `id`), `LIMIT -1/OFFSET` emulation in the sqlite `LIMIT` builder,
  `Migrator()` (`HasTable`/`HasColumn`/`RenameTable`/`CreateTable`/`DropTable`/
  `ColumnTypes`), `Table("(?) AS ...")` subquery counting (agent-network access
  log), `CreateBatchSize: 400` (`getGormConfig`).
- Required statement support for parity: SELECT with JOIN/WHERE/ORDER/LIMIT/
  OFFSET/COUNT, INSERT with ON CONFLICT + RETURNING (needs engine >= 3.35.0;
  bundled is 3.51.3), UPDATE/DELETE with RETURNING, explicit transactions
  (BEGIN/COMMIT/ROLLBACK incl. read-only repeatable-read for network-map),
  schema introspection via `sqlite_master`, and the two PRAGMAs
  (`busy_timeout`, `defer_foreign_keys`).

## 7. Migrations (Go-to-Zig and back)

Order: `migratePreAuto` -> `AutoMigrate` (~40 models) -> `migratePostAuto`
(`NewSqlStore`, sql_store.go:115-142; lists in `store.go:559-700`).

- Pre-auto (representative, `store.go:559-641`): gob-to-JSON field conversions
  (`Account.network_net`, `Route.network`, `Route.peer_groups`),
  blob-to-JSON netip fields (`Peer.location_connection_ip`, `Peer.ip` +
  `idx_peers_account_id_ip` rebuild), setup-key hashing migration, `enabled`
  backfill on resources/routers, index drops, user name/email backfill,
  `peer_status_session_started_at` backfill, duplicate peer-key removal,
  orphan cleanup, `BackfillPublicIDs` on policies/groups/routes/resources/
  routers/name-server-groups/networks/posture-checks, agent-network
  settings-to-domain migration.
- Post-auto (`store.go:655-700`): custom-domain expiry migration, peer
  `idx_account_ip` / `idx_account_dnslabel` creation, group `peers` JSON-table
  split, `idx_peers_key` -> `idx_peers_key_unique` swap, proxy index drop,
  cost-aggregate folding into buckets.
- Cross-engine copies (the Go-to-Zig-and-back contract surface):
  `MigrateFileStoreToSqlite` / `NewSqliteStoreFromFileStore` (JSON
  `store.json` -> `store.db`; CLI `management/cmd/migration_up.go`);
  `NewPostgresqlStoreFromSqlStore` / `NewMysqlStoreFromSqlStore` via
  `seedFromSqliteStore` (`SaveInstallationID` + `SaveAccount` per account).
  A Zig store must read *and* write rows the Go code accepts in both
  directions, including every migration above (old databases must still open)
  and field encryption (`crypt.FieldEncrypt`, AES-GCM over user PII columns;
  activity `deleted_users` uses `enc_algo = "GCM"`).
- Test-loader seam: `LoadSQL` (`store.go:1201-1220`) splits a `.sql` file on
  `;` and `Exec`s each statement; `NewTestStoreFromSQL` builds a SQLite store
  from it and optionally reseeds Postgres/MySQL via testcontainers. No `.sql`
  fixtures are checked in; fixtures are derivable by dumping a migrated
  SQLite test store (Not verified: no fixture generated in this card, see
  section 10).

## 8. PostgreSQL / MySQL requirements (what Zig does NOT need for SQLite)

- Postgres adds: `pgxpool` (30 max / 1 min conns, 60m lifetime, 1m health
  check; `connectToPgDb`, sql_store.go), hand-written pgx SELECTs behind
  `if s.pool != nil` (e.g. `GetAccount` -> `getAccountPgx` vs `getAccountGorm`,
  sql_store_account.go:283-287; ~19 files reference `s.pool`),
  `TestPgxServiceColumnsMatchGorm` parity test guarding SELECT drift,
  `SET LOCAL` timeouts, DEFERRABLE FK rework
  (`sql_store_idp_migration.go:63-101`), `CREATE/DROP DATABASE` test scaffolding.
- MySQL adds: `charset=utf8&parseTime=True&loc=Local` DSN suffix, backtick
  `` `key` `` condition, session `FOREIGN_KEY_CHECKS` toggling.
- None of the above applies to the SQLite contract. Do not port pgx wire
  protocol or MySQL protocol for SQLite parity; do port the GORM-path
  semantics (preload order, upsert winners, GCM-encrypted PII round-trip).

## 9. Zig work breakdown (dependency DAG, assigned to W10 follow-ups)

1. `sqlite/vfs.zig`: OS file VFS on Linux 4.9 syscalls only (no io_uring,
   statx, openat2); POSIX `fcntl` locking; rollback-journal pager; single
   writer + busy-timeout. No WAL in v1 (upstream does not use it).
2. `sqlite/btree.zig`: varint/serial-type record codec, B-tree pages,
   `sqlite_master` schema codec. Fuzz against Go-produced `store.db` pages.
3. `sqlite/sql.zig`: parser + planner for the section-6 subset; `?`
   bindings; `ON CONFLICT`/`RETURNING` (>= 3.35 semantics); `LIMIT -1/OFFSET`.
4. `sqlite/tx.zig`: BEGIN/COMMIT/ROLLBACK incl. read-only repeatable-read
   snapshots; `busy_timeout`; `defer_foreign_keys`; error codes 1555/2067/787.
5. `sqlite/gorm.zig`: DDL generator matching section-5 tables, JSON
   serializer codec, preload-order reads, batch-create chunking (400),
   `Migrator()` operations.
6. `store/sqlite.zig`: the 301-method `Store` surface over 5; activity
   `events.db` store; network-map 16-query reader.
7. `store/migrate.zig`: pre/post migration runner (section 7) + JSON-file
   importer + cross-engine exporter (`LoadSQL`-compatible dump format).
8. Fixtures: checked-in `.sql` dump(s) produced from a migrated Go test store
   plus a Zig round-trip test (Go -> Zig -> Go byte-identical rows). Blocked
   on section 10.

Estimated scope: full SQLite engine, ~8-12k lines Zig + fixtures. This card
implements none of it; it only fixes the contract so estimates are grounded.

## 10. Blockers and Not verified

- True blocker: no pure-Zig SQLite implementation exists in this project and
  `std` provides none (verified by grep, section 1). SQLite support is the
  long pole of any management-server port; client-only milestones are
  unaffected (client `syncstore/disk.go` is a protobuf file write, not SQL).
- True blocker: no checked-in reference fixture (`.sql` dump or small
  `store.db`) may be generated by this card: producing one requires executing
  Go store code, which is a database-creating side effect outside this
  investigation's authority ("never run production/database mutations").
  Fixture generation needs explicit runner/file permission from the lead.
- Not verified: every behavior above is static source citation at
  `fca64287cf51a85552a41b022013abbfdb335452`; no Go test was executed, no
  SQLite file was opened, no Zig code was built in this card. `git diff --check`
  run at PR time; report records the output.
- Non-goals held: no change to the no-C constraint, no external `sqlite3`
  executable or Go helper process substitution, no data-destroying migration,
  no invented `std.sqlite`.
