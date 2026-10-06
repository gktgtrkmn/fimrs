use core::{FileMeta, Snapshot};
use rusqlite::{Connection, params};
use std::collections::BTreeMap;
use std::path::Path;

const SCHEMA_VERSION: i64 = 1;

pub struct Db {
    conn: Connection,
}

impl Db {
    pub fn open<P: AsRef<Path>>(path: P) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;

        // WAL gives us a single-writer/concurrent-reader journal; NORMAL
        // sync is durable enough for a local tool and much faster than FULL.
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;",
        )?;

        let mut db = Db { conn };
        db.migrate()?;
        Ok(db)
    }

    /// Create the schema if absent and stamp the schema version.
    fn migrate(&mut self) -> rusqlite::Result<()> {
        let version: i64 = self
            .conn
            .pragma_query_value(None, "user_version", |row| row.get(0))?;

        if version < 1 {
            self.conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS files (
                     path     TEXT PRIMARY KEY,
                     size     INTEGER NOT NULL,
                     modified INTEGER NOT NULL,
                     hash     TEXT
                 );",
            )?;
        }

        // Future migrations: `if version < 2 { ... }`, etc.

        self.conn
            .pragma_update(None, "user_version", SCHEMA_VERSION)?;
        Ok(())
    }

    /// Replace the stored snapshot with `snapshot`, atomically.
    pub fn save(&mut self, snapshot: &Snapshot) -> rusqlite::Result<()> {
        let tx = self.conn.transaction()?;
        tx.execute("DELETE FROM files", [])?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO files (path, size, modified, hash)
                 VALUES (?1, ?2, ?3, ?4)",
            )?;
            for (path, meta) in snapshot {
                stmt.execute(params![path, meta.size as i64, meta.modified, meta.hash])?;
            }
        }
        tx.commit()
    }

    /// Load the stored snapshot into an in-memory [`Snapshot`].
    pub fn load_latest(&self) -> rusqlite::Result<Snapshot> {
        let mut stmt = self
            .conn
            .prepare("SELECT path, size, modified, hash FROM files")?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                FileMeta {
                    size: row.get::<_, i64>(1)? as u64,
                    modified: row.get(2)?,
                    hash: row.get(3)?,
                },
            ))
        })?;

        let mut snapshot: Snapshot = BTreeMap::new();
        for row in rows {
            let (path, meta) = row?;
            snapshot.insert(path, meta);
        }
        Ok(snapshot)
    }
}
