use rusqlite::Connection;
use std::path::Path;

pub fn open<P: AsRef<Path>>(path: P) -> rusqlite::Result<Connection> {
    Connection::open(path)
}
