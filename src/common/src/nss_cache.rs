/*
   Unix Azure Entra ID implementation
   Copyright (C) David Mulder <dmulder@samba.org> 2024

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
use crate::idprovider::interface::Id;
use rusqlite::{params, Connection, OpenFlags, Result};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::unix_proto::NssUser;

#[derive(PartialEq)]
pub enum Mode {
    ReadOnly,
    ReadWrite,
}

pub struct NssCache {
    conn: Option<Connection>,
    writable: bool,
}

impl NssCache {
    pub fn new(db_path: &str, mode: &Mode) -> Result<Self> {
        let is_root = unsafe { libc::getuid() } == 0;
        let path = Path::new(db_path);
        let mut writable = false;

        if !path.exists() && is_root {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|_| rusqlite::Error::InvalidPath(parent.into()))?;
                fs::set_permissions(parent, fs::Permissions::from_mode(0o755))
                    .map_err(|_| rusqlite::Error::InvalidPath(parent.into()))?;
            }
        }

        let mut conn = if path.exists() {
            if is_root && *mode == Mode::ReadWrite {
                writable = true;
                Some(Connection::open(db_path)?)
            } else {
                Some(Connection::open_with_flags(
                    db_path,
                    OpenFlags::SQLITE_OPEN_READ_ONLY,
                )?)
            }
        } else if is_root && *mode == Mode::ReadWrite {
            writable = true;
            let conn = Connection::open(db_path)?;
            fs::set_permissions(db_path, fs::Permissions::from_mode(0o644))
                .map_err(|_| rusqlite::Error::InvalidPath(db_path.into()))?;
            Some(conn)
        } else {
            None
        };

        if writable {
            if let Some(conn) = conn.as_mut() {
                Self::initialize_schema(conn)?;
            }
        }

        Ok(NssCache { conn, writable })
    }

    fn initialize_schema(conn: &mut Connection) -> Result<()> {
        if conn
            .prepare("SELECT display_name FROM nss_passwd LIMIT 0")
            .is_ok()
        {
            return Ok(());
        }
        let tx = conn.transaction()?;
        tx.execute(
            "CREATE TABLE IF NOT EXISTS nss_passwd (
                name TEXT PRIMARY KEY,
                uid INTEGER NOT NULL,
                gid INTEGER NOT NULL,
                gecos TEXT NOT NULL,
                homedir TEXT NOT NULL,
                shell TEXT NOT NULL,
                last_updated INTEGER NOT NULL,
                display_name TEXT
             )",
            [],
        )?;
        let has_display_name = {
            let mut stmt = tx.prepare("PRAGMA table_info(nss_passwd)")?;
            let columns = stmt.query_map([], |row| row.get::<_, String>(1))?;
            columns
                .collect::<Result<Vec<_>>>()?
                .iter()
                .any(|name| name == "display_name")
        };
        if !has_display_name {
            tx.execute("ALTER TABLE nss_passwd ADD COLUMN display_name TEXT", [])?;
        }
        tx.commit()
    }

    pub fn insert_user(&self, user: &NssUser) -> Result<()> {
        if let Some(conn) = &self.conn {
            if self.writable {
                let cache_key = user
                    .canonical_name
                    .as_ref()
                    .map(|name| name.to_lowercase())
                    .unwrap_or_else(|| user.name.clone());
                let display_name = user.canonical_name.as_ref().map(|_| user.name.as_str());
                let tx = conn.unchecked_transaction()?;

                if !user.cacheable {
                    // A lookup-only result must also invalidate older fallback rows.
                    tx.execute(
                        "DELETE FROM nss_passwd WHERE name = ?1 OR uid = ?2",
                        params![cache_key, user.uid],
                    )?;
                    return tx.commit();
                }

                tx.execute(
                    "DELETE FROM nss_passwd WHERE uid = ?1 AND name != ?2",
                    params![user.uid, cache_key],
                )?;
                tx.execute(
                    "INSERT OR REPLACE INTO nss_passwd
                     (name, uid, gid, gecos, homedir, shell, last_updated, display_name)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![
                        cache_key,
                        user.uid,
                        user.gid,
                        user.gecos,
                        user.homedir,
                        user.shell,
                        now_secs(),
                        display_name
                    ],
                )?;
                tx.commit()?;
            }
        }
        Ok(())
    }

    fn query_users(&self, filter: &str, params: &[&dyn rusqlite::ToSql]) -> Vec<(NssUser, i64)> {
        let Some(conn) = self.conn.as_ref() else {
            return Vec::new();
        };
        let columns = "name, uid, gid, gecos, homedir, shell, last_updated";
        let query = format!("SELECT {columns}, display_name FROM nss_passwd {filter}");
        let legacy_query = format!("SELECT {columns}, NULL FROM nss_passwd {filter}");
        let Ok(mut stmt) = conn
            .prepare(&query)
            .or_else(|_| conn.prepare(&legacy_query))
        else {
            return Vec::new();
        };
        let Ok(rows) = stmt.query_map(params, |row| {
            let cache_key: String = row.get(0)?;
            let display_name: Option<String> = row.get(7)?;
            let user = NssUser {
                canonical_name: display_name.as_ref().map(|_| cache_key.clone()),
                name: display_name.unwrap_or(cache_key),
                uid: row.get(1)?,
                gid: row.get(2)?,
                gecos: row.get(3)?,
                homedir: row.get(4)?,
                shell: row.get(5)?,
                cacheable: true,
            };
            Ok((user, row.get(6)?))
        }) else {
            return Vec::new();
        };
        let users: Vec<(NssUser, i64)> = rows.flatten().collect();
        users
    }

    /// Look a user up while the daemon is unavailable. A name which contains
    /// an `@` is only ever resolved by its canonical UPN, because only the
    /// daemon can verify that it is not another user's real UPN. A name
    /// without one may also be the configured display name of a single user.
    pub fn get_user(&self, id: &Id) -> Option<NssUser> {
        let (filter, key): (&str, &dyn rusqlite::ToSql) = match id {
            Id::Name(name) => ("WHERE name = ?1 COLLATE NOCASE", name),
            Id::Gid(uid) => ("WHERE uid = ?1", uid),
        };
        let now = now_secs();
        let mut owners = self.query_users(filter, &[key]);
        if owners.is_empty() {
            let Id::Name(name) = id else {
                return None;
            };
            if name.contains('@') {
                return None;
            }
            owners = self.query_users("WHERE display_name = ?1 COLLATE NOCASE", &[name]);
            owners.retain(|(_, updated)| now - updated <= MAX_AGE_SECS);
        }
        match owners.as_slice() {
            [(user, updated)] if now - updated <= MAX_AGE_SECS => Some(user.clone()),
            _ => None,
        }
    }

    pub fn get_users(&self) -> Vec<NssUser> {
        let now = now_secs();
        self.query_users("", &[])
            .into_iter()
            .filter(|(_, updated)| now - updated <= MAX_AGE_SECS)
            .map(|(user, _)| user)
            .collect()
    }
}

const MAX_AGE_SECS: i64 = 48 * 3600;

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cache() -> NssCache {
        let mut conn = Connection::open_in_memory().unwrap();
        NssCache::initialize_schema(&mut conn).unwrap();
        NssCache {
            conn: Some(conn),
            writable: true,
        }
    }

    fn user(canonical_name: &str, name: &str, uid: u32) -> NssUser {
        NssUser {
            name: name.to_string(),
            canonical_name: Some(canonical_name.to_string()),
            uid,
            gid: uid,
            gecos: "Test User".to_string(),
            homedir: "/home/test".to_string(),
            shell: "/bin/bash".to_string(),
            cacheable: true,
        }
    }

    fn name(name: &str) -> Id {
        Id::Name(name.to_string())
    }

    fn create_legacy_schema(conn: &Connection) {
        conn.execute_batch(
            "CREATE TABLE nss_passwd (
                name TEXT PRIMARY KEY, uid INTEGER NOT NULL, gid INTEGER NOT NULL,
                gecos TEXT NOT NULL, homedir TEXT NOT NULL, shell TEXT NOT NULL,
                last_updated INTEGER NOT NULL
             );
             INSERT INTO nss_passwd VALUES
                ('alice', 1000, 1000, 'Test User', '/home/test', '/bin/bash', strftime('%s', 'now'));",
        )
        .unwrap();
    }

    #[test]
    fn display_name_resolves_only_unqualified_and_only_unambiguously() {
        let cache = cache();
        cache
            .insert_user(&user("alice.long@contoso.com", "alice", 1000))
            .unwrap();
        let found = cache.get_user(&name("alice")).unwrap();
        assert_eq!(found.uid, 1000);
        assert_eq!(
            found.canonical_name.as_deref(),
            Some("alice.long@contoso.com")
        );
        assert!(cache.get_user(&name("ALICE.long@contoso.com")).is_some());
        assert!(cache.get_user(&name("alice@contoso.com")).is_none());

        cache
            .insert_user(&user("alice.long@fabrikam.com", "alice", 1001))
            .unwrap();
        assert!(cache.get_user(&name("alice")).is_none());
        assert_eq!(cache.get_users().len(), 2);
    }

    #[test]
    fn canonical_identity_wins_over_a_display_name_even_when_expired() {
        let cache = cache();
        cache
            .insert_user(&user("bob@contoso.com", "bob@contoso.com", 1000))
            .unwrap();
        cache
            .insert_user(&user("alice@contoso.com", "bob", 1001))
            .unwrap();
        assert_eq!(cache.get_user(&name("bob")).unwrap().uid, 1001);

        cache
            .insert_user(&user("bob", "bob@contoso.com", 1002))
            .unwrap();
        cache
            .conn
            .as_ref()
            .unwrap()
            .execute(
                "UPDATE nss_passwd SET last_updated = 0 WHERE name = 'bob'",
                [],
            )
            .unwrap();
        assert!(cache.get_user(&name("bob")).is_none());
        assert!(cache.get_user(&Id::Gid(1002)).is_none());
        assert_eq!(cache.get_users().len(), 2);
    }

    #[test]
    fn refresh_replaces_the_previous_owner_of_a_uid() {
        let cache = cache();
        cache
            .insert_user(&user("old.upn@contoso.com", "alice", 1000))
            .unwrap();
        cache
            .insert_user(&user("new.upn@contoso.com", "alice", 1000))
            .unwrap();
        assert!(cache.get_user(&name("old.upn@contoso.com")).is_none());
        assert_eq!(
            cache
                .get_user(&name("alice"))
                .unwrap()
                .canonical_name
                .as_deref(),
            Some("new.upn@contoso.com")
        );
        assert_eq!(cache.get_users().len(), 1);
    }

    #[test]
    fn current_schema_does_not_require_a_write_lock() {
        let mut conn = Connection::open_in_memory().unwrap();
        NssCache::initialize_schema(&mut conn).unwrap();
        conn.pragma_update(None, "query_only", true).unwrap();
        NssCache::initialize_schema(&mut conn).unwrap();
    }

    #[test]
    fn legacy_read_only_cache_needs_no_migration() {
        let path = std::env::temp_dir().join(format!("himmelblau-nss-{}.db", uuid::Uuid::new_v4()));
        let conn = Connection::open(&path).unwrap();
        create_legacy_schema(&conn);
        drop(conn);
        let cache = NssCache::new(path.to_str().unwrap(), &Mode::ReadOnly).unwrap();
        let found = cache.get_user(&name("alice")).unwrap();
        assert_eq!(found.name, "alice");
        assert!(found.canonical_name.is_none());
        assert_eq!(cache.get_user(&Id::Gid(1000)).unwrap().uid, 1000);
        assert_eq!(cache.get_users().len(), 1);
        assert!(cache.get_user(&name("missing")).is_none());
        drop(cache);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn migration_preserves_legacy_rows_and_refresh_deduplicates_them() {
        let mut conn = Connection::open_in_memory().unwrap();
        create_legacy_schema(&conn);
        NssCache::initialize_schema(&mut conn).unwrap();
        NssCache::initialize_schema(&mut conn).unwrap();
        let cache = NssCache {
            conn: Some(conn),
            writable: true,
        };
        assert_eq!(cache.get_user(&name("alice")).unwrap().uid, 1000);
        cache
            .insert_user(&user("alice.long@contoso.com", "alice@contoso.com", 1000))
            .unwrap();
        assert_eq!(cache.get_users().len(), 1);
        assert!(cache.get_user(&name("alice")).is_none());
        assert_eq!(
            cache.get_user(&name("alice.long@contoso.com")).unwrap().uid,
            1000
        );
    }

    fn lookup_only_user() -> NssUser {
        NssUser {
            cacheable: false,
            ..user("user@example.com", "user@example.com", 2000)
        }
    }

    #[test]
    fn lookup_only_user_does_not_enter_fallback_cache() {
        let cache = cache();
        let mut user = lookup_only_user();
        let id = Id::Name(user.name.clone());

        cache.insert_user(&user).unwrap();
        assert!(cache.get_user(&id).is_none());
        user.cacheable = true;
        cache.insert_user(&user).unwrap();
        assert!(cache.get_user(&id).is_some());
    }

    #[test]
    fn lookup_only_user_evicts_matching_fallback_rows() {
        for (name, uid) in [
            ("user@example.com", 2000),
            ("user@example.com", 3000),
            ("renamed@example.com", 2000),
        ] {
            let cache = cache();
            let mut user = lookup_only_user();
            user.cacheable = true;
            let cached_name = Id::Name(user.name.clone());
            let cached_uid = Id::Gid(user.uid);
            cache.insert_user(&user).unwrap();
            assert!(cache.get_user(&cached_name).is_some());
            assert!(cache.get_user(&cached_uid).is_some());

            let mut unrelated = lookup_only_user();
            unrelated.name = "unrelated@example.com".to_string();
            unrelated.canonical_name = Some(unrelated.name.clone());
            unrelated.uid = 4000;
            unrelated.gid = 4000;
            unrelated.cacheable = true;
            cache.insert_user(&unrelated).unwrap();

            user.name = name.to_string();
            user.canonical_name = Some(name.to_string());
            user.uid = uid;
            user.cacheable = false;
            cache.insert_user(&user).unwrap();

            assert!(cache.get_user(&cached_name).is_none());
            assert!(cache.get_user(&cached_uid).is_none());
            assert!(cache.get_user(&Id::Name(user.name.clone())).is_none());
            assert!(cache.get_user(&Id::Gid(user.uid)).is_none());
            assert!(cache.get_user(&Id::Name(unrelated.name.clone())).is_some());
            assert!(cache.get_user(&Id::Gid(unrelated.uid)).is_some());
            let users = cache.get_users();
            assert_eq!(users.len(), 1);
            assert_eq!(users[0].uid, unrelated.uid);
        }
    }
}
