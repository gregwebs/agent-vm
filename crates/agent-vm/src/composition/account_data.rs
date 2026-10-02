//! The shared *declaration* model for `users`/`groups` (issue #228, roadmap
//! CP1), consumed later by CP4's accounts kernel and CP8's parser.
//!
//! This is not a validated union and not CP4's canonical rendered union: it
//! carries no account name/path/id policy, no auto-group creation, no
//! collision decision and no passwd/shadow rendering. CP8 validates authoring
//! shape; CP4 decides collisions and renders the union. What CP1 owns is the
//! stable serialization of a *declared* set so both checkpoints can depend on
//! one representation instead of each other, and so retained data round-trips
//! deterministically.
//!
//! [`AccountSet::to_canonical_bytes`] is for declaration/retained-data
//! stability only. CP4's rendered union bytes are what
//! [`super::identity::AccountLayerIdentity::of_canonical_bytes`] hashes; do
//! not substitute one for the other.

/// One layer's declared users and groups.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AccountSet {
    pub(crate) users: Vec<DeclaredUser>,
    pub(crate) groups: Vec<DeclaredGroup>,
}

/// A declared user. `gid` is numeric or a declared group name; `groups` are
/// supplementary group names.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeclaredUser {
    pub(crate) name: String,
    pub(crate) uid: u32,
    pub(crate) gid: GidRef,
    pub(crate) home: String,
    pub(crate) shell: String,
    pub(crate) groups: Vec<String>,
}

/// A declared group.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeclaredGroup {
    pub(crate) name: String,
    pub(crate) gid: u32,
}

/// A user's primary group: a numeric gid or a name to resolve. Kept as a
/// two-armed enum so the number-vs-name distinction survives serialization.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub(crate) enum GidRef {
    Id(u32),
    Name(String),
}

impl AccountSet {
    /// A deterministic byte encoding of this declared set: each user's
    /// supplementary groups sorted, then users and groups sorted by name
    /// bytes with equal names broken by the full record's bytes, then the
    /// whole set serialized as compact JSON.
    ///
    /// Struct fields keep declaration order under `serde_json` (no map
    /// iteration), and values are JSON-escaped, so the result has no
    /// delimiter ambiguity. Duplicates are preserved — canonical
    /// serialization is not collision validation; CP4 and CP8 own that.
    pub(crate) fn to_canonical_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let mut canonical = self.clone();
        for user in &mut canonical.users {
            user.groups.sort();
        }

        // Each record's sort key is precomputed before sorting so the
        // comparator never runs a fallible serializer and never unwraps.
        let mut users = canonical
            .users
            .into_iter()
            .map(|user| {
                let bytes = serde_json::to_vec(&user)?;
                Ok((user.name.clone(), bytes, user))
            })
            .collect::<anyhow::Result<Vec<(String, Vec<u8>, DeclaredUser)>>>()?;
        users.sort_by(|a, b| {
            a.0.as_bytes()
                .cmp(b.0.as_bytes())
                .then_with(|| a.1.cmp(&b.1))
        });
        canonical.users = users.into_iter().map(|(_, _, user)| user).collect();

        let mut groups = canonical
            .groups
            .into_iter()
            .map(|group| {
                let bytes = serde_json::to_vec(&group)?;
                Ok((group.name.clone(), bytes, group))
            })
            .collect::<anyhow::Result<Vec<(String, Vec<u8>, DeclaredGroup)>>>()?;
        groups.sort_by(|a, b| {
            a.0.as_bytes()
                .cmp(b.0.as_bytes())
                .then_with(|| a.1.cmp(&b.1))
        });
        canonical.groups = groups.into_iter().map(|(_, _, group)| group).collect();

        Ok(serde_json::to_vec(&canonical)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(name: &str, uid: u32, gid: GidRef, groups: &[&str]) -> DeclaredUser {
        DeclaredUser {
            name: name.to_string(),
            uid,
            gid,
            home: format!("/home/{name}"),
            shell: "/bin/sh".to_string(),
            groups: groups.iter().map(|group| group.to_string()).collect(),
        }
    }

    fn group(name: &str, gid: u32) -> DeclaredGroup {
        DeclaredGroup {
            name: name.to_string(),
            gid,
        }
    }

    #[test]
    fn account_declaration_serialization_is_canonical() {
        // Same model, three kinds of permutation: users reordered, groups
        // reordered, and each user's supplementary groups reordered.
        let a = AccountSet {
            users: vec![
                user(
                    "bob",
                    2001,
                    GidRef::Name("staff".to_string()),
                    &["users", "sudo"],
                ),
                user("alice", 1000, GidRef::Id(1000), &["sudo", "users"]),
                user("bob", 2002, GidRef::Id(2002), &[]),
            ],
            groups: vec![
                group("staff", 2000),
                group("users", 1000),
                group("sudo", 27),
            ],
        };
        let b = AccountSet {
            users: vec![
                user("alice", 1000, GidRef::Id(1000), &["users", "sudo"]),
                user("bob", 2002, GidRef::Id(2002), &[]),
                user(
                    "bob",
                    2001,
                    GidRef::Name("staff".to_string()),
                    &["sudo", "users"],
                ),
            ],
            groups: vec![
                group("sudo", 27),
                group("users", 1000),
                group("staff", 2000),
            ],
        };

        let bytes = a.to_canonical_bytes().unwrap();
        assert_eq!(bytes, b.to_canonical_bytes().unwrap());

        let canonical: AccountSet = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            canonical
                .users
                .iter()
                .map(|user| user.name.as_str())
                .collect::<Vec<_>>(),
            // Duplicates are preserved, not unioned, and the two `bob`s are
            // ordered by their full record bytes (uid 2001 before 2002).
            vec!["alice", "bob", "bob"]
        );
        assert_eq!(
            canonical
                .users
                .iter()
                .filter(|user| user.name == "bob")
                .map(|user| user.uid)
                .collect::<Vec<_>>(),
            vec![2001, 2002]
        );
        assert_eq!(
            canonical
                .groups
                .iter()
                .map(|group| group.name.as_str())
                .collect::<Vec<_>>(),
            vec!["staff", "sudo", "users"]
        );
    }

    #[test]
    fn account_declaration_serialization_preserves_fields() {
        let set = AccountSet {
            users: vec![
                DeclaredUser {
                    name: "bob".to_string(),
                    uid: 1001,
                    gid: GidRef::Name("staff".to_string()),
                    home: "/home/bob\"x\\y".to_string(),
                    shell: "/bin/bash".to_string(),
                    groups: vec![],
                },
                DeclaredUser {
                    name: "alice".to_string(),
                    uid: 1000,
                    gid: GidRef::Id(1000),
                    home: "/home/alice".to_string(),
                    shell: "/bin/sh".to_string(),
                    groups: vec!["users".to_string(), "sudo".to_string()],
                },
            ],
            groups: vec![group("users", 1000), group("staff", 2000)],
        };

        let bytes = set.to_canonical_bytes().unwrap();
        // Every field, both `GidRef` arms, JSON escaping, and empty arrays.
        let want = r#"{"users":[{"name":"alice","uid":1000,"gid":1000,"home":"/home/alice","shell":"/bin/sh","groups":["sudo","users"]},{"name":"bob","uid":1001,"gid":"staff","home":"/home/bob\"x\\y","shell":"/bin/bash","groups":[]}],"groups":[{"name":"staff","gid":2000},{"name":"users","gid":1000}]}"#;
        assert_eq!(String::from_utf8(bytes.clone()).unwrap(), want);

        let roundtrip: AccountSet = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            roundtrip.groups,
            vec![group("staff", 2000), group("users", 1000)]
        );
        assert_eq!(roundtrip.users[0].gid, GidRef::Id(1000));
        assert_eq!(
            roundtrip.users[0].groups,
            vec!["sudo".to_string(), "users".to_string()]
        );
        assert_eq!(roundtrip.users[1].gid, GidRef::Name("staff".to_string()));
        assert_eq!(roundtrip.users[1].home, "/home/bob\"x\\y");
        assert_eq!(roundtrip.users[1].shell, "/bin/bash");
        assert!(roundtrip.users[1].groups.is_empty());
    }
}
