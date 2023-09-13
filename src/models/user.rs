use bitcoin::hashes::hex::ToHex;
use bitcoin::XOnlyPublicKey;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

use super::schema::users;

#[derive(
    Queryable,
    Insertable,
    Identifiable,
    AsChangeset,
    Serialize,
    Deserialize,
    Debug,
    Clone,
    PartialEq,
)]
#[diesel(primary_key(id))]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct User {
    pub id: i32,
    npub: String,
    created_at: chrono::NaiveDateTime,
}

#[derive(Insertable, AsChangeset)]
#[diesel(table_name = users)]
pub struct NewUser<'a> {
    pub npub: &'a str,
}

impl User {
    pub fn pubkey(&self) -> XOnlyPublicKey {
        XOnlyPublicKey::from_str(&self.npub).expect("invalid pubkey")
    }

    pub fn get_user_count(conn: &mut PgConnection) -> anyhow::Result<i64> {
        let count = users::table.count().get_result(conn)?;
        Ok(count)
    }

    pub fn get_all_npubs(conn: &mut PgConnection) -> anyhow::Result<Vec<XOnlyPublicKey>> {
        let npubs = users::table
            .select(users::npub)
            .load::<String>(conn)?
            .into_iter()
            .map(|npub| XOnlyPublicKey::from_str(&npub).expect("invalid pubkey"))
            .collect::<Vec<_>>();

        Ok(npubs)
    }

    pub fn get_by_pubkey(conn: &mut PgConnection, pubkey: &XOnlyPublicKey) -> Option<Self> {
        users::table
            .filter(users::npub.eq(pubkey.to_hex()))
            .first::<Self>(conn)
            .ok()
    }
}
