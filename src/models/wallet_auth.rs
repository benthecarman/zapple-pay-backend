use bitcoin::hashes::hex::ToHex;
use bitcoin::util::bip32::{ChildNumber, ExtendedPrivKey};
use bitcoin::XOnlyPublicKey;
use diesel::prelude::*;
use nostr::SECP256K1;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

use super::schema::wallet_auth;

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
#[diesel(primary_key(index))]
#[diesel(check_for_backend(diesel::pg::Pg))]
#[diesel(table_name = wallet_auth)]
pub struct WalletAuth {
    pub index: i32,
    pubkey: String,
    user_pubkey: Option<String>,
    created_at: chrono::NaiveDateTime,
}

#[derive(Insertable, Serialize, Deserialize, Debug, Clone, PartialEq)]
#[diesel(table_name = wallet_auth)]
struct NewWalletAuth {
    pubkey: String,
}

#[derive(QueryableByName)]
struct NextId {
    #[diesel(sql_type = diesel::sql_types::Int4)]
    new_id: i32,
}

impl WalletAuth {
    pub fn pubkey(&self) -> XOnlyPublicKey {
        XOnlyPublicKey::from_str(&self.pubkey).expect("invalid pubkey")
    }

    pub fn user_pubkey(&self) -> Option<XOnlyPublicKey> {
        self.user_pubkey
            .as_deref()
            .map(|s| XOnlyPublicKey::from_str(s).expect("invalid user_pubkey"))
    }

    pub fn create(conn: &mut PgConnection, xpriv: ExtendedPrivKey) -> anyhow::Result<Self> {
        conn.transaction(|conn| {
            // Get the next value from the sequence
            let query =
                "SELECT nextval(pg_get_serial_sequence('wallet_auth', 'index'))::int4 as new_id";
            let next_index: Vec<NextId> = diesel::sql_query(query).load(conn)?;
            let next_index = next_index[0].new_id;

            // Derive the pubkey for the next index
            let (derived_pubkey, _) = xpriv
                .derive_priv(
                    SECP256K1,
                    &[ChildNumber::from_hardened_idx(next_index as u32).unwrap()],
                )
                .unwrap()
                .private_key
                .x_only_public_key(SECP256K1);

            // Now, you can insert the row with the reserved `index`, and the derived values
            let result = diesel::insert_into(wallet_auth::table)
                .values((
                    wallet_auth::index.eq(next_index),
                    wallet_auth::pubkey.eq(derived_pubkey.to_hex()),
                ))
                .get_result(conn)?;

            Ok(result)
        })
    }

    pub fn add_pubkey(
        conn: &mut PgConnection,
        pubkey: XOnlyPublicKey,
        user_pubkey: XOnlyPublicKey,
    ) -> anyhow::Result<()> {
        diesel::update(wallet_auth::table)
            .filter(wallet_auth::pubkey.eq(pubkey.to_hex()))
            .set(wallet_auth::user_pubkey.eq(user_pubkey.to_hex()))
            .execute(conn)?;

        Ok(())
    }

    /// Returns the index of the wallet_auth entry for the given pubkey
    /// Also verifies that user_pubkey is set so that we don't link to a wallet_auth entry that
    /// hasn't been claimed yet
    pub fn get_index_by_pubkey(
        conn: &mut PgConnection,
        pubkey: XOnlyPublicKey,
    ) -> Result<Option<i32>, diesel::result::Error> {
        let id = wallet_auth::table
            .select(wallet_auth::index)
            .filter(wallet_auth::pubkey.eq(pubkey.to_hex()))
            .filter(wallet_auth::user_pubkey.is_not_null())
            .first(conn)
            .optional()?;

        Ok(id)
    }

    pub fn get_by_pubkey(
        conn: &mut PgConnection,
        pubkey: XOnlyPublicKey,
    ) -> Result<Option<WalletAuth>, diesel::result::Error> {
        let id = wallet_auth::table
            .select(wallet_auth::all_columns)
            .filter(wallet_auth::pubkey.eq(pubkey.to_hex()))
            .first(conn)
            .optional()?;

        Ok(id)
    }

    pub fn get_user_pubkey(
        conn: &mut PgConnection,
        index: i32,
    ) -> anyhow::Result<Option<XOnlyPublicKey>> {
        let user_pubkey = wallet_auth::table
            .select(wallet_auth::user_pubkey)
            .filter(wallet_auth::index.eq(index))
            .first::<Option<String>>(conn)?;

        Ok(user_pubkey
            .map(|pubkey| XOnlyPublicKey::from_str(&pubkey).expect("invalid user_pubkey")))
    }

    pub fn get_unlinked(conn: &mut PgConnection) -> anyhow::Result<Vec<XOnlyPublicKey>> {
        let unlinked = wallet_auth::table
            .select(wallet_auth::pubkey)
            .filter(wallet_auth::user_pubkey.is_null())
            .filter(
                wallet_auth::created_at
                    .lt(chrono::Utc::now().naive_utc() - chrono::Duration::days(1)),
            )
            .load::<String>(conn)?;

        let unlinked = unlinked
            .into_iter()
            .filter_map(|s| XOnlyPublicKey::from_str(&s).ok())
            .collect();

        Ok(unlinked)
    }

    pub fn get_pubkeys(conn: &mut PgConnection) -> anyhow::Result<Vec<XOnlyPublicKey>> {
        let pubkeys = wallet_auth::table
            .select(wallet_auth::pubkey)
            .filter(wallet_auth::user_pubkey.is_not_null())
            .load::<String>(conn)?;

        let pubkeys = pubkeys
            .into_iter()
            .filter_map(|s| XOnlyPublicKey::from_str(&s).ok())
            .collect();

        Ok(pubkeys)
    }
}
