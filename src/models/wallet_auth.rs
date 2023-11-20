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
    relay: Option<String>,
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

    pub fn add_user_data(
        conn: &mut PgConnection,
        pubkey: XOnlyPublicKey,
        user_pubkey: XOnlyPublicKey,
        relay: Option<String>,
    ) -> anyhow::Result<()> {
        diesel::update(wallet_auth::table)
            .filter(wallet_auth::pubkey.eq(pubkey.to_hex()))
            .set((
                wallet_auth::user_pubkey.eq(user_pubkey.to_hex()),
                wallet_auth::relay.eq(relay),
            ))
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

    pub fn get_user_data(
        conn: &mut PgConnection,
        index: i32,
    ) -> anyhow::Result<Option<(XOnlyPublicKey, Option<String>)>> {
        let (user_pubkey, relay) = wallet_auth::table
            .select((wallet_auth::user_pubkey, wallet_auth::relay))
            .filter(wallet_auth::index.eq(index))
            .first::<(Option<String>, Option<String>)>(conn)?;

        Ok(user_pubkey.map(|pubkey| {
            (
                XOnlyPublicKey::from_str(&pubkey).expect("invalid user_pubkey"),
                relay,
            )
        }))
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

#[cfg(test)]
mod test {
    use crate::models::wallet_auth::WalletAuth;
    use crate::models::MIGRATIONS;
    use bitcoin::util::bip32::ExtendedPrivKey;
    use diesel::r2d2::{ConnectionManager, Pool};
    use diesel::{Connection, PgConnection, RunQueryDsl};
    use diesel_migrations::MigrationHarness;
    use nostr::key::XOnlyPublicKey;
    use std::str::FromStr;

    const PUBKEY: &str = "e1ff3bfdd4e40315959b08b4fcc8245eaa514637e1d4ec2ae166b743341be1af";

    fn init_db() -> Pool<ConnectionManager<PgConnection>> {
        dotenv::dotenv().ok();
        let url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
        let manager = ConnectionManager::<PgConnection>::new(url);
        let db_pool = Pool::builder()
            .max_size(16)
            .test_on_check_out(true)
            .build(manager)
            .expect("Could not build connection pool");

        // run migrations
        let mut connection = db_pool.get().unwrap();
        connection
            .run_pending_migrations(MIGRATIONS)
            .expect("migrations could not run");

        db_pool
    }

    fn clear_database(conn: &mut PgConnection) {
        conn.transaction::<_, anyhow::Error, _>(|conn| {
            diesel::delete(crate::models::schema::zap_events::table).execute(conn)?;
            diesel::delete(crate::models::schema::donations::table).execute(conn)?;
            diesel::delete(crate::models::schema::subscription_configs::table).execute(conn)?;
            diesel::delete(crate::models::schema::zap_configs::table).execute(conn)?;
            diesel::delete(crate::models::schema::users::table).execute(conn)?;
            Ok(())
        })
        .unwrap();
    }

    #[tokio::test]
    async fn test_get_user_data() {
        let db_pool = init_db();
        let conn = &mut db_pool.get().unwrap();
        clear_database(conn);

        let xpriv = ExtendedPrivKey::new_master(bitcoin::Network::Bitcoin, &[]).unwrap();
        let wallet_auth = WalletAuth::create(conn, xpriv).unwrap();

        let pubkey = wallet_auth.pubkey();

        let user_data = WalletAuth::get_user_data(conn, wallet_auth.index).unwrap();
        assert_eq!(user_data, None);

        let user_pubkey = XOnlyPublicKey::from_str(PUBKEY).unwrap();
        WalletAuth::add_user_data(conn, pubkey, user_pubkey, None).unwrap();

        let user_data = WalletAuth::get_user_data(conn, wallet_auth.index)
            .unwrap()
            .unwrap();
        assert_eq!(user_data.0, user_pubkey);
        assert_eq!(user_data.1, None);

        clear_database(conn);
    }

    #[tokio::test]
    async fn test_get_user_data_with_relay() {
        let db_pool = init_db();
        let conn = &mut db_pool.get().unwrap();
        clear_database(conn);

        let xpriv = ExtendedPrivKey::new_master(bitcoin::Network::Bitcoin, &[]).unwrap();
        let wallet_auth = WalletAuth::create(conn, xpriv).unwrap();

        let pubkey = wallet_auth.pubkey();

        let user_data = WalletAuth::get_user_data(conn, wallet_auth.index).unwrap();
        assert_eq!(user_data, None);

        let user_pubkey = XOnlyPublicKey::from_str(PUBKEY).unwrap();
        let relay = Some("wss://nostr.mutinywallet.com/".to_string());
        WalletAuth::add_user_data(conn, pubkey, user_pubkey, relay.clone()).unwrap();

        let user_data = WalletAuth::get_user_data(conn, wallet_auth.index)
            .unwrap()
            .unwrap();
        assert_eq!(user_data.0, user_pubkey);
        assert_eq!(user_data.1, relay);
        clear_database(conn);
    }
}
