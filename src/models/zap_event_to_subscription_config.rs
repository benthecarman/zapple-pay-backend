use diesel::prelude::*;
use serde::{Deserialize, Serialize};

use super::schema::zap_events_to_subscription_configs;

#[derive(Queryable, Insertable, AsChangeset, Serialize, Deserialize, Debug, Clone, PartialEq)]
#[diesel(check_for_backend(diesel::pg::Pg))]
#[diesel(table_name = zap_events_to_subscription_configs)]
pub struct ZapEventToSubscriptionConfig {
    pub zap_event_id: i32,
    pub subscription_config_id: i32,
}

impl ZapEventToSubscriptionConfig {
    pub fn new(
        conn: &mut PgConnection,
        zap_event_id: i32,
        subscription_config_id: i32,
    ) -> anyhow::Result<Self> {
        let new = Self {
            zap_event_id,
            subscription_config_id,
        };
        let zap_event = diesel::insert_into(zap_events_to_subscription_configs::table)
            .values(&new)
            .get_result(conn)?;
        Ok(zap_event)
    }

    pub fn find_by_zap_event_id(
        conn: &mut PgConnection,
        event_id: i32,
    ) -> anyhow::Result<Option<Self>> {
        let zap_event = zap_events_to_subscription_configs::table
            .filter(zap_events_to_subscription_configs::zap_event_id.eq(event_id))
            .first::<Self>(conn)
            .optional()?;
        Ok(zap_event)
    }

    pub fn delete_by_zap_event_id(
        conn: &mut PgConnection,
        event_id: i32,
    ) -> anyhow::Result<Option<Self>> {
        let zap_event = diesel::delete(
            zap_events_to_subscription_configs::table
                .filter(zap_events_to_subscription_configs::zap_event_id.eq(event_id)),
        )
        .get_result(conn)
        .optional()?;
        Ok(zap_event)
    }
}
