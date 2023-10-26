// @generated automatically by Diesel CLI.

diesel::table! {
    donations (id) {
        id -> Int4,
        config_id -> Int4,
        lnurl -> Nullable<Text>,
        amount -> Int4,
        npub -> Nullable<Text>,
    }
}

diesel::table! {
    subscription_configs (id) {
        id -> Int4,
        user_id -> Int4,
        to_npub -> Text,
        amount -> Int4,
        time_period -> Text,
        nwc -> Text,
        created_at -> Timestamptz,
        last_paid -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    users (id) {
        id -> Int4,
        npub -> Text,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    zap_configs (id) {
        id -> Int4,
        user_id -> Int4,
        emoji -> Text,
        amount -> Int4,
        nwc -> Text,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    zap_events (id) {
        id -> Int4,
        from_npub -> Text,
        to_npub -> Text,
        config_type -> Text,
        amount -> Int4,
        created_at -> Timestamptz,
        secret_key -> Text,
        payment_hash -> Text,
        event_id -> Text,
        paid_at -> Nullable<Timestamp>,
    }
}

diesel::table! {
    zap_events_to_subscription_configs (zap_event_id, subscription_config_id) {
        zap_event_id -> Int4,
        subscription_config_id -> Int4,
    }
}

diesel::table! {
    zap_events_to_zap_configs (zap_event_id, zap_config_id) {
        zap_event_id -> Int4,
        zap_config_id -> Int4,
    }
}

diesel::joinable!(donations -> zap_configs (config_id));
diesel::joinable!(subscription_configs -> users (user_id));
diesel::joinable!(zap_configs -> users (user_id));

diesel::allow_tables_to_appear_in_same_query!(
    donations,
    subscription_configs,
    users,
    zap_configs,
    zap_events,
    zap_events_to_subscription_configs,
    zap_events_to_zap_configs,
);
