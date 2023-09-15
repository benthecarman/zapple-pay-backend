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
);
