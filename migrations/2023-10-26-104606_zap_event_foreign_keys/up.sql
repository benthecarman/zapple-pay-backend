-- table linking zap events to zap configs
CREATE TABLE zap_events_to_zap_configs
(
    zap_event_id  INTEGER NOT NULL,
    zap_config_id INTEGER NOT NULL,
    PRIMARY KEY (zap_event_id, zap_config_id)
);

-- table linking zap events to subscription configs
CREATE TABLE zap_events_to_subscription_configs
(
    zap_event_id          INTEGER NOT NULL,
    subscription_config_id INTEGER NOT NULL,
    PRIMARY KEY (zap_event_id, subscription_config_id)
);
