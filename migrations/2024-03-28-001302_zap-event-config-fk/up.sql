DELETE
FROM zap_events_to_zap_configs
WHERE zap_event_id NOT IN (SELECT id FROM zap_events);

ALTER TABLE zap_events_to_zap_configs
    ADD CONSTRAINT fk_zap_events_to_zap_configs_zap_event_id
        FOREIGN KEY (zap_event_id)
            REFERENCES zap_events (id)
            ON DELETE CASCADE;
