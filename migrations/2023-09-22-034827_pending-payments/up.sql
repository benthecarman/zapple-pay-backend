-- delete everything from the zap_events table
DELETE
FROM zap_events;

ALTER TABLE zap_events
    ADD COLUMN secret_key TEXT NOT NULL;
ALTER TABLE zap_events
    ADD COLUMN payment_hash TEXT NOT NULL;
ALTER TABLE zap_events
    ADD COLUMN event_id TEXT UNIQUE NOT NULL;

ALTER TABLE zap_events
    ADD COLUMN paid_at TIMESTAMP;
