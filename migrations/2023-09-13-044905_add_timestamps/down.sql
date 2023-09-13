-- drop created at date from users
ALTER TABLE users DROP COLUMN created_at;
-- drop created at date from zap_configs
ALTER TABLE zap_configs DROP COLUMN created_at;
-- drop created at date from subscription_configs
ALTER TABLE subscription_configs DROP COLUMN created_at;
-- drop created at date from zap_events
ALTER TABLE zap_events DROP COLUMN created_at;
