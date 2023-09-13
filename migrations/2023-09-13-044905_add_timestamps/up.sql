-- add created at date to users
ALTER TABLE users ADD COLUMN created_at timestamp with time zone DEFAULT now();
ALTER TABLE users ALTER COLUMN created_at SET NOT NULL;
-- add created at date to zap_configs
ALTER TABLE zap_configs ADD COLUMN created_at timestamp with time zone DEFAULT now();
ALTER TABLE zap_configs ALTER COLUMN created_at SET NOT NULL;
-- add created at date to subscription_configs
ALTER TABLE subscription_configs ADD COLUMN created_at timestamp with time zone DEFAULT now();
ALTER TABLE subscription_configs ALTER COLUMN created_at SET NOT NULL;
-- add created at date to zap_events
ALTER TABLE zap_events ADD COLUMN created_at timestamp with time zone DEFAULT now();
ALTER TABLE zap_events ALTER COLUMN created_at SET NOT NULL;
