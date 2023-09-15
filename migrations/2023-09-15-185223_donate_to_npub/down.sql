ALTER TABLE donations
    DROP COLUMN npub;

ALTER TABLE donations
    ALTER COLUMN lnurl SET NOT NULL;
