ALTER TABLE rooms ADD COLUMN geo_lat DOUBLE PRECISION NULL;
ALTER TABLE rooms ADD COLUMN geo_lng DOUBLE PRECISION NULL;
ALTER TABLE rooms ADD COLUMN geo_radius_m INTEGER NULL;
ALTER TABLE rooms ADD COLUMN geo_label TEXT NULL;
ALTER TABLE rooms ADD COLUMN geo_source TEXT NULL;
ALTER TABLE rooms ADD CONSTRAINT rooms_geo_all_or_none
  CHECK ((geo_lat IS NULL AND geo_lng IS NULL AND geo_radius_m IS NULL)
  OR (geo_lat IS NOT NULL AND geo_lng IS NOT NULL AND geo_radius_m IS NOT NULL));
ALTER TABLE rooms ADD CONSTRAINT rooms_geo_lat CHECK (geo_lat IS NULL OR (geo_lat >= -90 AND geo_lat <= 90));
ALTER TABLE rooms ADD CONSTRAINT rooms_geo_lng CHECK (geo_lng IS NULL OR (geo_lng >= -180 AND geo_lng <= 180));
ALTER TABLE rooms ADD CONSTRAINT rooms_geo_radius CHECK (geo_radius_m IS NULL OR (geo_radius_m >= 50 AND geo_radius_m <= 50000));
ALTER TABLE rooms ADD CONSTRAINT rooms_geo_source CHECK (geo_source IS NULL OR geo_source IN ('search', 'device'));

ALTER TABLE memberships ADD COLUMN last_lat DOUBLE PRECISION NULL;
ALTER TABLE memberships ADD COLUMN last_lng DOUBLE PRECISION NULL;
ALTER TABLE memberships ADD COLUMN last_accuracy_m DOUBLE PRECISION NULL;
ALTER TABLE memberships ADD COLUMN last_distance_m DOUBLE PRECISION NULL;
ALTER TABLE memberships ADD COLUMN last_inside BOOLEAN NULL;
ALTER TABLE memberships ADD COLUMN last_checked_at TIMESTAMPTZ NULL;
