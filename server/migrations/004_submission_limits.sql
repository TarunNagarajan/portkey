ALTER TABLE private_submissions DROP CONSTRAINT private_submissions_encrypted_bytes_check;
ALTER TABLE private_submissions ADD CONSTRAINT private_submissions_encrypted_bytes_check
  CHECK (encrypted_bytes BETWEEN 0 AND 262148000);
