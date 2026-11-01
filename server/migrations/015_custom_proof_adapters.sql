ALTER TABLE platform_contract_versions
  ADD COLUMN adapter_config JSONB;

ALTER TABLE platform_contract_versions ALTER COLUMN proof_depth DROP NOT NULL;
ALTER TABLE platform_challenges ADD COLUMN staged_public_signals JSONB;
ALTER TABLE platform_challenges ADD COLUMN staged_nullifier_digest CHAR(64);

ALTER TABLE platform_contract_versions
  DROP CONSTRAINT platform_contract_versions_group_ids_check,
  DROP CONSTRAINT platform_contract_versions_adapter_check,
  ADD CONSTRAINT platform_contract_versions_adapter_check
    CHECK (adapter IN ('semaphore-membership-v1','groth16-bn254-v1')),
  DROP CONSTRAINT platform_contract_versions_proof_depth_check,
  ADD CONSTRAINT platform_contract_versions_adapter_shape_check CHECK (
    (adapter='semaphore-membership-v1' AND proof_depth IS NOT NULL AND proof_depth=10 AND cardinality(group_ids) BETWEEN 1 AND 4 AND adapter_config IS NULL)
    OR
    (adapter='groth16-bn254-v1' AND proof_depth IS NULL AND cardinality(group_ids)=0 AND adapter_config IS NOT NULL AND jsonb_typeof(adapter_config)='object')
  );

CREATE TABLE platform_custom_nullifiers (
  contract_id UUID NOT NULL,
  contract_version INTEGER NOT NULL,
  nullifier_digest CHAR(64) NOT NULL CHECK (nullifier_digest ~ '^[a-f0-9]{64}$'),
  request_id UUID NOT NULL UNIQUE REFERENCES platform_requests(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(contract_id, contract_version, nullifier_digest),
  FOREIGN KEY(contract_id, contract_version) REFERENCES platform_contract_versions(contract_id, version) ON DELETE CASCADE
);
