ALTER TABLE oauth_providers ADD COLUMN issuer_url TEXT;
ALTER TABLE oauth_providers ADD COLUMN jwks_url TEXT;
ALTER TABLE oauth_providers ADD COLUMN admin_roles TEXT;
ALTER TABLE oauth_providers ADD COLUMN collaborator_roles TEXT;
