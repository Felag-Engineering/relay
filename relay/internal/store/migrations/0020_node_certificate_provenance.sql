-- Certificate provenance on the Node record (#440, ADR-0034).
--
-- The registry stored a certificate FINGERPRINT and nothing else, so the Relay
-- could not answer when a Node's identity expires, how many times it has
-- renewed, or when it first joined. Certificate validity existed only
-- transiently at issuance (internal/ca), and `enrolled_at` existed nowhere: the
-- Node's join time was recoverable only by trawling the audit trail, and
-- `last_seen` moved on every reconnect, so provenance was lost the moment a
-- Node came back.
--
-- The practical cost was `state:cert-expiring` (ADR-0034), which is the ONLY
-- warning before a Node that has stopped renewing drops silently off the fleet.
-- It could be defined and never computed.
--
-- Every column here is RELAY-ISSUED, not Node-reported. The Relay minted the
-- certificate, so it alone knows the expiry — a daemon cannot influence any of
-- these values, and registry.Report deliberately has no field for them, exactly
-- as it has none for relay: labels or revocation (a structural test asserts it).
--
-- Defaults make this a pure additive migration over an existing fleet: Nodes
-- enrolled before it carry zero values until their next renewal, which is at
-- most one leaf lifetime away (~14 days). A reader must treat the zero value as
-- "not recorded", never as "expires at the epoch".

-- cert_not_after is the NotAfter of the certificate the Node currently holds,
-- read from the issued certificate itself rather than recomputed from the CA's
-- validity constant — so if that constant changes, the record follows what was
-- actually signed instead of what the code would sign today.
ALTER TABLE nodes ADD COLUMN cert_not_after TIMESTAMP;

-- enrolled_at is set ONCE, at first enrollment, and never written again. It is
-- the anchor of the provenance chain: renewal is certificate-authenticated and
-- preserves node_id, so an unbroken line runs from here to the Enrollment Token
-- the Node joined with.
ALTER TABLE nodes ADD COLUMN enrolled_at TIMESTAMP;

-- renewal_count and last_renewed_at move on renewal ONLY. A Node whose
-- renewal_count stops climbing while its cert_not_after approaches is the exact
-- signal state:cert-expiring exists to raise.
ALTER TABLE nodes ADD COLUMN renewal_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE nodes ADD COLUMN last_renewed_at TIMESTAMP;

-- There is deliberately NO connected column. Liveness is a property of a socket
-- that exists this instant, and a persisted `connected = true` surviving a
-- crash is a lie the fleet view would render as a green dot. It is held in
-- memory, fed by the transport's stream open and close, and derived onto the
-- Node on every read — the same treatment `Outdated` already gets.
