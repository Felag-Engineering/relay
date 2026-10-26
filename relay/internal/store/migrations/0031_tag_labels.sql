-- tag_labels holds the tag: namespace (ADR-0050): disjoint from node_labels and
-- relay_labels, written only by the atomic tag write, never by a Node report
-- (invariant 7).
CREATE TABLE tag_labels (
    node_id TEXT NOT NULL REFERENCES nodes (node_id) ON DELETE CASCADE,
    key     TEXT NOT NULL,
    value   TEXT NOT NULL,
    PRIMARY KEY (node_id, key)
);
