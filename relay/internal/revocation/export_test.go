package revocation

// CascadeRecordChunk exports cascadeRecordChunk to the external
// revocation_test package, so its fixtures can be sized to the real chunk
// boundary without this tuning constant becoming part of the package's public
// API.
const CascadeRecordChunk = cascadeRecordChunk
