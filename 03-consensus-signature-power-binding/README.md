# Consensus Signature Verification Without Explicit Power Binding

##  Query
- Glider DB: https://r.xyz/glider-query-database/query/696e7ba7b78dfdbec169cebf
  
## Description

Detects consensus-based validator or committee update entrypoints that verify cryptographic signatures and aggregate voting power, but do not explicitly bind each recovered signer to a specific validator index or power allocation.

In these implementations, voting power attribution relies on positional ordering or implicit assumptions about how signatures correspond to validator entries rather than enforcing the relationship cryptographically. If the recovered signer is not checked against the validator whose power is being counted, a valid signature may be credited with incorrect validator power.

This can weaken the integrity of consensus verification logic and may allow incorrect voting power attribution depending on how signature arrays, validator ordering, or validation flows are handled.

## Impact
If signer-to-validator binding assumptions are broken, the following risks may arise:

Validator signatures may be attributed to incorrect voting power
Voting power aggregation may rely on positional assumptions rather than cryptographic binding
Consensus thresholds could be reached under incorrect power attribution
Validator set updates or batch executions could succeed under unintended authority
While this does not guarantee immediate exploitation in isolation, it introduces a fragile trust boundary where consensus safety depends on off-chain ordering guarantees rather than explicit on-chain validation.

This class of issue has historically contributed to bridge and validator verification failures when ordering guarantees or relayer behavior changed.