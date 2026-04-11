# Missing Message Origin Validation in LayerZero V2 lzCompose Enables Cross-Chain Message Spoofing

##  Query
- Glider DB: https://r.xyz/glider-query-database/query/694707cedb3b3efd61383814

##  Description

This query detects **LayerZero V2 `lzCompose` implementations** that fail to properly validate critical trust boundaries for cross-chain messages, specifically:

- The message origin (`from`)
- The caller (`msg.sender`)

LayerZero V2 **does not guarantee message integrity**. Relayers and executors are untrusted and may submit arbitrary calldata to `lzCompose`. As a result, all callback parameters must be treated as attacker-controlled unless explicitly validated.

The query flags contracts that implement `lzCompose` and perform downstream execution while missing required validation of:

- `msg.sender == endpoint` (trusted LayerZero Endpoint), and/or  
- `from == expectedOFT / trusted OApp` (verified message origin)

---

##  Impact

Failing to validate the `from` parameter enables **cross-chain message spoofing**, where:

- Malicious actors can craft arbitrary `lzCompose` messages  
- Contracts may execute logic under false assumptions of trusted origin  
- Assets or execution flows can be redirected or abused  

This breaks the **core trust model of cross-chain messaging**.