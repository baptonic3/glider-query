from glider import *

def query():
    """
    @title: Missing Signature-to-Power Binding in Consensus Validator Updates
    @description:
        Detects consensus-based validator or committee update entrypoints that
        verify cryptographic signatures and aggregate voting power, but do not
        explicitly bind each recovered signer to a specific validator index or
        power allocation.

        In such designs, voting power attribution relies on positional or
        off-chain assumptions rather than cryptographic enforcement. This can
        allow a valid signer to be credited with incorrect or amplified power,
        potentially compromising consensus safety.
    @author: baptonic
    @tags: consensus, signatures, validator-set, power, bridge
    """

    # Tokens indicating validator / committee membership
    VALIDATOR_TOKENS = ["validators", "_validators", "committee", "members"]

    # Tokens indicating voting power aggregation
    POWER_TOKENS = ["powers", "_powers", "votingPower", "weights", "stakes"]

    # Tokens suggesting explicit signer → validator binding
    BIND_TOKENS = ["indexOf", "validatorIndex", "signerIndex", "findValidator"]

    # -----------------------------------
    # Helper utilities
    # -----------------------------------

    def any_in(src, toks):
        for t in toks:
            if t in src:
                return True
        return False

    # Detect signature verification logic 
    def has_signature_logic(fn):
        instructions = (
            fn.instructions()
            .with_one_of_callee_names([
                "ecrecover",
                "recover",
                "checkValidatorSignatures",
                "verifySignatures",
                "validateSignatures"
            ])
            .exec(1)
        )
        return len(instructions) > 0

    # Determine if function resembles validator consensus logic
    def looks_like_consensus_update(src):
        return (
            any_in(src, VALIDATOR_TOKENS)
            and any_in(src, POWER_TOKENS)
        )

    # Detect explicit signer → validator binding logic
    def has_explicit_signer_binding(src):
        return any_in(src, BIND_TOKENS)

    # Exclude centralized admin functions
    def is_centralized_control(src):
        return any_in(src, [
            "onlyOwner",
            "onlyAdmin",
            "onlyOperator",
            "onlyGovernance"
        ])

    # -----------------------------------
    # Seed selection
    # -----------------------------------

    candidates = (
        Functions()
        .with_properties(FunctionFilters.IS_EXTERNAL | FunctionFilters.IS_PUBLIC)
        .without_properties([MethodProp.IS_VIEW, MethodProp.IS_PURE])
        .with_name_regex(r"(update|commit|submit|apply|execute)")
        .exec()
    )

    findings = []

    # -----------------------------------
    # Analysis loop
    # -----------------------------------

    for fn in candidates:

        if not fn.get_contract().is_main():
            continue

        src = fn.source_code()
        if not src:
            continue

        # Must resemble validator consensus logic
        if not looks_like_consensus_update(src):
            continue

        # Must contain signature verification logic
        if not has_signature_logic(fn):
            continue

        # Skip centralized admin functions
        if is_centralized_control(src):
            continue

        # Core vulnerability signal:
        # signatures + power aggregation WITHOUT explicit signer binding
        if not has_explicit_signer_binding(src):
            findings.append(fn)

    return findings