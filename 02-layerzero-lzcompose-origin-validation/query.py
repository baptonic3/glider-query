from glider import *

"""
@title: Missing Origin Validation in LayerZero V2 lzCompose Enables Cross-Chain Message Spoofing
@description: 
This query detects **LayerZero V2 `lzCompose` implementations that fail to fully validate critical trust boundaries**, specifically:

- Missing validation of the `from` parameter (expected to be the originating OFT / OApp contract)
- Missing or incomplete enforcement of the trusted LayerZero Endpoint (`EndpointV2`) as the sole caller

LayerZero V2 explicitly **does not guarantee message integrity**. Relayers and executors are untrusted and may submit **arbitrary calldata** to `lzCompose`. As a result, **all parameters must be treated as attacker-controlled unless explicitly validated**.

Contracts that:
- Accept `lzCompose` callbacks,
- Decode and act on message payloads,
- Transfer assets or execute downstream logic,

**must** verify both:

1. `msg.sender == endpoint`, and
2. `from == expectedOFT / trusted sender`.

Failing to validate the `from` parameter allows **cross-chain message spoofing**, where a malicious relayer can craft fake messages that trigger unintended execution paths, asset transfers, or external calls under false assumptions of origin.

@tags:
layerzero, cross-chain, message-spoofing, lzcompose, access-control

@author:
baptonic

@references:
- https://docs.layerzero.network/v2/developers/evm/oapp/overview  
- https://github.com/windhustler/Interoperability-Protocol-Security-Checklist/blob/main/audit-checklists/LayerZeroV2.md
- https://docs.layerzero.network/v2/developers/evm/technical-reference/endpoints  
"""

def query():
    # Find all lzCompose function implementations
    lzcompose_functions = Functions().with_name("lzCompose").exec()
    
    findings = []
    
    for fn in lzcompose_functions:
        contract = fn.get_contract()

        if not contract.is_main():
            continue

        if not fn.is_external():
            continue
                
        if not validates_from_parameter(fn):
            findings.append(fn)
            continue

        if not validates_msg_sender_is_endpoint(fn):
            findings.append(fn)
            continue

    return findings


# ============================================================
# Validation helpers
# ============================================================

def validates_from_parameter(function):
    """
    Checks whether the lzCompose `from` argument is explicitly validated
    via an equality comparison and guarded by revert/require.
    """
    
    args = function.arguments().list()
    if len(args) == 0:
        return False

    from_arg_full = args[0].get_variable().source_code()
    from_arg = from_arg_full.split()[-1]

    instructions = function.instructions_recursive()

    for inst in instructions:
        if not revert_condition(inst):
            continue

        components = get_components_recursive(inst)

        has_from = False
        has_equality = False
        has_nonzero = True

        for comp in components:
            src = comp.source_code()

            if from_arg in src:
                has_from = True

            if "address(0)" in src:
                has_nonzero = False

            if "Operator" in str(comp):
                op = comp.get_operator()
                if str(op) in ("OperatorType.EQUAL", "OperatorType.NOT_EQUAL"):
                    has_equality = True

        if has_from and has_equality and has_nonzero:
            return True

    return False

def validates_msg_sender_is_endpoint(function):
    """
    Checks whether msg.sender is explicitly validated
    against an endpoint variable.
    """
    instructions = function.instructions_recursive()

    for inst in instructions:
        if not revert_condition(inst):
            continue

        components = get_components_recursive(inst)

        has_sender = False
        has_endpoint = False
        has_equality = False

        for comp in components:
            src = comp.source_code()

            if "msg.sender" in src:
                has_sender = True

            if "endpoint" in src.lower():
                has_endpoint = True

            if "Operator" in str(comp):
                op = comp.get_operator()
                if str(op) in ("OperatorType.EQUAL", "OperatorType.NOT_EQUAL"):
                    has_equality = True

        if has_sender and has_endpoint and has_equality:
            return True

    return False

# ============================================================
# Utility helpers 
# ============================================================

def revert_condition(instruction):
    callee_names = instruction.callee_names()
    if "require" in callee_names or "assert" in callee_names:
        return True

    if instruction.is_if():
        try:
            return any(
                "revert" in c for c in instruction.first_true_instruction().callee_names()
            )
        except Exception:
            pass

    return False


def get_components_recursive(component):
    components = []

    try:
        if "IndexAccess" in str(component):
            components.append(component.get_sequence())
            components.append(component.get_index())

        if isinstance(component, Call):
            components.extend(component.get_args())
            qualifier = component.get_call_qualifier()

            if "IndexAccess" in str(qualifier):
                components.append(qualifier)
                components.append(qualifier.get_sequence())
                components.append(qualifier.get_index())
        else:
            components = component.get_components()
    except Exception:
        pass

    results = []
    for comp in components:
        results.append(comp)
        results.extend(get_components_recursive(comp))

    return results