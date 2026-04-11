from glider import *

def query():
    """
    @title: Flashloan callback missing caller validation enables forged execution
    @description:
        This query detects flashloan callback functions (e.g. executeOperation,
        onFlashLoan) that perform sensitive operations such as state writes, 
        external calls, or value transfers, but do NOT validate msg.sender 
        against a trusted flashloan provider (Aave, ERC-3156, etc).

        While some implementations rely on internal state flags (e.g. status variables
        or initiator checks), the absence of explicit msg.sender validation introduces
        a fragile trust assumption. If those internal guards are bypassed due to future
        refactors, upgrade bugs, or compromised privileged flows, an attacker may invoke
        the callback directly and execute arbitrary logic under flashloan context.

        This pattern has historically led to real-world exploits and is considered
        a high-risk defensive gap in flashloan integrations.
    @tags: flashloan, callback, missing-validation, aave, erc3156
    @author: baptonic
    @references:
        - https://docs.aave.com/developers/guides/flash-loans
        - https://eips.ethereum.org/EIPS/eip-3156
        - https://rekt.news/flashloan-attacks/
        - https://blog.openzeppelin.com/defensive-smart-contract-design/
    """

    # 1. Find public / external functions with common flashloan callback names
    functions = (
        Functions()
        .with_one_property([MethodProp.EXTERNAL, MethodProp.PUBLIC])
        .without_properties([MethodProp.IS_VIEW, MethodProp.IS_PURE])
        .with_name_regex(
            "executeOperation|onFlashLoan|executeFlashLoan"
        )
        .exec()
        .filter(lambda f: f.get_contract().is_main())

    )

    results = []

    for function in functions:
        try:
            instructions = function.instructions_recursive()
        except Exception:
            continue

        if not instructions:
            continue

        # 2. Detect sensitive behavior inside callback
        has_external_calls = False
        has_value_transfer = False

        for instr in instructions:
            callee_names = instr.callee_names() or []

            # External calls
            if instr.is_call():
                has_external_calls = True

            # ETH / ERC20 transfers
            if any(
                name in callee_names
                for name in ["transfer", "transferFrom", "send", "call"]
            ):
                has_value_transfer = True

        if not (has_external_calls or has_value_transfer):
            continue

        # 3. Check for msg.sender validation using glider validation logic
        if not validates_msg_sender(function):
            results.append(function)

    return results


# ==============================================================================================================
# msg.sender validation helpers (from Glider cheatsheet)
# ==============================================================================================================

# Note: msg.sender passed into a Call or used as IndexAccess and the return value 
# is equated against are treated as a msg.sender validation.
def validates_msg_sender(function):
    for instruction in function.instructions_recursive():
        if revert_condition(instruction) and potential_msg_sender_call(instruction):
            return True 
    return False 


# Checks if revert is called
def revert_condition(instruction):
    builtin_callee_names = instruction.callee_names()
    if 'require' in builtin_callee_names or 'assert' in builtin_callee_names:
        return True

    if not instruction.is_if():
        return False
        
    return any('revert' in x for x in instruction.first_true_instruction().callee_names())


# Checks if an instruction calls msg.sender in any call
def potential_msg_sender_call(instruction):
    components = get_components_recursive(instruction)

    for component in components:
        # Ignore Calls and IndexAccesses since they produce a large number of FPs.
        if isinstance(component, Call) or "IndexAccess" in str(component):
            continue

        # There are cases where msg.sender is passed into a check that isn't 
        # validating the msg.sender address. For example balance >= balances[msg.sender]. 
        # This skips those cases.
        if isinstance(component, ValueExpression) and not contains_equality_op(component):
            continue

        for msg_sender_call in msg_sender_calls():
            if msg_sender_call in component.source_code(): 
                return True

    return False


# Iterate through a component's operations and check for equality checks. 
def contains_equality_op(component):
    ops = component.get_components().filter(lambda component : "Operator" in str(component)).get_operator()

    for operator in ops:
        if "OperatorType.NOT_EQUAL" in str(operator) or "OperatorType.EQUAL" in str(operator):
            return True

    return False


# Returns a list of common ways to retrieve msg.sender
def msg_sender_calls():
    return [
        "msg.sender",
        "msgSender",
        "_msgSender",
        "_msgSenderERC1155",
        "caller"  # Assembly msg.sender call
    ]


# Returns all components in Instruction through recursive manner suited for msg.sender validations.
def get_components_recursive(component):
    components = []
    results = [] 

    try:
        # If we are dealing with a call, we get the call arguments as components
        if isinstance(component, Call):
            components.extend(component.get_args()) 
        else:
            # Get components within components
            components = component.get_components()
    except: 
        # This handles cases where the component can't be broken down further
        None

    for comp in components:    
        results.append(comp)

        for sub_comp in get_components_recursive(comp):
            results.append(sub_comp)

    return results