from binaryninja import *


def safe_asm(bv, asm_str):
    return bv.arch.assemble(asm_str)


def get_ssa_def(mlil, var):
    """ Gets the IL that defines var in the SSA form of mlil """
    return mlil.ssa_form.get_ssa_var_definition(var)


def gather_defs(il, defs):
    """ Walks up a def chain starting at the given il (mlil-ssa)
    until constants are found, gathering all addresses along the way
    """
    defs.add(il.address)
    op = il.operation

    if op == MediumLevelILOperation.MLIL_CONST:
        return

    if op in [MediumLevelILOperation.MLIL_VAR_SSA_FIELD,
              MediumLevelILOperation.MLIL_VAR_SSA]:
        gather_defs(get_ssa_def(il.function, il.src), defs)

    if op == MediumLevelILOperation.MLIL_VAR_PHI:
        for var in il.src:
            gather_defs(get_ssa_def(il.function, var), defs)

    if hasattr(il, 'src') and isinstance(il.src, MediumLevelILInstruction):
        gather_defs(il.src, defs)


def llil_at(bv, addr):
    funcs = bv.get_functions_containing(addr)
    if funcs is None:
        return None

    return funcs[0].get_low_level_il_at(addr)


def is_call(bv, addr):
    llil = llil_at(bv, addr)
    if llil is None:
        return False

    return llil.operation == LowLevelILOperation.LLIL_CALL


def get_func_containing(bv, addr):
    """ Finds the function, if any, containing the given address """
    funcs = bv.get_functions_containing(addr)
    return funcs[0] if funcs is not None else None
