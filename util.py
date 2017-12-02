from binaryninja import *


def safe_asm(bv, asm_str):
    asm, err = bv.arch.assemble(asm_str)
    if asm is None:
        raise Exception(err)
    return asm


def get_ssa_def(mlil, var):
    return mlil.ssa_form[mlil.ssa_form.get_ssa_var_definition(var)]


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
