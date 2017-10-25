#!/usr/bin/env python


from binaryninja import *
from operator    import *
from pprint      import *


def VisitDefUse(bv, dispatchDef, mlil, cb):
    # perform a depth-first search on state variables
    def DFS(dispatchDef):
        cb(dispatchDef)
        if hasattr(dispatchDef, "dest"):
            dispatchDef = mlil.get_var_uses(dispatchDef.dest)
            if len(dispatchDef) > 0:
                dispatchDef = itemgetter(*dispatchDef)(mlil)
                # there may be more than one possible usage
                if isinstance(dispatchDef, tuple):
                    for i in dispatchDef:
                        DFS(i)
                else:
                    DFS(dispatchDef)
    DFS(dispatchDef)


def ValOrVals(valueSet):
    try:
        return set([valueSet.value])
    except:
        return valueSet.values


def DeObfuscateOLLVM(bv, addr):
    func = bv.get_basic_blocks_at(addr)[0].function
    mlil = func.medium_level_il
    stateVar = func.get_low_level_il_at(addr).medium_level_il
    stateVar = stateVar.dest

    # compute all usages of the stateVar using a DFS
    backbone = { }
    def VisitBackboneCB(dispatchDef):
        if dispatchDef.operation             == MediumLevelILOperation.MLIL_SET_VAR and \
           dispatchDef.operands[1].operation == MediumLevelILOperation.MLIL_CMP_E:
            backbone[dispatchDef.operands[1].operands[1].value.value] = \
                bv.get_basic_blocks_at(dispatchDef.address)[0]

    backboneDef = mlil.get_var_definitions(stateVar)
    backboneDef = backboneDef[0]  # XXX: is this a good assumption?
    VisitDefUse(bv, mlil[backboneDef], mlil, VisitBackboneCB)
    print "[+] Computed backbone"
    pprint(backbone)

    # compute all the usages of the stateVar in the original basic blocks
    original = mlil.get_var_definitions(stateVar)
    original = original[1:] # XXX: is this a good assumption?
    original = itemgetter(*original)(mlil)
    print "[+] Usages of the state variable"
    pprint(original)

    # at this point we have all the information to reconstruct the CFG
    CFG = { }
    for il in original:
        curr = bv.get_basic_blocks_at(il.address)[0]
        vals = ValOrVals(il.src.possible_values)
        CFG[curr] = { i:backbone[i] for i in vals }
    print "[+] Computed original CFG"
    pprint(CFG)


PluginCommand.register_for_address("Deobfuscate (OLLVM)",
        "Remove Control Flow Flattening given switch variable",
        DeObfuscateOLLVM)
