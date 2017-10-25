#!/usr/bin/env python2

from binaryninja import *
from operator    import *
from pprint      import *
from itertools   import chain


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


def ComputeBackboneCmps(bv, mlil, stateVar):
    backbone = { }
    def VisitBackboneCB(dispatchDef):
        if dispatchDef.operation     == MediumLevelILOperation.MLIL_SET_VAR and \
           dispatchDef.src.operation == MediumLevelILOperation.MLIL_CMP_E:
            backbone[dispatchDef.src.right.constant] = \
                bv.get_basic_blocks_at(dispatchDef.address)[0]

    backboneDef = mlil.get_var_definitions(stateVar)
    backboneDef = backboneDef[0]    # XXX: is this a good assumption?
    VisitDefUse(bv, mlil[backboneDef], mlil, VisitBackboneCB)
    return backbone


def ComputeOriginalBlocks(bv, mlil, stateVar):
    original = mlil.get_var_definitions(stateVar)
    original = original[1:]         # XXX: is this a good assumption?
    return itemgetter(*original)(mlil)


def DeObfuscateOLLVM(bv, addr):
    func = bv.get_basic_blocks_at(addr)[0].function
    mlil = func.medium_level_il
    stateVar = func.get_low_level_il_at(addr).medium_level_il
    stateVar = stateVar.dest

    # compute all usages of the stateVar using a DFS
    backbone = ComputeBackboneCmps(bv, mlil, stateVar)
    print "[+] Computed backbone"
    pprint(backbone)

    # compute all the defs of the stateVar in the original basic blocks
    original = ComputeOriginalBlocks(bv, mlil, stateVar)
    print "[+] Usages of the state variable in original basic blocks"
    pprint(original)

    # at this point we have all the information to reconstruct the CFG
    CFG = { }
    for il in original:
        curr = bv.get_basic_blocks_at(il.address)[0]
        vals = ValOrVals(il.src.possible_values)
        CFG[curr] = { i:backbone[i] for i in vals }
    print "[+] Computed original CFG"
    pprint(CFG)

    ApplyPatchesToCFG(bv, stateVar, CFG)


def LinkBB1ToBB2(bv, bb1, bb2):
    prev = bb1.get_disassembly_text()[-1].address
    next = bb2.start

    print "[+] Patching from {:x} to {:x}".format(prev, next)
    jmp, err = bv.arch.assemble("jmp {}".format(hex(next-prev).rstrip("L")))
    if jmp is None:
        raise Exception(err)
    bv.write(prev, jmp)                # XXX: do we have enough space?


def ApplyPatchesToCFG(bv, stateVar, CFG):
    # first link up all basic blocks with only a
    # single outgoing edge
    unconditional = filter(lambda x:len(CFG[x]) == 1, CFG.keys())
    print "[+] Identified unconditional jumps"
    pprint(unconditional)

    for prev in unconditional:
        curr = CFG[prev].values()[0]
        curr = curr.outgoing_edges[0].target # True branch
        LinkBB1ToBB2(bv, prev, curr)

    if False:
        # XXX: now do unconditional branches, which may be
        # *much* more difficult
        conditional = filter(lambda x:len(CFG[x]) > 1, CFG.keys())
        print "[+] Identified conditional jumps"
        pprint(conditional)

    if False:
        # XXX: now we remove the backbone layer, since this
        # is now useless with the basic blocks linked together
        # correctly
        backbones = set(chain(*map(lambda x: x.values(), CFG.values())))
        print "[+] Identified backbone blocks:"
        pprint(backbones)
        for back in backbones:
            prev = back.incoming_edges[0].source
            next = back.outgoing_edges[1].target # False branch
            LinkBB1ToBB2(bv, prev, next)


"""
{ <block: x86_64@0x4061df-0x406240: {0x37aaf505: <block: x86_64@0x406198-0x4061a9>,
                                     0x45260b82: <block: x86_64@0x4061ae-0x4061bf>},
  <block: x86_64@0x406309-0x40636d: {0x45260b82: <block: x86_64@0x4061ae-0x4061bf>},
  <block: x86_64@0x406240-0x4062fe: {0x37aaf505: <block: x86_64@0x406198-0x4061a9>,
                                     0xec95166a: <block: x86_64@0x40617c-0x406193>}}
"""

PluginCommand.register_for_address("Deobfuscate (OLLVM)",
        "Remove Control Flow Flattening given switch variable",
        DeObfuscateOLLVM)
