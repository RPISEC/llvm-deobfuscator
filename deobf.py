#!/usr/bin/env python2

from binaryninja import *
from operator    import *
from pprint      import *
from itertools   import chain


def safe_asm(bv, asm_str):
    asm, err = bv.arch.assemble(asm_str)
    if asm is None:
        raise Exception(err)
    return asm


class CFGLink(object):
    def __init__(self, block, true_block, false_block=None, def_il=None):
        self.il = def_il  # The definition il we used to find this link
        self.block = block

        self.backbone_blocks = [true_block, false_block]
        self.true_block = true_block.outgoing_edges[0].target
        self.false_block = false_block
        if self.false_block is not None:
            self.false_block = self.false_block.outgoing_edges[0].target

    @property
    def is_uncond(self):
        return self.false_block is None

    @property
    def is_cond(self):
        return not self.is_uncond

    def gen_asm(self, bv, base_addr):
        # It's assumed that base_addr is the start of free space
        # at the end of a newly recovered block
        def rel(addr):
            return hex(addr - base_addr).rstrip('L')

        # Unconditional jmp
        if self.is_uncond:
            next_addr = self.true_block.start
            print "[+] Patching from {:x} to {:x}".format(base_addr, next_addr)
            return safe_asm(bv, "jmp {}".format(rel(next_addr)))

        # Branch based on original cmovcc
        else:
            assert self.il is not None
            true_addr = self.true_block.start
            false_addr = self.false_block.start
            print "[+] Patching from {:x} to T: {:x} F: {:x}".format(base_addr,
                                                                     true_addr,
                                                                     false_addr)

            # Find the cmovcc by looking at the def il's incoming edges
            # Both parent blocks are part of the same cmov
            il_bb = next(bb for bb in self.il.function if bb.start <= self.il.instr_index < bb.end)
            cmov_addr = il_bb.incoming_edges[0].source[-1].address
            cmov = bv.get_disassembly(cmov_addr).split(' ')[0]

            # It was actually painful to write this
            jmp_instr = cmov.replace('cmov', 'j')

            # Generate the branch instructions
            asm = safe_asm(bv, '{} {}'.format(jmp_instr, rel(true_addr)))
            base_addr += len(asm)
            asm += safe_asm(bv, 'jmp {}'.format(rel(false_addr)))

            return asm


    def __repr__(self):
        if self.is_uncond:
            return '<U Link: {} => {}>'.format(self.block,
                                               self.true_block)
        else:
            return '<C Link: {} => T: {}, F: {}>'.format(self.block,
                                                         self.true_block,
                                                         self.false_block)


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


def get_ssa_def(mlil, var):
    return mlil.ssa_form[mlil.ssa_form.get_ssa_var_definition(var)]


def ResolveCFGLink(bv, mlil, il, backbone):
    # il refers to a definition of the stateVar
    bb = bv.get_basic_blocks_at(il.address)[0]

    # Unconditional jumps will set the state to a constant
    if il.src.operation == MediumLevelILOperation.MLIL_CONST:
        return CFGLink(bb, backbone[il.src.constant], def_il=il)

    # Conditional jumps choose between two values
    else:
        # Go into SSA to figure out which state is the false branch
        # Get the phi for the state variable at this point
        phi = get_ssa_def(mlil, il.ssa_form.src.src)
        assert phi.operation == MediumLevelILOperation.MLIL_VAR_PHI

        # The cmov (select) will only ever replace the default value (false)
        # with another if the condition passes (true)
        # So all we need to do is take the earliest version of the SSA var
        # as the false state
        f_def, t_def = sorted(phi.src, key=lambda var: var.version)

        # There will always be one possible value here
        false_state = get_ssa_def(mlil, f_def).src.possible_values.value
        true_state  = get_ssa_def(mlil, t_def).src.possible_values.value

        return CFGLink(bb, backbone[true_state], backbone[false_state], il)


def DeObfuscateOLLVM(bv, addr):
    func = bv.get_basic_blocks_at(addr)[0].function
    mlil = func.medium_level_il
    stateVarInit = func.get_low_level_il_at(addr).medium_level_il
    stateVar = stateVarInit.dest

    # compute all usages of the stateVar using a DFS
    backbone = ComputeBackboneCmps(bv, mlil, stateVar)
    print "[+] Computed backbone"
    pprint(backbone)

    # compute all the defs of the stateVar in the original basic blocks
    original = ComputeOriginalBlocks(bv, mlil, stateVar)
    print "[+] Usages of the state variable in original basic blocks"
    pprint(original)

    # at this point we have all the information to reconstruct the CFG
    CFG = [ResolveCFGLink(bv, mlil, il, backbone) for il in original]
    print "[+] Computed original CFG"
    pprint(CFG)

    ApplyPatchesToCFG(bv, mlil, stateVarInit, CFG, backbone)


def gather_defs(il, defs):
    defs.add(il.address)
    op = il.operation
    print hex(il.address), op, il

    if op == MediumLevelILOperation.MLIL_CONST:
        return

    if op == MediumLevelILOperation.MLIL_VAR_SSA_FIELD:
        gather_defs(get_ssa_def(il.function, il.src), defs)

    if op == MediumLevelILOperation.MLIL_VAR_PHI:
        for var in il.src:
            gather_defs(get_ssa_def(il.function, var), defs)

    if hasattr(il, 'src') and isinstance(il.src, MediumLevelILInstruction):
        gather_defs(il.src, defs)


def clean_block(bv, mlil, link):
    # Return the data for a block with all unnecessary instructions removed

    # The terminator gets replaced anyway
    block = link.block
    nop_addrs = {block.disassembly_text[-1].address}

    # Gather all address related to the state variable
    if link.il is not None:
        gather_defs(link.il.ssa_form, nop_addrs)

    # Rebuild the block, skipping the bad instrs
    addr = block.start
    data = ''
    while addr < block.end:
        ilen = bv.get_instruction_length(addr)
        if addr not in nop_addrs:
            # print 'adding', bv.get_disassembly(addr)
            data += bv.read(addr, ilen)
        addr += ilen
    return data, block.start + len(data)


def patch_link(bv, mlil, link):
    blockdata, cave_addr = clean_block(bv, mlil, link)
    blockdata += link.gen_asm(bv, cave_addr)
    bv.write(link.block.start, blockdata)


def ApplyPatchesToCFG(bv, mlil, stateVarInit, CFG, backbone):
    print '[+] Patching all discovered links'
    for prev in CFG:
        patch_link(bv, mlil, prev)

    # All of the inner blocks are now correctly linked together
    # All that's left to do is find the target of the first block and link them
    # The whole backbone becomes a code cave as a result
    print '[+] Patching first block to delete backbone'
    init_bb = bv.get_basic_blocks_at(stateVarInit.address)[0]
    next_bb = backbone[stateVarInit.src.constant]
    patch_link(bv, mlil, CFGLink(init_bb, next_bb, def_il=stateVarInit))


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
