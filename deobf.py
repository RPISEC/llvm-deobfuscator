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


def ComputeBackboneCmps(bv, mlil, stateVar):
    backbone = {}

    # Find the variable that all subdispatchers use in comparisons
    var = stateVar
    uses = mlil.get_var_uses(var)
    while len(uses) <= 2:
        var = mlil[uses[-1]].dest
        uses = mlil.get_var_uses(var)
    uses += mlil.get_var_definitions(var)

    # Gather the blocks where this is used
    blks = (b for idx in uses for b in mlil.basic_blocks if b.start <= idx < b.end)

    # In each of these blocks, find the value of the state
    for bb in blks:
        # Find the comparison
        cond_var = bb[-1].condition.src
        cmp_il = mlil[mlil.get_var_definitions(cond_var)[0]]

        # Pull out the state value
        state = cmp_il.src.right.constant
        backbone[state] = bv.get_basic_blocks_at(bb[0].address)[0]

    return backbone


def ComputeOriginalBlocks(bv, mlil, stateVar):
    original = mlil.get_var_definitions(stateVar)
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


def DeObfuscateOLLVM(bv, addr):
    func = bv.get_basic_blocks_at(addr)[0].function
    mlil = func.medium_level_il
    stateVar = func.get_low_level_il_at(addr).medium_level_il.dest

    # compute all usages of the stateVar
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

    # patch in all the changes
    print '[+] Patching all discovered links'
    for link in CFG:
        # Clean out instructions we don't need to make space
        blockdata, cave_addr = clean_block(bv, mlil, link)

        # Add the new instructions and patch
        blockdata += link.gen_asm(bv, cave_addr)
        bv.write(link.block.start, blockdata)


"""
Example CFG:
[<C Link: <block: x86_64@0x4006e7-0x400700> => T: <block: x86_64@0x400700-0x400720>, F: <block: x86_64@0x400735-0x400741>>,
 <U Link: <block: x86_64@0x4006d4-0x4006e7> => <block: x86_64@0x4006e7-0x400700>>,
 <U Link: <block: x86_64@0x400700-0x400720> => <block: x86_64@0x400720-0x400735>>,
 <U Link: <block: x86_64@0x4006b4-0x4006d4> => <block: x86_64@0x400741-0x400749>>,
 <U Link: <block: x86_64@0x400735-0x400741> => <block: x86_64@0x400741-0x400749>>,
 <C Link: <block: x86_64@0x400699-0x4006b4> => T: <block: x86_64@0x4006b4-0x4006d4>, F: <block: x86_64@0x4006d4-0x4006e7>>,
 <U Link: <block: x86_64@0x400720-0x400735> => <block: x86_64@0x4006e7-0x400700>>]
"""

PluginCommand.register_for_address("Deobfuscate (OLLVM)",
        "Remove Control Flow Flattening given switch variable",
        DeObfuscateOLLVM)
