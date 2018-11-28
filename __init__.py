#!/usr/bin/env python2
from binaryninja import *
from .deflatten import deflatten_cfg
from .util import *


class RunInBackground(BackgroundTaskThread):
    def __init__(self, bv, addr, msg, func):
            BackgroundTaskThread.__init__(self, msg, True)
            self.bv = bv
            self.addr = addr
            self.func = func

    def run(self):
            bv = self.bv
            bv.begin_undo_actions()
            fix_analysis(bv, self.addr)
            self.func(bv, self.addr)
            bv.commit_undo_actions()
            bv.update_analysis()


def DeFlattenBackgrounder(bv, addr):
    s = RunInBackground(bv, addr, "Removing Control Flow Flattening", deflatten_cfg)
    s.start()


def fix_analysis(bv, addr):
    # Binja may have skipped analysis of the function
    # force analysis so we can use llil/mlil
    f = get_func_containing(bv, addr)
    if f is not None and f.analysis_skipped:
        f.analysis_skip_override = FunctionAnalysisSkipOverride.NeverSkipFunctionAnalysis
        bv.update_analysis_and_wait()

# I have no idea how to make a dropdown, so we'll just have these separate things for now
PluginCommand.register_for_address("Deobfuscate (OLLVM)",
                                   "Remove Control Flow Flattening given switch variable",
                                   DeFlattenBackgrounder)
