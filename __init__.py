#!/usr/bin/env python2
from binaryninja import *
from .deflatten import DeFlattenCFG


class RunInBackground(BackgroundTaskThread):
    def __init__(self, bv, addr, msg, func):
            BackgroundTaskThread.__init__(self, msg, True)
            self.bv = bv
            self.addr = addr
            self.func = func

    def run(self):
            bv = self.bv
            bv.begin_undo_actions()
            self.func(bv, self.addr)
            bv.commit_undo_actions()
            bv.update_analysis()


def DeFlattenBackgrounder(bv, addr):
    s = RunInBackground(bv, addr, "Removing Control Flow Flattening", DeFlattenCFG)
    s.start()


# I have no idea how to make a dropdown, so we'll just have these separate things for now
PluginCommand.register_for_address("Deobfuscate (OLLVM)",
                                   "Remove Control Flow Flattening given switch variable",
                                   DeFlattenBackgrounder)
