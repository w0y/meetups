#!/usr/bin/env python3
import angr

def ex1_string_found(state):
    return b"EXAMPLE1_STRING" in state.posix.dumps(1)

proj = angr.Project('./ex1', auto_load_libs=False)
simulation_manager = proj.factory.simgr()
simulation_manager.explore(find=ex1_string_found)
print(simulation_manager)

state = simulation_manager.found[0]
address = state.callstack.func_addr
print(hex(address))

simulation_manager = proj.factory.simgr()
simulation_manager.explore(find=address)
print(simulation_manager)