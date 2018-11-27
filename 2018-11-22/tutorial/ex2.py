#!/usr/bin/env python3
import angr

proj = angr.Project('./ex2', auto_load_libs=False)

# Creating a simulation manager and explore for the "Welcome!" string.
# Instead of creating a find function, we can just use a lambda function.
# Hint: ragequit's equivalent to "Welcome!" is "SUPER ENCRYPTED FILE BACKUP"
simgr = proj.factory.simgr()
simgr.explore(find=lambda s: b"Welcome!" in s.posix.dumps(1))

# We take the state we found and get the address of the current function,
# which is crackme(const char *).
state = simgr.found[0]
crackme_addr = state.callstack.func_addr

# Use a simulation manager to directly find the address of crackme(const char *).
simgr = proj.factory.simgr()
simgr.explore(find=crackme_addr)

# Retrieve the value of the first argument, which is the address of the secret
state = simgr.found[0]
secret_addr = state.regs.rdi

# Construct a call state at the crackme address
cstate = proj.factory.call_state(crackme_addr, secret_addr)

# Creating a simulation manager and explore for the "Scrambled secret is:" string.
# Hint: ragequit's equivalent would be "Payment reference:"
# Also: note that we are now using cstate to initialize a simulation manager
simgr = proj.factory.simgr(cstate)
simgr.explore(find=lambda s: b"Scrambled secret is:" in s.posix.dumps(1))

# We take the state we found and get the address of the current function,
# which is print_scrambled(const unsigned char *).
state = simgr.found[0]
print_addr = state.callstack.func_addr

# Use a simulation manager to directly find the address
# of print_scrambled(const unsigned char *).
simgr = proj.factory.simgr(cstate)
simgr.explore(find=print_addr)

# Retrieve the value of the first argument, which is the address of
# the scrambling buffer
state = simgr.found[0]
scrambled_addr = state.regs.rdi

# The secret is 19 characters long, each character/byte gets its own
# symbolic variable
for i in range(19):
    cstate.mem[secret_addr + i].byte = cstate.solver.BVS('key', 8)

# Go to print_scrambled
simgr = proj.factory.simgr(cstate)
simgr.explore(find=print_addr)

# Store target state
target_state = simgr.found[0]

# Convert the input to bytes and constrain the actual bytes of the
# buffer to be equal to the bytes from the output
target_bytes = bytes.fromhex("4512571a5d12337d227d22035718410021743c")
for i in range(19):
    buffer_byte = target_state.memory.load(scrambled_addr + i, 1)
    target_byte = target_bytes[i];
    target_state.add_constraints(buffer_byte == target_byte)

# Load all the secret bytes into a variable
secret = target_state.memory.load(secret_addr, 19)
print(target_state.solver.eval(secret, cast_to=bytes))
