# angr Basics for Ragequit

This document covers a small subset of **angr** functionality which is needed for solving the **ragequit** challenge.

## Getting Started

**angr** is a Python library, you should therefore understand some basic Python concepts to work with it; more than basic Python should not be needed to work with **angr**. To install **angr**, it is recommended to use a Python virtual environment and install it via pip:

```sh
$ virtualenv -p /usr/bin/python3 venv
$ source venv/bin/activate
$ pip install angr
```

If you don't want a virtualenv, you can always install **angr** globally and just run the pip command. Our template solution works with python3 and uses **angr** from pip with the version 8.18.10.25. Once you installed **angr**, you are ready to go. You can start an **angr** project with the following lines of code:

```python
import angr
proj = angr.Project('./ragequit', auto_load_libs=False)
```

Setting the *auto_load_libs* keyword to *False* ensures that shared libraries aren't loaded automatically on project creation, which would most definitely cause a severe impact on **angr**'s analysis speed.

**Optional:** When you set up Python and entered a virtualenv, it might be useful to have **IPython** available. **IPython** is an improved Python shell, making live-coding Python easier, not having to save it into a file and execute it everytime. This is especially useful when you want to use **angr** for exploration (or angr runs into issues and you have to debug). When you are done, you can use the *%history* command to print everything you've just typed into **IPython**. This is how you set it up:

```sh
$ pip install ipykernel
$ alias ipy="python -c 'import IPython; IPython.terminal.ipapp.launch_new_instance()'"
$ ipy
``` 

## Basic Exploration

Lets start with the following C program as first example:

```c
// Compile with: gcc -no-pie -O0 ex1.c -o ex1
#include <stdio.h>
#include <stdlib.h>

void target_func(const char *input) {
    printf("%s\n", input);
}

int main(int argc, char **argv) {
    target_func("EXAMPLE1_STRING");
    
    return EXIT_SUCCESS;
}
```

Now, without disassembling the program first, we want to find the address of *target_func*. Conveniently, this function prints the string **EXAMPLE1_STRING**, so we can tell **angr** that we want to look for exactly this string in the standard output and give us the execution state at the time of the output. For this we need a predicate function taking an **angr** execution state and returning True or False depending on whether our target state has been found or not. For this example, it can look like this:

```python
def ex1_string_found(state):
    return b"EXAMPLE1_STRING" in state.posix.dumps(1)
```

We'll cover the **state** object in a bit more detail later, but for now, all we need to know is that ```state.posix.dumps(1)``` corresponds to the standard output at the current execution state. Now we need to tell angr that we want to look for a state fullfilling the function we just defined:

```python
proj = angr.Project('./ex1', auto_load_libs=False)
simulation_manager = proj.factory.simgr()
simulation_manager.explore(find=ex1_string_found)
print(simulation_manager)
```

You should now get a printout saying ```<SimulationManager with 1 found>```, meaning we have found exactly one state fullfilling our predicate. We can retrieve this state by accessing ```simulation_manager.found[0]``` and get more information out of it. What we wanted to know is the address of *target_func* and we can use the ```callstack``` attribute for this. ```callstack``` gives you the top of the call stack for the current state, if you want to get information about the whole stack frame, you can iterate through the callstack by using ```callstack.next```, which is again a callstack object. To find the address of the current function, use this:

```python
state = simulation_manager.found[0]
address = state.callstack.func_addr
print(hex(address))
```

Now you can load the ex1 binary into IDA or radare2 and look up the *target_func*, which should have the same address that was just printed. **NOTE:** If you're wondering why we got the callstack of *target_func* and not *printf* (theoretically, the **EXAMPLE1_STRING** should have been printed to stdout somewhere inside of *printf* or another function) its because **angr** actually used a proxy function to deal with printf, in order to give us better results (and make the symbolic execution easier).

## States and Exploration

Now that was a first quick example, but what exactly is happening in there? **angr** notion of symbolic execution is mostly defined by execution **states**, where a state has everything needed to describe the current execution frame, most importantly: values of the registers it uses, values of memory it uses, callstack, current execution address. There is more than that, but those are the attributes needed to solve **ragequit**. Now, when you start using **angr**, you first create a *project* object. How do you go from a *project* to a *state*? With factories:

```python
state = proj.factory.entry_state()
```

This line of code creates an execution state which starts at the entrypoint of a program. To perform one step of symbolic execution, you can call the ```step()``` function on the state attribute:

```python
successor = state.step()
```

If you call ```step()``` you don't immediately get the next step, but a tuple of successors. The reason for this is pretty straightforward: If the program branches on a simple if condition, you won't get one, but two possible states. You could now potentially implement a loop or your own strategy on how to explore your program with these states, but **angr** already has several techniques for default cases. These techniques are being run by the simulation manager:

```python
# Create a new simulation manager starting with an entry_state
simulation_manager = proj.factory.simgr()

# Create a new simulation manager based on a pre-existing state
simulation_manager = proj.factory.simgr(state)
```

**IMPORTANT**: Creating a simulation manager based on a pre-existing state is vital for solving **ragequit**, since **ragequit** does not take any input directly from its user. You can use the simulation_manager with the entry_state for exploring the binary for simple strings, but in order to solve the payment reference generation, you'll have to construct a state calling the payment reference generation function. You can do this the following way:

```python
state = proj.factory.call_state(function_address, function_param1, function_param2, ...);
```

After you've constructed your state and your simulation manager you can use the ```explore()``` function, shown in the first section, to let the simulation manager find your target state. The ```explore()``` function has two parameters: **find** and **avoid**. You can use *avoid* to tell **angr** which states to avoid, but the challenge is solvable without using this, so we'll concentrate on *find*. Long story short: *find* can either take a predicate function, as shown in the first section, or an address in the program you're trying to reach. For example, we can take the address found in the last example of the first section and construct a new simulation manager looking directly for this address:

```
state = simulation_manager.found[0]
address = state.callstack.func_addr

simulation_manager = proj.factory.simgr()
simulation_manager.explore(find=address)
print(simulation_manager)
```

## Reading and Writing Memory

Reading and writing memory works with the ```mem``` attribute of an execution state. In pseudocode, this approximately looks like this, where we swap ADDRESS by the address we want to read and DATATYPE by the type of data we want to treat the memory as:

```python
data = state.mem[ADDRESS].DATATYPE
```

Usually, the DATATYPE corresponds to the length of the data type we want to read, e.g. ```byte```, ```word```, ```dword```, ```qword```. If you want to read an array of some type, it is more straightforward to just read each element of this type in a loop. The syntax works the same if you want to write to a memory address. Lets say you want to replace a byte at address 0x1234, you can do so with the following code:

```python
state.mem[0x1234].byte = 0x41
``` 

Besides reading/writing memory, you can do the same for registers, which are accessed through the ```regs``` attribute. You can access the usual x86-64 registers, e.g. finding the value of the second argument of a function call:

```python
simgr = proj.factory.simgr()
simgr.explore(find=FUNCTION_ADDRESS)
second_arg = simgr.found[0].regs.rsi
```

If you combine ```mem``` and ```regs``` you can do nifty stuff, like accessing local variables. This is helpful, since if we want to retrieve a function argument and explore by string, by the time printf is called, the arguments won't be in ```rdi```, ```rsi```, etc. anymore. Disassemblers (radare2 and IDA at least) give you the address of a local variable relative to the stack frame, and you can just copy and paste this into your Python script:

```python
simgr.explore(find=lambda s: b"Payment reference:" in s.posix.dumps(1))
s = simgr.found[0]
var = s.mem[s.regs.rbp - 0x18].qword.resolved;
```

If you access the memory via ```mem``` it still carries some information for symbolic execution and if you do ```s.mem[s.mem[s.regs.rbp - 0x18].qword]``` you'll probably get an error. This is why we added the ```.resolved``` after the qword, getting rid of the symbolic information and retrieving the actual value.

## Constraint Solving

Now we've reached the part where we combine everything up until now and use **angr** to specify actual constraints and solve them. One additional thing we need to know is that **angr** internally does not have a concept of integers or addresses, but works with bitvectors with a certain size. If you have a ```byte``` that gives you a bitvector with length 8; so far so good. However, instead of having a bitvector with a concrete value, a ```BVV```, you can also introduce a symbol with a specified length and name, but no actual value, a ```BVS```. (*Sidenote*: It appears the name of a variable doesn't actually matter at all and is probably only used for pretty-printing). If you have a state, you can create a symbolic variable like this:

```python
symbolic_byte = state.solver.BVS('x', 8)
```

If we want to create an array of symbolic values, e.g. symbolic bytes of a key, we can just create symbolic variables in a loop. You can also assign symbolic variables to memory addresses directly, so if the key is stored in a buffer, we can just do this:

```python
for i in range(KEY_LENGTH):
    state.mem[key_addr+i:].byte = state.solver.BVS('key', 8)
``` 

The workflow for constraint solving is usually ordered this way:

1. Set up state/call_state
2. Declare symbolic variables
3. Use a simulation manager to explore/reach the target state
4. Add constraints
5. Solve for the constraints

Since we set up our symbolic variables (and presumably reached our target state), we can now set the constraints for our solution. In the case of **ragequit** we receive some kind of payment reference that is printed to stdout. This doesn't map directly to **ragequit**, but we assume that the output we want to use as constraint is also loaded into a buffer and we can then do this:

```python
state = simgr.found[0]
for i in range(BUFF_SIZE):
    b = state.memory.load(BUFF_ADDRESS + i, 1)
    state.add_constraints(b == TARGET_VALUES[i])
```

After this, we leave it to **angr** to do the work for us. The only thing left we need to specify is what we actually want to evaluate. And what we want to evaluate is the key we don't know:

```python
keyvar = state.memory.load(key_addr, KEY_LENGTH)
key_bytes = state.solver.eval(keyvar, cast_to=bytes)
```

## Specific Example

Now lets have a look at a specific example. Here's a program which is a very simplified version of **ragequit**:

```c
// Compile with: gcc -no-pie -O0 ex2.c -o ex2
#include <stdio.h>
#include <stdlib.h>

const char *SECRET = "THE_SECRET_WAS_HERE";

void print_scrambled(const unsigned char *scrambled) {
    puts("Scrambled secret is:");
    for (int i = 0; i < 19; i++)
        printf("%02x", scrambled[i]);
    puts("");
}

void crack_me(const char *flag) {
    unsigned char scramble_buffer[19];

    // Welcome message, so we can find the function per string
    puts("Welcome!");

    // Just shuffle the characters randomly
    scramble_buffer[ 0] = SECRET[10];
    scramble_buffer[ 1] = SECRET[ 4];
    scramble_buffer[ 2] = SECRET[15];
    scramble_buffer[ 3] = SECRET[14];
    scramble_buffer[ 4] = SECRET[12];
    scramble_buffer[ 5] = SECRET[ 1];
    scramble_buffer[ 6] = SECRET[18];
    scramble_buffer[ 7] = SECRET[ 6];
    scramble_buffer[ 8] = SECRET[ 7];
    scramble_buffer[ 9] = SECRET[11];
    scramble_buffer[10] = SECRET[ 3];
    scramble_buffer[11] = SECRET[16];
    scramble_buffer[12] = SECRET[ 8];
    scramble_buffer[13] = SECRET[ 5];
    scramble_buffer[14] = SECRET[ 0];
    scramble_buffer[15] = SECRET[13];
    scramble_buffer[16] = SECRET[17];
    scramble_buffer[17] = SECRET[ 2];
    scramble_buffer[18] = SECRET[ 9];

    // XOR each character with the last one
    for (int i = 1; i < 19; i++)
        scramble_buffer[i] ^= scramble_buffer[i - 1];

    // Print the scrambled result
    print_scrambled(scramble_buffer);
}

int main(int argc, char **argv) { 
    crack_me(SECRET);
    return EXIT_SUCCESS;
}
```

And this is the output it produced when it was executed with the real secret:

```
Welcome!
Scrambled secret is:
4512571a5d12337d227d22035718410021743c
```

Now you can easily reverse this program by hand, but this should only serve as a basic example of the concepts described in the previous sections. The following will be a step-by-step guide on how you can approach solving this example (and how you can approach solving **ragequit**, since the programs are similiar). The full code is available in the *tutorials* folder as *ex2.py*. Let's start with creating an angr project:

```python
import angr

proj = angr.Project('./ex2', auto_load_libs=False)
```

So first thing we want to do is find the address of the crackme function. Conveniently, this function prints the string "Welcome!" so we can just explore for this string:

```python
# Creating a simulation manager and explore for the "Welcome!" string.
# Instead of creating a find function, we can just use a lambda function.
# Hint: ragequit's equivalent to "Welcome!" is "SUPER ENCRYPTED FILE BACKUP"
simgr = proj.factory.simgr()
simgr.explore(find=lambda s: b"Welcome!" in s.posix.dumps(1))

# We take the state we found and get the address of the current function,
# which is crackme(const char *).
state = simgr.found[0]
crackme_addr = state.callstack.func_addr
```

If we used a disassembler and checked which local variable the function argument was stored in, we could extract the address to the function argument from this state as well. We're too lazy to disassemble the program for now and just use another exploration to jump to the beginning of the ```crackme``` function. Then we can extract the argument, the pointer to the memory where the secret is stored, from ```rdi``` (check the Linux amd64 calling conventions for reference):

```python
# Use a simulation manager to directly find the address of crackme(const char *).
simgr = proj.factory.simgr()
simgr.explore(find=crackme_addr)

# Retrieve the value of the first argument, which is the address of the secret
state = simgr.found[0]
secret_addr = state.regs.rdi
```

We now know the address of ```crackme``` as well as the parameter we need to pass in. This is enough for us to construct a ```call_state``` which we can use as a starting point when creating new simulation managers. This way, we won't have to start over from the beginning of the program, but can start directly with the function call. (*Sidenote*: technically we should be able to use the state we just found (at the beginning of ```crackme```) for this exact purpose, however it's good to know how we can construct an explicit call state). Constructing the ```call_state``` looks like this:

```python
cstate = proj.factory.call_state(crackme_addr, secret_addr)
```

This gives us the starting state for our simulation, but what do we use as the target state? Well, we can start from ```cstate```, which we just constructed, and explore till we find ```print_scrambled```. This is basically just rinse and repeat of the commands we used to find ```crackme``` and its argument, but this time we start from ```cstate``` instead of the program entry point:

```python
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
```

Now we have everything we need to set up our symbolic variables, constraints and solve for the secret. First, create symbolic variables for each character of the secret in the memory of the call state:

```python
# The secret is 19 characters long, each character/byte gets its own
# symbolic variable
for i in range(19):
    cstate.mem[secret_addr + i].byte = cstate.solver.BVS('key', 8)
```

Next, explore the simulation till we reached our target state:

```python
# Go to print_scrambled
simgr = proj.factory.simgr(cstate)
simgr.explore(find=print_addr)

# Store target state
target_state = simgr.found[0]
```

Next, add the constraints to the target state. We want the output of ```print_scrambled``` to produce the same output as if it would be using the real secret, i.e. *4512571a5d12337d227d22035718410021743c*. We therefore add a constraint for every byte of
the output:

```python
# Convert the input to bytes and constrain the actual bytes of the
# buffer to be equal to the bytes from the output
target_bytes = bytes.fromhex("4512571a5d12337d227d22035718410021743c")
for i in range(19):
    buffer_byte = target_state.memory.load(scrambled_addr + i, 1)
    target_byte = target_bytes[i];
    target_state.add_constraints(buffer_byte == target_byte)
```

And in the final step, we solve for the secret:

```python
# Load all the secret bytes into a variable
secret = target_state.memory.load(secret_addr, 19)
print(target_state.solver.eval(secret, cast_to=bytes))
```

## Hints for ragequit

The basic structure of **ragequit** is relatively close to the example. To sketch the basic control flow:

```c
int main(int argc, char **argv) {
    // Print 'SUPER ENCRYPTED FILE BACKUP' header
    crackme(0, key);

    // Do weird encryption stuff
    // ...

    // Do the actual scrambling
    crackme(1, key);
}
```

It also has its own equivalent of the ```print_scrambled``` function, i.e. where the "Payment reference" is printed.