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

# Reading and Writing Memory

Reading and writing memory works with the ```mem``` attribute of an execution state. In pseudocode, this approximately looks like this, where we swap ADDRESS by the address we want to read and DATATYPE by the type of data we want to treat the memory as:

```python
data = state.mem[ADDRESS].DATATYPE
```

Usually, the DATATYPE corresponds to the length of the data type we want to read, e.g. ```byte```, ```word```, ```dword```, ```qword```. If you want to read an array of some type, it is more straightforward to just read each element of this type in a loop. The syntax works the same if you want to write to a memory address. Lets say you want to replace a byte at address 0x1234, you can do so with the following code:

```python
state.mem[0x1234].byte = 0x41
``` 

