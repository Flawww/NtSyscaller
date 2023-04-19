# Manual Syscalls
NtSyscaller allows you to directly perform syscalls on windows without going through any API or external linked library. The reason why someone would want to do this is security. Going through the normal API's, or even directly calling the syscall-functions in `ntdll.dll` allows an adversary to intercept the syscall and either log the syscall, or worse (ie. modify inputs, block the call, or fabricate fake results). Both x64 and x86 is supported, but please refer to the end of the readme for a caveat of the x86 support.

By manually making these syscalls we can protect ourself against this. The way a syscall works is by writing the syscall number the the `eax` register, and then doing the actual syscall, which is implemented a special interrupt. This is something we can do ourselves, without having to go through `ntdll.dll`. 

## Requirements
To run the library you need the `fnv1a.h`, `NtSyscaller.cpp`, and `NtSyscaller.h` files. Works for any compiler with support for C++14 or later.

## How to use
Call the function `syscall` from a NtSyscaller object. The first argument is the hash value of the name of the wanted syscall, hashed with FNV1a, here I highly recommend a compile-time FNV1a implementation like in the included `fnv1a.h` file. The rest of the arguments are the actual arguments for the syscall. For the syscall arguments you need to be very type-concious, as wrong types **can cause stack corruption and undefined behaviour (!)**.

The function `NtSyscaller::print_syscalls` can be used to display the syscall number, name, and RVA for all available syscalls.

### Example
In this example, we allocate memory with the [ZwAllocateVirtualMemory](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwallocatevirtualmemory) syscall.
```c++
    NtSyscaller syscall_factory;

    uintptr_t addr = 0;
    size_t size = 0x42;
    int ret = syscall_factory.syscall(FNV1A("ZwAllocateVirtualMemory"), HANDLE(-1), &addr, ULONG_PTR(0), &size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

```

## x86 caveat
Despite that this library does have x86 support, the safety of the x86 mode is currently lacking because it it still hookable in x64 memory space or simply patching the shellcode which performs the segment switch to x64 mode.

Full support for x86 would mean generating x64 shellcode to fix the arguments for the real syscall, and manually perform the syscall like we currently already do for x64, and also manually performing the segment switch to x64 from x86 (and back to x86 again). This is doable, but far from trivial. I will add support for this in the future if the time and motivation can be found. 