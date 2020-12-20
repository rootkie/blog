---
title: "Windows Process notes"
date: 2020-12-20T17:18:22+08:00
draft: false
categories: ["notes"]
---
# Introduction

This is notes I have taken down while reading the Windows Internals 7th edition chapter 3.

The structure of the notes largely follows the book. It's not very well organised as it is done during the reading. Will revisit this later.

# Processes and Threads

To understand this post, we need to understand the difference between a process and a thread.

Process is a container for a set of resources for the programs to execute. Threads are entities that Windows schedules to execute a program.

| Process contains:                   | Threads contains:                    |
| ----------------------------------- | ------------------------------------ |
| Private virtual address space       | CPU register information             |
| Executable program. (.text section) | Two stacks (kernel-mode / user-mode) |
| List of open handles                | Thread-local storage                 |
| Security Context (access token)     | Thread ID                            |
| Process ID                          | Might have its own security context  |
| Threads of execution                |                                      |

All these information are contained in the EPROCESS and ETHREAD data structure which will be explored later

# Processes

## Creating a process

There are many different API for creating process

| API                     | What it does                                                 |
| ----------------------- | ------------------------------------------------------------ |
| CreateProcess           | Create a process with the same access token as the creating process |
| CreateProcessAsUser     | Takes in handle to a token object as an additional argument  |
| CreateProcessWithTokenW | Similar to CreateProcessAsUser but requires different privilege |
| CreateProcessWithLogonW | Log on with a given user credential and create process with obtained token |

Both `CreateProcessWithTokenW` and `CreateProcessWithLogonW` will make a RPC to Secondary Logon service (seclogon.dll) in SvcHost.exe to do the process creation. `runas` command in CMD uses these functions.

These functions only can run proper PE file, batch file, or 16-bit COM applications. Need to use `ShellExecute` and `ShellExecuteEx` for other file types like .txt where Windows will use registry settings to determine which executable to run files of these extensions.

All functions to create process lead to **CreateProcessInternal**. After some setup, it will call **NtCreateUserProcess** in Ntdll.dll which calls the **NtCreateUserProcess**  in the kernel Executive.

For API specifications, refer to MSDN [here](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw).

The aforementioned functions are for creating classic Windows application. However, native images cannot be created using those methods as **CreateProcessInternal** will reject Native Image type. Ntdll.dll provides **RtlCreateUserProcess** as a wrapper around **NtCreateUserProcess** to create native image processes. (Smss.exe and Csrss.exe) This is necessary because when some native images are launched, the Windows API is not ready to provide **CreateProcess*** API yet.

Kernel processes are created by **NtCreateProcessEx** system call.

Regardless of user process or kernel process, they all end up calling **PspAllocateProcess** and **PspInsertProcess**

## Process Internals

### EPROCESS / KPROCESS

Process is encapsulated as a **EPROCESS** Data structure. It is an opaque kernel data structure so it is not available on MSDN. However, Nirsoft [here](https://www.nirsoft.net/kernel_struct/vista/EPROCESS.html) contains some decent information on how it looks like. Or use `dt nt!_EPROCESS` in windbg for more updated symbols.

I will only take down notes on a few key components of **EPROCESS** since it is really massive and there are a lot of attributes that are self-explanatory.

Note that **EPROCESS** and most of its related data structures exist in system address space. One exception is Process Environment Block (**PEB**), which exists in the process (user) address space.

Generally, the data structure follows the layering principle of the system architecture. Kernel functions (dispatcher, scheduler and etc) use **KPROCESS**, Executive functions (SRM and etc) use **EPROCESS**. This prevents unwanted dependencies between layers.

Useful commands to investigate the internal structures in windbg:

```text
dt nt!_EPROCESS
dt nt!_KPROCESS
dt nt!_EPROCESS <field>
dt nt!_EPROCESS <field>. // expand the structure of <field>. E.g dt nt!_EPROCESS Pcb. == dt nt!_KPROCESS
!process 0 0 // gets the address of all EPROCESS structures in the system
```

### PEB

PEB is in user-mode address space. It contains information used by the image loader, the heap manager, and other Windows components that need to access it from user mode. This prevents expensive thread context switching to obtain information from the kernel-mode EPROCESS structure. This also means that PEB only makes sense in the context of its process. Since each user-mode process has its own private virtual address space unlike kernel-mode where they share a single address space.

```text
// from kernel debugger
.process /P <target process context address> // switch to target process context
!peb // resolve PEB and see content in current context
dt nt!_PEB // view PEB structure


r $peb  //Dump address of PEB. $peb == pseudo-register
dt nt!_PEB @$peb //Dump PEB of current process
```

### CSR_PROCESS

For each process that is executing a Windows Program, **Csrss** maintains a parallel structure called the **CSR_PROCESS**.

Only Windows applications have a CSR_PROCESS. services does not. E.g(Smss.exe does not have CSR_PROCESS structure). It is managed by Csrss process.

![image-20201203151328239](../img/csr_process.png)

Since CSR_PROCESS only exist in Csrss process and we can't attach to Csrss.exe from user-land debugger because it is a protected process, we can use the **/P** to switch to Csrss.exe from the kernel debugger.

### W32PROCESS

Kernel-mode part of the Windows subsystem (Win32k.sys) maintains a per-process data structure, **W32PROCESS**. They are created as soon as **User32.dll** is loaded which is usually triggered by **CreateWindow(Ex)** and **GetMessage.**

Since Win32k.sys uses DirectX-based hardware accelerated graphics, the GDI component causes DirectX Graphics Kernel (Dxgkrnl.sys) to initialize **DXGPROCESS**. It contains information for DirectX objects (surfaces, shaders, etc).

These data structures have no public available symbols. So I will just leave a snip of Windows internals image here.

![image-20201203152320381](../img/w32_process.png)

## Protected process

Usually, any process running with debug privilege (such as administrator account) can read / write arbitrary process memory, inject code, suspend and resume threads, and query information on other processes. This cannot be done on protected processes. 

This is introduced to ensure DRM processes cannot be easily broken by user-land debuggers.

Any process from image signed with Windows Media Certificate is able to spawn a protected process.

Protected process have a special bits set in their EPROCESS structure that modify the behavior of security-related routines. Only `PROCESS_QUERY/SET_LIMITED_INFORMATION`, `PROCESS_TERMINATE`, and `PROCESS_SUSPEND_RESUME` are granted.

### Bypass

Edit the EPROCESS of your debugger to make it a protected process. However, this can only be done by a rogue driver. Some protected processes will not work under debug mode which you need to run your kernel debugger.

### Protected Process Light (PPL)

PPL is an extension to the DRM focus Protected processes. There are different trust levels depending on the signer. Some PPLs are more protected than other PPLs. This trust level is determined by the protection flag in the EPROCESS structure. For details can read the [crowdstrike blog here](https://www.crowdstrike.com/blog/protected-processes-part-3-windows-pki-internals-signing-levels-scenarios-signers-root-keys/)

Windows extended Protected process to allow other developer with valid certificate to spawn protected process light. However they have to include an enhanced key usage (EKU) OIDs in the certificate to determine what level of PPL they are allowed to spawn.

PPLs images also have an limit on what DLLs they can load. This is to prevent malicious 3rd party DLL to be loaded to operate at PPL level.

## Minimal Process

Minimal processes are processes that do not have the mandatory process components such as PEB, threads and etc.

### Creation

Minimal processes are created by passing a specific flag to `NtCreateProcessEx`. A minimal process will be created with the following:

- User-mode address space, so no PEB and related structures
- NTDLL will not be mapped
- No section objects, meaning no executable image file is associated to its execution
- The minimal flag will be set in the EPROCESS flags. Threads will become minimal threads without TEB and user-mode stack

## Pico Process

Pico Process are minimal process that has a special component called Pico Provider. Pico Provider control Pico Process executions from an operating system perspective. Pico Provider can emulate another operating system and developer can add data structures of other operating system userland processes to Pico Process. This allows binaries from other operating systems to run in Pico Process as if it is running in the native operating system. This is how WSL 1 works.

A Pico Provider can be registered with `PsRegisterPicoProvider`. This API can only be called by core drivers signed with a Microsoft Signer Certificate and Windows Component EKU before other 3rd party drivers are loaded.

WSL core driver is Lxss.sys which loads the Pico Provider driver LxCore.sys.

When a Pico Provider calls the registration API, it receives a set of function pointers to do the following

1. Create / Terminate Pico Process
2. Create / Terminate Pico Thread
3. Suspend / Resume Pico Thread
4. Get / Set Context of a Pico Process
5. Get / Set Context of a Pico Thread
6. Get / Set CPU context of a Pico Thread
7. Change FS / GS segments of a Pico Thread

A provider needs to transfer a set of function pointers to the kernel. Callbacks whenever the Pico Process / Thread perform the following activities:

1. Pico thread makes a system call using SYSCALL instruction
2. Pico Thread raises an exception
3. There is a fault during a probe and lock operation on a memory descriptor list ([MDL](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/using-mdls))
4. Some caller requesting name of a Pico Process
5. Event Tracing for Windows ([ETW](https://docs.microsoft.com/en-us/windows/win32/etw/about-event-tracing)) is requesting the user-mode stack trace of a Pico Process.
6. When an application tries to open a handle to a Pico Process / Thread
7. When someone requests the termination of a Pico Process
8. When Pico Process / Thread terminates unexpectedly.

## Trustlets

Trustlets are regular PE files that runs in VTL 1. They run in user-mode but is isolated from regular user-mode and NT kernel in VTL 0. They use a special kernel and NTDLL equivalent. Trustlets must be launched by using specific process attribute when using **CreateProcess**.

Trustlets contains a PE section named `.tPolicy` with an exported global variable named `s_IumPolicyMetaData`. This serves as metadata for the Secure Kernel to implement policy settings around permitting VTL 0 access to the Trustlet. This policy metadata describes how "accessible" the Trustlet will be from VTL 0.

| Policy                              | Meaning                                                      | More Information                                             |
| ----------------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| ETW                                 | Enables or Disable ETW                                       |                                                              |
| Debug                               | Configures debugging                                         | Debug can be enabled at all times, only when SecureBoot is disabled, or using an on-demand challenge/response mechanism |
| Crash Dump                          | Enables or disables Crash Dump                               |                                                              |
| Crash Dump Key                      | Specifies Public Key for Encrypting Crash Dump               | Dumps can be submitted to Microsoft Product Team, which has the private key for decryption |
| Crash Dump GUID                     | Specifies identifier for crash dump key                      | This allows multiple keys to be used / identified by the product team |
| Parent Security Descriptor          | [SDDL](https://docs.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language) format | This is used to validate the owner/parent process is expected |
| Parent Security Descriptor Revision | [SDDL](https://docs.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language) format revision ID | This is used to validate the owner/parent process is expected |
| SVN                                 | Security version                                             | This is a unique number that can be used by the Trustlet (along its identity) when encrypting AES256/GCM messages. |
| Device ID                           | Secure device PCI identifier                                 | The Trustlet can only communicate with a Secure Device whose PCI ID matches |
| Capabilities                        | Enables powerful VTL 1 capabilities                          | This enables access to the Create Secure Section API, DMA and user-mode MMIO access to Secure Devices, and Secure Storage API |
| Scenario ID                         | Specifies the scenario ID for this binary                    | Encoded as a GUID, this must be specified by Trustlets when creating secure image sections to ensure it is for a known scenario. |

Based on Windows internals 7, there are 5 different Trustlets in Windows 10.

| Binary Name (Trustlet ID) | Description                                   | Policy Options                                               |
| ------------------------- | --------------------------------------------- | ------------------------------------------------------------ |
| Lsalso.exe (1)            | Credential and Key Guard Trustlet             | Allow ETW, Disable Debugging, Allow Encrypted Crash Dump     |
| Vmsp.exe (2)              | Secure Virtual Machine Worker (vTPM Trustlet) | Allow ETW, Disable Debugging, Disable Crash Dump, Enable Secure Storage Capability, Verify Parent Security Descriptor is 5-1-5-B3-0 (NT VIRTUAL MACHINE\Virtual Machines) |
| Unknown (3)               | vTPM Key Enrollment Trustlet                  | Unknown                                                      |
| Biolso.exe (4)            | Secure Biometric Trustlet                     | Allow ETW, Disable Debugging. Allow Encrypted Crash Dump     |
| Fsiso.exe (5)             | Secure Frame Server Trustlet                  | Disable ETW, Allow Debugging, Enable Create Secure Section Capability, Use Scenario ID. |

### Security Features

Trustlets are protected from VTL 0 (our usual environment) through a few ways. 

Firstly, Trustlets are isolated from VTL 0 applications. Depending on the policy settings, some Trustlets cannot be debugged from VTL 0 debuggers. They do not share the same library or kernel as the rest of the VTL 0 applications.

Secondly, Trustlets have limited number of Syscalls they can use. They cannot use Device I/O (files creation and etc), creation of other process or any sort of GUI API usage. Trustlets are the isolated back-end for their front-end counter part in VTL 0. They can only communicate through ALPC or exposed secure sections.

### Identifying Trustlet

Can identify a trustlet by looking at their EPROCESS Pcb.SecurePID field or ETHREAD Tcb.SecureThreadCookie field.

![image-20201209201234702](../img/identify_trustlet.png)

# Life of a process

This section is specific to process creation of a Windows Subsystem process (CSRSS).

![image-20201210111708534](../img/image-20201210111708534.png)

```C++
BOOL CreateProcessA(
  LPCSTR                lpApplicationName,
  LPSTR                 lpCommandLine,
  LPSECURITY_ATTRIBUTES lpProcessAttributes,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  BOOL                  bInheritHandles,
  DWORD                 dwCreationFlags,
  LPVOID                lpEnvironment,
  LPCSTR                lpCurrentDirectory,
  LPSTARTUPINFOA        lpStartupInfo,
  LPPROCESS_INFORMATION lpProcessInformation
);
```



The flow:

1. `CreateProcessInternalW` convert and validate parameters and flags, once done, calls `NtCreateUserProcess`
2. Loads image files
3. `NtCreateUserProcess` validates arguments, then does the following through `PspAllocateProcess`
   1. Sets up EPROCESS
   2. Creating initial process address space
   3. Sets up KPROCESS (`KeInitializeProcess`)
   4. Finalize process address space (`MmInitiliazeProcessAddressSpace`)
   5. Sets up PEB (`MmCreatePeb`) and maps NTDLL to process memory
   6. Complete setup of the executive process object (`PspInsertProcess`)
4. Create initial thread and its stack and context (`PspCreateThread` uses `PspAllocateThread` and `PspInsertThread`)
5. `NtCreateUserProcess` completes, back into `CreateProcessInternalW` which sets up the Windows Subsystem stuff like CSR_PROCESS.
6. Start execution on the initial thread
7. Perform process initialization in the context of new process

The detailed process is very well explained by this blog post [here](https://medium.com/@Achilles8284/the-birth-of-a-process-part-2-97c6fb9c42a2). I will not go into too much details as this post is getting very long.



# Image Loading

While the above process details how Windows kernel prepares the environment and context for the execution of an image file, it does not result in the execution of an application. There is a crucial step in the process of executing an application, that is to load the application image. The image loader resides in NTDLL and its functions are prefixed with `Ldr`.

Loader's main functions include:

1. Creating the initial heap, setting up the thread-local storage and fiber-local storage
2. Parsing the import table (IAT) and load the DLLs
3. Loading and unloading DLL at run time
4. Handling manifest file for Windows Side-by-Side (SxS) support as well as Multiple Language User Interface (MUI) files and resources
5. Enabling support for API Sets and API redirection for UWP applications
6. Shim engine loading if needed

Loader is usually invisible to users and developers since it runs before the main application code most of the time.

In newer version of Windows, loader builds a dependency map of DLLs from all the IATs and try to load various DLL in parallel. The loaded DLLs or known as modules are maintained by the loader. This information is stored in PEB in a sub-structure PEB_LDR_DATA.



## DLL name resolution and redirection

By default, the order of directory Windows look for DLL is as follows:

1. Directory where application is launched
2. System32 folder
3. System folder
4. C:\Windows
5. Current directory at application launch time
6. Directories in %PATH%

There are ways to change the ordering but it is out of scope for this post. 

## Post-Import process initialization

After all the DLLs are loaded using the IAT, DLLMain routine is called for all DLL to initialize all the DLLs. If the image uses any TLS slots, TLS initializers gets called. 

# API Sets

To prevent having a large multi purpose DLL with thousands of API that most would not use, Windows now breaks some DLLs like Kernel32.dll into multiple virtual DLL files. For Kernel32.dll, it imports many other DLLs prefixed with API-MS-WIN. All these virtual DLLs make up the entire API interface of Kernel32.dll.

This allows application to link only the API libraries that provide the functionality they need. The mapping of virtual DLL to logical DLLs are stored in System32\ApiSetSchema.dll section .apiset.

# Server Silos

Basically lightweight windows containers that can only be created by a client on a Windows Server system. The details of this is not very important to me at the moment because most of my reverse engineering is done on Windows PC and not Server applications. I might cover this more in depth in the future in a separate post if necessary.

# Conclusion

This chapter is packed with information. Together with holiday procrastinations, it took a long time to finish the notes on this one. I have chosen to skim through large chunks of information on jobs, image loading and stuff. I feel like they are either not very important since it is something that I don't really work with or they are better understood using projects. The theory aspect of them is too detailed and the lack of abstraction make it really hard to understand from a high level perspective. I may write a post on IAT hooking or DLL injection in the future to further explain some of the concepts here.

I guess I will end this chapter here and review them in the future.
