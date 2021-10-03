---
title: "Windows System Architecture notes"
date: 2020-12-03T10:17:28+08:00
draft: false
categories: ["notes"]
---
# Introduction

This is notes I have taken down while reading the Windows Internals 7th edition chapter 2. I have also referenced many other blogs and documents such as http://www.cs.sjtu.edu.cn/~kzhu/cs490/3/3_Win-Structuring.pdf

The structure of the notes largely follows the book. It's not very well organised as it is done during the reading. Will revisit this later.

# System Architecture

Windows separate running application from OS itself. It has many layers of abstractions to ensure portability. Windows abstracts away differences in hardware and subsystems by having a common interface at different layers. Each layer's implementation handles the complexity and exposes a common interface that layers above it can build upon.

Windows is symmetric multiprocessing OS. OS and Userland can use any processors. All processors share a single memory space.

![image-20201201131859244](../img/windows_architecture.png)

# Virtualization-based security architecture

![image-20201201131930544](../img/VTL.png)

When booting, hypervisor is first system component to be launched by the boot loader, it can program the SLAT (Second Layer Address Translation, a CPU feature) and I/O MMU as it sees fit, defining the VTL (Virtual Trust Level) 0 and 1 execution environment. Then, while in the VTL 1, the boot loader runs again, loading the secure kernel (securekernel.exe), which can configure the system further to its needs. Only then is the VTL dropped, which will see the execution of the normal kernel, now living in its VTL 0 jail, unable to escape.

Only Microsoft **trustlets** can be ran in VTL 1. Secure Kernel has a list of signed trustlets that can be ran. Anything in VTL 1 is isolated from VTL 0. VTL 0 uses ntdll.dll to access kernel (ntoskrnl.exe) while VTL 1 uses Iumdll.dll. E.g. Credential Guard is a trustlet.

This is to enforce isolation. Kernel code from VTL 0 cannot touch User-Mode code in VTL 1. But the user-mode code can use syscalls to access kernel resources.

VTL 1 can use the hypervisor to limit VTL 0 OS access to certain memory region by using SLAT. This is the basis of Credential Guard. Securely storing information in a memory region that VTL 0 cannot access.

# Windows subsystem DLL List

Reference from: https://en.wikipedia.org/wiki/Microsoft_Windows_library_files

| Internal DLL | Purpose                                                      |
| ------------ | ------------------------------------------------------------ |
| ntdll.dll    | NTDLL.DLL exports the Windows Native API. The Native API is the interface used by user-mode components of the operating system that must run without support from [Win32](https://en.wikipedia.org/wiki/Win32) or other API subsystems. |
| hal.dll      | The Windows [Hardware Abstraction Layer](https://en.wikipedia.org/wiki/Hardware_Abstraction_Layer) (HAL) is implemented in **hal.dll**.[[1\]](https://en.wikipedia.org/wiki/Microsoft_Windows_library_files#cite_note-1) The HAL implements a number of functions that are implemented in  different ways by different hardware platforms, which in this context,  refers mostly to the [chipset](https://en.wikipedia.org/wiki/Chipset). Other components in the [operating system](https://en.wikipedia.org/wiki/Operating_system) can then call these functions in the same way on all platforms, without regard for the actual implementation. |

| Win 32 API   | Purpose                                                      |
| ------------ | ------------------------------------------------------------ |
| KERNEL32.DLL | KERNEL32.DLL exposes to applications most of the Win32 base APIs, such as [memory management](https://en.wikipedia.org/wiki/Memory_management), [input/output (I/O)](https://en.wikipedia.org/wiki/Input/output) operations, [process](https://en.wikipedia.org/wiki/Process_(computing)) and [thread](https://en.wikipedia.org/wiki/Thread_(computing)) creation, and synchronization functions. Many of these are implemented  within KERNEL32.DLL by calling corresponding functions in the [native API](https://en.wikipedia.org/wiki/Native_API), exposed by NTDLL.DLL |
| GDI32.DLL    | GDI32.DLL exports [Graphics Device Interface (GDI)](https://en.wikipedia.org/wiki/Graphics_Device_Interface) functions that perform primitive drawing functions for output to video displays and printers |
| USER32.DLL   | **USER32.DLL** implements the Windows USER component that **creates and manipulates the standard elements of the Windows user interface**, such  as the desktop, windows, and menus. It thus enables programs to implement a [graphical user interface (GUI)](https://en.wikipedia.org/wiki/Graphical_user_interface) that matches the Windows look and feel. Programs call functions from  Windows USER to perform operations such as creating and managing  windows, receiving window messages (which are mostly user input such as  mouse and keyboard events, but also notifications from the operating  system), displaying text in a window, and displaying message boxes. |
| COMCTL32.DLL | **COMCTL32.DLL** implements a wide variety of standard **Windows  controls**, such as File Open, Save, and Save As dialogs, progress bars,  and list views. It calls functions from both USER32.DLL and GDI32.DLL to create and manage the windows for these UI elements, place various  graphic elements within them, and collect user input. |
| COMDLG32.DLL | **COMDLG32.DLL**, the Common Dialog Box Library, implements a wide  variety of **Windows dialog boxes** intended to perform what Microsoft deems 'common application tasks'. Starting with the release of Windows Vista, Microsoft considers the "Open" and "Save as" dialog boxes provided by  this library as deprecated and replaced by the 'Common Item Dialog API' |
| WS2_32.DLL   | **WS2_32.DLL** implements the [Winsock](https://en.wikipedia.org/wiki/Winsock) API, which provides TCP/IP networking functions and provides partial, broken compatibility with other network APIs. **wsock.dll** and **wsock32.dll** are older versions for Win3.11 and Win95 compatibility. |
| ADVAPI32.DLL | **ADVAPI32.DLL** provides security calls and functions for manipulating the [Windows Registry](https://en.wikipedia.org/wiki/Windows_Registry). |
| NETAPI32.DLL | **NETAPI32.DLL** provides functions for querying and managing network interfaces. |
| OLE32.DLL    | **OLE32.DLL** provides the [Component Object Model](https://en.wikipedia.org/wiki/Component_Object_Model), as well as [Object Linking and Embedding](https://en.wikipedia.org/wiki/Object_Linking_and_Embedding). |

# Subsystems

Windows subsystems are started by Session Manager (Smss.exe) process. 

## Windows Subsystems

### Csrss.exe

Windows susbsystem consists of the following major components:

- For each session, an instance of the environment subsystem process (Csrss.exe) loads four DLLs (Basesrv.dll, Winsrv.dll, Sxssrv.dll, and Csrsrv.dll) that contain support for the following:
  - Housekeeping tasks related to creating and deleting processes and threads
  - Shutting down Windows application (ExitWindowsEx API)
  - Containing .ini file to registry location mappings for backward compatibility.
  - Sending certain kernel notification message
  - Side-By-Side / Fusion and manifest cache support
  - natural language support functions, to provide caching
  - Might load Cdd.dll

| DLL         | Purpose                                                      |
| ----------- | ------------------------------------------------------------ |
| Basesrv.dll | Not sure                                                     |
| Winsrv.dll  | kernel mode code that handles the raw input thread and desktop thread (mouse cursor, keyboard input and handling of the desktop windows) |
| Cdd.dll     | Canonical Display Driver. Responsible for communicating with the DirectX support in the kernel on each vertical refresh (Vsync) to draw visible desktop state without traditional hardware-accelerated GDI support |

- Kernel-Mode device driver (Win32k.sys) that contains:
  - The window manager. Controls window displays; manages screen output; collects input from keyboard, mouse and other devices; and passes user messages to applications
  - Graphics Device Interface - A library of function for graphics output devices. Includes functions for line, text and figure drawing and for graphics manipulation
  - Wrapper for DirectX support that is implemented in another kernel driver (Dxgkrnl.sys)
- The console host process (conhost.exe)
- The Desktop Window Manager (Dwm.exe), compositing visible window rendering into a single surface through the CDD and DirectX
- Subsystem DLLS (e.g Kernel32.dll, Advapi.dll, User32.dll, Gdi32.dll)
- Graphics device drivers for hardware-dependent graphics display drivers, printer drivers, and video miniport drivers.

-----

Most GUI application call the standard USER functions to create UI. Window manager communicates these requests to GDI which passes them to graphics device drivers. GDI provides standard two-dimensional functions that let applications communicate with graphics devices without knowing anything about the devices.

### Conhost.exe

Console window host.

Before win 7: csrss.exe responsible for managing console windows and each console application

win 7:  conhost.exe is used. A single console window can be shared by multiple console applications. Conhost spawns child processes cmd.exe

win 8 and later: conhost.exe spawned from console-based process by the console driver (ConDrv.sys) by sending read, write, I/O control and other I/O request types. Cmd.exe spawns conhost.exe as child process.

Since win 8 and later, csrss.exe is no long needed for console applications. It doesn't need to receive keyboard input, send it through Win32k.sys to Conhost.exe, and then use ALPC to send it to Cmd.exe.

Conhost.exe is now designated as a server and the process using the console is the client. The client (console applications) directly receive input from the console driver through read/write I/Os, avoiding needless context switching.

The real workhorse of conhost.exe is the DLL it loads (\Windows\System32\ConhostV2.dll). This DLL includes the bulk of code that communicates with the console driver.

## Other Subsystem

### Pico provider

It is a custom kernel-mode driver that receives access to specialized kernel interfaces through the ` PsRegisterPicoProvider` API.

- The provider can create Pico processes and threads while **customizing their execution contexts, segments, and store data in their respective EPROCESS and ETHREAD structures.**
- The provider can **receive notifications whenever such processes or threads engage in certain system actions** such as system calls, exceptions, APCs, page faults, termination, context changes, suspension/resume, etc.

#### Pico Processes and WSL

Reference: https://article.itxueyuan.com/dE74L

![image-20201201131604903](../img/picoprocess.png)

In the view of applications running in pico process, the Pico Provider is the kernel interface. LXSS / LXCore are Pico Provider. They are components of WSL1.

Pico Processes allow Linux processes to be ran without recompiling the binary to a Windows PE file. Because you can implement your Pico Process as modified Linux Processes and let Pico Provider handles the Kernel Level emulations. However, this also means that Windows does not know how to map these binaries as they are not PE files, so they cannot be launched using CreateProcess API.

Creation of Pico Processes from usermode is handled by the LXSS Manager, which is a user-mode service. It has a COM-based interface to communicate with a specialised launcher process, **Bash.exe**, and with a management process, called **Lxrun.exe**.

In WSL, the Pico Provider basically wraps / reimplement hundreds of Linux Syscalls. The Pico Process talks to the Pico Provider as if it's the Linux Kernel.

## Native images

While Win32 applications mostly access Ntdll.dll function through its subsystem DLL such as Kernel32.dll, some applications have to be ran natively before Windows Subsystem (Csrss.exe) is executed. These applications link only to Ntdll.dll. They are called native images. An example would be Session Manager process (Smss.exe), it starts the Csrss.exe process.

# Kernel Mode Components

## Executive

![image-20201201143429830](../img/simplified_windows_architecture.png)

Executive is the upper layer for the Windows Kernel. It provides an interface to call functions from Ntoskrnl.exe and various device drivers. Basically anything you want to do with the kernel or device driver, you invoke an function from the executive layer. Such as Process Management, Memory Management, Power management and etc.

The executive layer is where most policy decision makings are made. Security Reference Monitor (SRM) resides here.

## Kernel

Kernel consists of a set of functions in Ntoskrnl.exe that provides fundamental OS mechanisms. They are used the by executive layer to perform tasks.

Kernel separates itself from the rest of the executive. It only implement OS mechanisms and avoid policy making. Only policy decisions made in the kernel are thread scheduling and dispatching.

Kernel has kernel Objects. These objects are encapsulated by various executive objects to represent threads and other shareable resources.

There are 2 sets of kernel objects

- Control objects: semantics for controlling various OS functions. E.g. `Asynchronous Procedure Call (APC)` object, the `Deferred Procedure Call (DPC)` object, and several objects the I/O manager uses, such as the `interrupt` object
- dispatcher objects: incorporation of synchronization capabilities. E.g kernel thread, mutex (mutant in kernel terminology), event, kernel event pair, semaphore, timer, and waitable timer.

Executive uses kernel functions to create instances of kernel objects and construct the more complex objects it provides to user mode.

### Kernel processor control region (KPCR) and control block

KPCR stores processor specific data. It contains information like

- Interrupt Dispatch Table (IDT)
- Task state segment (TSS)
- Global descriptor table (GDT)
- interrupt controller state (shared with other modules like the ACPI driver and the HAL)
- Control Block (KPRCB)

kernel stores a pointer to KPCR in the fs register on 32-bit Windows and gs register on an x64 Windows system.

KPRCB is a private structure used only by the kernel code in Ntoskrnl.exe. It contains the following

- Scheduling information such as current, next, idle threads scheduled
- The dispatcher database for the processors
- The Deferred Procedure Call queue
- CPU vendor and identifier information
- CPU and NUMA topology
- Cache sizes
- Time account information
- I/O statistics
- Cache Manager statistics
- DPC statistics
- Memory manager statistics

View these information using windbg kernel debugger.

```text
!pcr 0 // CPU 0 pcr
dt nt!_KPCR <pcr address>
```

![image-20201201162432988](../img/prcb_windbg.png)

## Hardware Abstraction Layer

A layer to isolate kernel and executive from the hardware specific implementations. Provide a common interface for various hardware. Implemented in Hal.dll which is a loadable kernel-mode module. Most of the HAL routines are documented in the WDK.

Because hardware can be very different and have missing / additional features, Windows now support modules known as **HAL extensions**, which are additional DLLs that bootloader may load if specific hardware requires them.

**HAL extensions** are created in collaboration with Microsoft because they need to be custom signed with a special HAL extension certificate.

## Summary

When user applications request / send stuff, Executive layer decides what to do, where to redirect the request or reject the requests. The kernel performs OS specific tasks when asked by the Executive, Device Driver perform their tasks in relation to their target device when asked by executive.

Ntoskrnl.exe contains both executive and the kernel layer.

# Drivers

## Device Drivers

They can be kernel-mode or user-mode. Here only talk about kernel-mode.

Device drivers are loadable kernel-mode modules (*.sys files). It is an interface between the I/O manager and the relevant hardware. They call on HAL routines to interface with the hardware.

| Type of device drivers          | Details                                                      |
| ------------------------------- | ------------------------------------------------------------ |
| Hardware device drivers         | Use HAL to manipulate hardware to write output or read input from physical device or network. |
| File system drivers             | Accept file-oriented I/O requests and translate them into I/O requests for a particular device |
| File system filter drivers      | Drivers that perform tasks on filesystem, processing I/O request before passing on to the next layer (file system drivers) |
| Network redirectors and servers | File system drivers that works on the network. transmit / receive FS I/O on network |
| Protocol drivers                | Implement networking protocol such as TCP/IP, NetBEUI, IPX/SPX |
| Kernel streaming filter drivers | chained together to perform signal processing on data streams. (recording or displaying audio and video) |
| Software drivers                | Applications that don't involve hardware but only can be done in kernel-mode, like reading / writing to kernel memory |

## Windows Driver Model

| Type of drivers  | Details                                                      |
| ---------------- | ------------------------------------------------------------ |
| Bus Drivers      | It services a bus controller, adapter, bridge, or any device that has child devices. (PCI, USB and etc) |
| Function Drivers | The main device driver. Provides the operational interface for its device. |
| Filter Drivers   | It adds functionality to a device or existing drivers, or to modify I/O requests or response from other drivers. Below a function driver but above a bus driver. |

## Windows Driver Foundation

While WDM is the OG driver development model for a long time, now we have 2 simpler framework. Kernel-Mode Driver Framework (KMDF) and User-Mode Driver Framework (UMDF). They provide simpler interface to WDM and hides the complexity. Drivers can call into KMDF library for work that isn't specific to the hardware they are managing, such as generic power management and synchronization which is previously implemented by each WDM driver itself.



# Windows System Routine Naming Convention

Reference: https://openwares.net/2009/08/24/system_routine_naming_convention/

\<Prefix\> \<Operation\> \<Object\>

**ExAllocatePoolWithTag:** executive support routine to allocate from paged or non-paged pool

**KeInitializeThread:** allocates and sets up a kernel thread object

Some routine might append **f** to the prefix to signal fastcall. E.g. **ObfReferenceObject**

| Prefix | Component                                                    |
| ------ | ------------------------------------------------------------ |
| Alpc   | Advanced Local Procedure Calls                               |
| Cc     | Common Cache                                                 |
| Cm     | Configuration Manager                                        |
| Dbg    | Kernel debug support                                         |
| Dbgk   | Debugging Framework for User-Mode                            |
| Em     | Errata Manager                                               |
| Etw    | Event Tracing for Windows                                    |
| Ex     | Executive support routines                                   |
| FsRtl  | File System Driver Run-Time Library                          |
| Hal    | Hardware abstraction layer                                   |
| Hvl    | Hypervisor Library                                           |
| Io     | I/O manager                                                  |
| Ke     | Kernel                                                       |
| Kd     | Kernel Debugger                                              |
| Ks     | Kernel Streaming                                             |
| Lsa    | Local Security Authority                                     |
| Mm     | Memory manager                                               |
| Nt     | NT system services(most of which are exported as Win32 functions) ,NT Native API |
| Ob     | Object manager                                               |
| Pf     | Prefetcher                                                   |
| Po     | Power manager                                                |
| Pp     | PnP manager                                                  |
| Ps     | Process support                                              |
| Rtl    | Run-time library                                             |
| Se     | Security                                                     |
| Tm     | Transaction manager                                          |
| Vf     | Verifier                                                     |
| Whea   | Windows Hardware Error Architecture                          |
| Wmi    | windows management instrumentation                           |
| Wdi    | windows diagnostic infrastructure                            |
| Zw     | The origin of the prefix “Zw” is unknown;it is rumored that this  prefix was chosen due to its having no significance at all.Mirror entry  point for system services (beginning with Nt) that sets previous access  mode to kernel,which eliminates parameter validation, since Nt system  services validate parameters only if previous access mode is user mode |
| Lpc    | Local Procedure Call                                         |
| Ldr    | Loader                                                       |
| Nls    | National language support                                    |
| Tdi    | Transport driver interface                                   |
| Csr    | Client Server Runtime,represents the interface to the win32 subsystem located in csrss.exe |
| Inbv   | Initialize boot video                                        |

# System Processes

Details reference from Windows System Internals 7th Edition page 100+. Skipped lots of initialization related stuff because they are mostly defined by Microsoft and out of our control.

| Process Name                       | Purpose                                                      |
| ---------------------------------- | ------------------------------------------------------------ |
| Idle process*                      | Contains 1 thread per CPU to account of idle CPU time        |
| System Process*                    | Contains the majority of the kernel-mode system thread and handles |
| Secure System Process*             | Contains the address space of the secure kernel in VTL 1, if running |
| Memory Compression process*        | Contains the compressed working set of user-mode processes   |
| Session Manager                    | Smss.exe (create sessions, start subsystems) First user-mode process created in the system. |
| Windows subsystem                  | Csrss.exe (Explained earlier, critical process)              |
| Session 0 initalization            | Wininit.exe, init the first session                          |
| Logon process                      | Winlogon.exe, self explanatory name.                         |
| Service Control Manager            | Services.exe and the child service processes it creates such as system-supplied generic service-host process (Svchost.exe) |
| Local Security Authentical Service | Lsass.exe, and if Credential Guard is active, the Isolated Local Security Authentication Server (Lsaiso.exe) |

**Idle Process, System Process, Secure System Process and Memory Compression Process are not full processes because they are not running a user-mode executable.* They are minimal-processes.

## Kernel Mode System threads

They are similar to User-Mode threads but they only run in kernel-mode. It doesn't have user process address space so it only can allocate dynamic storage from OS memory heaps, such as a paged or non-paged pool.

They are crated by the `PsCreateSystemThread` or `IoCreateSystemThread` function.

While they are by default owned by the System process, a device driver can create system thread in any process.

## Windows Logon Process

Winlogon.exe handles interactive user logon and logoffs. It listens for ctrl+alt+delete. This sequence cannot be intercepted by user-mode applications (That's why for windows VM you want to use Ctrl+Alt+Ins).

Winlogon.exe spawns a child process LogonUI.exe which manages the credential providers and the UI to display the logon dialog box. LogonUI.exe process terminates after user enters their credentials or dismiss the logon UI.

Winlogon.exe can load network provider DLLs to perform secondary authentication.

After user enters their password, credentials are sent to Lsass.exe. Lsass.exe chooses the appropriate authentication package (a DLL) to perform the verification. Password is usually stored in Active Directory or SAM. If Credential Guard is enabled for a domain logon, Lsass.exe will communicate with Lsaio.exe to obtain the machine key required to authenticate the legitimacy of the authentication request. (Cannot spoof your machine and bruteforce domain logons)

After authentication succeed, Lsass.exe contacts the Security Reference Monitor (SRM) in executive layer to generate access token object. If UAC is enabled and user is an admin, a second restricted access token is generated. This access token is used by Winlogon.exe to initialize the user's session. Initial processes are stored in HKLM\SOFTWARE\Microsoft\WindowsNT\CurrentVersion\Winlogon registry key. Can have more than 1 image

Userinit.exe initialise user environment, then create a process to run the system-defined SHELL in the Winlogon registry key (default Explorer.exe). Then Userinit.exe exits.

