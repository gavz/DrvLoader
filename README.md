## DrvLoader

**Introduction:**
This utility can be used during the post-exploitation phase of an offensive engagement, it drops an embedded driver (resource) to disk and loads it using the undocumented NT Windows function NtLoadDriver. After, the loaded driver can be unloaded using NtUnloadDriver and traces of the dropped resource on disk are removed. Using NtLoadDriver is a stealthier option compared to using the SCM API's. This utility also supports loading the same embedded resource using the SCM by creating a new kernel driver service (SERVICE_KERNEL_DRIVER). After, the service can be deleted. 

[Read the technical details here](https://github.com/FULLSHADE/DrvLoader/blob/main/Documentation.md)

**Inspiration:**
While performing analysis into the Microsoft signed [NetFilter Windows kernel rootkit](https://www.gdatasoftware.com/blog/microsoft-signed-a-malicious-netfilter-rootkit), the dropper component used during the deployment process is very similar to the tool here. NetFilter's dropper/loader utility extracted the rootkit from itself and deployed it onto the target system using NtLoadDriver. NetFilter's dropped didn't bypass DSE since the rootkit was digitally signed. 

**DrvLoader Features**

- [x] Drop a driver (capcom.sys) from an embedded resource to disk
- [x] Check if the running process is running as Administrator
- [x] Enable SeLoadDriverPrivilege for the current processes access token
- [x] Load a kernel driver using the undocumented NtLoadDriver function
- [x] Perform cleanup, and unload the driver using NtUnloadDriver
- [x] Load the embedded driver resource using the SCM
- [ ] Calculate g_CiOptions, disable DSE and support loading an unsigned driver
- [ ] Decode and decompress the (packed) embedded resource via XOR
- [ ] Resolve all API functions via LoadLibrary / GetProcAddress

## Usage

1. You need to add a driver resource to the project when compiling the application `Resource Files > Add > Resource > Import`. While testing capcom.sys was used since it's a signed driver and can be loaded with DSE enabled on the system. 
2. Load the embedded resource using `/LOAD` or `/LOADSCM` and then use `/UNLOAD` or `/UNLOADSCM` when you are done with the target system

```
C:\development\newDrvLoader>DrvLoader.exe

DrvLoader - A post exploitation tool to aid in loading kernel drivers

        Usage        Description
        -----        -----------------------------------------------------------------
        /LOAD        Drop and load a signed kernel driver onto the system with NtLoadDriver
        /UNLOAD      Unload the loaded  driver from the system with NtUnloadDriver
        /LOADSCM     Load the embedded driver resource using the SCM
        /UNLOADSCM   Unload the embedded driver resource using the SCM
```

### /LOAD

```
C:\development\newDrvLoader>DrvLoader.exe /LOAD
[+] Successfully wrote the driver to disk
[+] Process is running with an elevated token [Administrator]

[+] Registry key was created up for calling NtLoadDriver
[+] Set the [ImagePath] value of the Registry key to the path of the driver
[+] Set the [Type] value of the Registry key to 1
[+] Set the [ErrorControl] value of the Registry key to 1
[+] Set the [Start] value of the Registry key to 1
[+] Added SeLoadDriverPrivilege to the current process token
[+] Sucessfully loaded the driver into the kernel via NtLoadDriver
```

### /UNLOAD

```
C:\development\newDrvLoader>DrvLoader.exe /UNLOAD
[+] Added SeLoadDriverPrivilege to the current process token

[+] Sucessfully unloaded the driver from the kernel
[+] Performed cleanup, removed keys and files from disk
```

### /LOADSCM

```
C:\development\newDrvLoader>DrvLoader.exe /LOADSCM
[+] Successfully wrote the driver to disk
[+] Sucessfully created a new service for the driver
```

### /UNLOADSCM

```
C:\development\newDrvLoader>DrvLoader.exe /UNLOADSCM
[+] Sucessfully deleted the driver service
```
