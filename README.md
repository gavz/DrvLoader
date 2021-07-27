## DrvLoader

**Context:** This is an older tool I once wrote and I found the source code while clearing out an old archive. This tool was written while participating in a offensive, malware development competition. It originally was supposed to include the ability to exploit Capcom to disable DSE via `CI!g_CiOptions` to eventually allow for loading an unsigned rootkit onto the system. This tool isn't entirely complete, so it's somewhat in an **archive** state, I probably won't be providing any updates any time soon.

**Introduction:**
This utility can be used during the post-exploitation phase of an offensive engadement, it drops an embedded driver (resource) to disk and loads it using the undocumented NT Windows function NtLoadDriver. After, the loaded driver can be unloaded using NtUnloadDriver and traces of the dropped resource on disk are removed. Using NtLoadDriver is a stealthier option compared to using the SCM API's. This utility also supports loading the same embedded resource using the SCM by creating a new kernel driver service (SERVICE_KERNEL_DRIVER). After, the service can be deleted. 

**DrvLoader Features**

- [x] Drop a driver (capcom.sys) from an embedded resource to disk
- [x] Check if the running process is running as Administrator
- [x] Enable SeLoadDriverPrivilege for the current processes access token
- [x] Create a Registry key value for the dropped driver (capcom.sys)
- [x] Load a kernel driver using NtLoadDriver
- [x] Perform cleanup, unload driver using NtUnloadDriver
- [x] Alternatively, Load the embedded driver resource using the SCM
- [ ] Calculate g_CiOptions, disable DSE and load an unsigned driver

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

## Technical Details

DrvLoader is a tool that can aid in the post-exploitation process of an offensive operation. It drops a kernel driver to disk from an embedded resource and then loads it into the kernel with the undocumented Windows NT function NtLoadDriver. There are a few requirements that need to be met prior to making a call to the NtLoadDriver function. 

![image](https://user-images.githubusercontent.com/70239991/125891506-a068b5b0-7188-47c2-83da-ee5957c7d26d.png)

While the function is “undocumented”, security researchers have reverse engineer and supplies the required documentation for usage of the function. Information about the function can be found on the Undocumented NT Functions wiki which provides an overview of how the function works. 

![image](https://user-images.githubusercontent.com/70239991/125655728-4567253c-ae09-4125-99a8-53569f7e5d49.png)

The function only requires a single parameter that is defined as “DriverServiceName”, the parameter needs to be a unicode string of the Registry location for that driver to be loaded. 

Under the hood `NtLoadDriver` simply is a wrapper for `IopLoadDriverImage`, which is another undocumented function from ntoskrnl. Daxx Rynd a great research piece about the interworkings of this function. `IopLoadDriverImage` is a private routine that includes various system routines including `IopLoadDriver` which includes `MmLoadSystemImageEx`. This routine is responsible for actually creating the sections for the specified driver.

![image](https://user-images.githubusercontent.com/70239991/125655533-ab58f37e-5fc4-48df-a809-4bd590e9e1fb.png)

Prior to loading the driver, getting a driver onto a target system is the first requirement, this can easily be accomplished by dropping the driver to disk from an embedded resource within the payload. DrvLoader accomplishes this by making calls to functions such as FindResource and LoadResource. When compiling DrvLoader, adding a driver as a resource will embedded it within the binary file. On execution DrvLoader locates that binary resource, obtains a pointer to it in memory and then creates and writes the file to disk within the PUBLIC users home directory. 

![image](https://user-images.githubusercontent.com/70239991/125863781-dda44ff4-291d-4cb3-9b70-c4d82f78641e.png)

1. Make a function call to `FindResource` to locate the location of the embedded resource based on the defined type and name defined when importing it
2. Retrieve a handle to the first byte of the resource in memory with `LoadResource`, this handle is later used to access the resource in memory
3. Obtain the size of the resource by calling `SizeOfResource`, this allows us to determine how much data we are writing to disk when the resource is dropped to disk.
4. Get a pointer to the resource in memory with `LockResource`
5. Create an empty file on disk for the resource by calling `CreateFile`, DrvLoader specifies `C:\Users\Public\<file>` as the location to drop the resource to disk.
6. Using a handle from the prior `CreateFile` function call, use `WriteFile` to write the contents of the resource into the file from memory using the pointer to it that was obtained from `LockResource`. 

Before being able to load the kernel driver onto the system the process that loads a driver requires a few specific process access token privileges. First, the process should be running as an Administrator, DrvLoader checks this by querying the current processes process token with a function call to OpenProcessToken with TOKEN_QUERY set as the desired access, using the handle returned by this call, another call to GetTokenInformation is called with a pointer to the TOKEN_ELEVATION structure passed to it, checking the structures TokenIsElevated member allows DrvLoader to determine if the running process is running under the context of an Administrator or not.

Next, in order to load a kernel driver, processes require the SeLoadDriverPrivilege privilege, even as an Administrator, this privilege is disabled by default. DrvLoader enables this privilege by making a call to LookupPrivilegeValue to add the privilege to the LUID structure, and then a subsequent call to AdjustTokenPrivileges to add the requested privilege to the current processes access token.

![image](https://user-images.githubusercontent.com/70239991/125863968-e410b60a-809d-4c38-9ddc-ddfac2b7825f.png)

1. Call `OpenProcess` to obtain a handle to the current process with the required access by PID with `GetCurrentProcessId`
2. Open a handle to the current processes access token with `OpenProcessToken` and include the `TOKEN_ADJUST_PRIVILEGES` for the returned handle
3. Define the requested privilege (`SeLoadDriverPrivilege`) with a call to `LookupPrivilegeValue`, this includes a pointer to the LUID structure which is used to set the wanted privileges
4. Define the `TOKEN_PRIVILEGES` structure and set it's members, set `PrivilegeCount` to 1 since only one privilege is being requested, set the `Luid` member to the previously defined LUID structure, and the `Attributes` to `SE_PRIVILEGE_ENABLED` to enable the requested privilege.
5. Call `AdjustTokenPrivileges` to adjust the current processes access token using the previously defined information, this takes the handle opened with `OpenProcessToken`, and a pointer to the `TOKEN_PRIVILEGES` structure definition 

![image](https://user-images.githubusercontent.com/70239991/125649557-9d2b1988-7f29-46a7-8308-284fa81a4c59.png)

After setting the needed privilege, issuing a `whoami /privs` command shows that the `SeLoadDriverPrivilege` privilege is now enabled for the current process. Now the process has the ability to load kernel drivers onto the system.

As defined in the “documentation” for NtLoadDriver, the function takes a single parameter that specifies the name and path of the Registry subkey responsible for identifying the driver to load. The path must begin with the CurrentControlSet\Services Registry key (`\\registry\\machine\\SYSTEM\\CurrentControlSet\\Services\\`), this Registry key is used for defining services that are loaded and running on the system. Each service can have an associated value in this Registry key to represent. When creating a subkey for this Registry key there are two required values that need to be set. First `ImagePath` needs to include a path to the driver that we want to load. And `Type` needs to have it’s value set to one. In addition to these “required” values, we are also going to set the `ErrorControl` value to 1 and the `Start` value to 1.

Creating the necessary subkey and values can be done through the Reg* API functions, we can use `RegCreateKeyExW` to create the initial subkey value, and then four subsequent calls to `RegSetValueExW` to set the different needed values.

1. The initial Registry subkey can be creating with a function call to RegCreateKeyExW, this function will take HKEY_LOCAL_MACHINE as a predefined key along with the full path of the subkey we are setting which in this case is the path mentioned earlier, but with a subkey value appended to the end, the subkey will have multiple value set. Calling this function will also return a HANDLE to the created key. We will use this handle later when setting the various required key values.
2. Now that the initial subkey was created to represent the driver that’s going to be loaded, we can call `RegSetValueEx` to start setting the required values. First setting `ImagePath` with the location of the dropped driver is set. It must be in the proper unicode format in order to work.
3. Now setting `Type` indicates that the service or driver is a Kernel-mode driver, this could also technically be set to 2, 4, 10, or 20 to indicate different types of services and drivers that can be loaded.
4. Setting `ErrorControl` to 1 indicates that if the driver fails to start, ignore the problem and display no errors.
5. Setting  `Start` to 3 indicates that the provided service need to be manually started by the user and it does not start automatically

Now that the current process contains the required access token privileges, and the necessary Registry keys have been created, we can call DrvLoader to initiate the loading of the driver. Calling NtLoadDriver directly won’t be possible, so instead calling `GetModuleHandle` to get a handle to ntdll.dll and then calling `GetProcAddress` to get the address of `NtLoadDriver` directly is the way to go. After dynamically resolving `NtLoadDriver` we can set up the Registry path and subkey that was previously created and set. 

In order to pass this path to `NtLoadDriver` first intilizing it as a unicode string need to be done, this can be done by dynamically resolving the address of `RtlInitUnicodeString` and passing it the string along with a UNICODE_STRING type variable. Once the path has been set, passing the unicode variable that contains the Registry path and subkey to `NtLoadDriver` will cause the previously dropped driver on disk to be loaded directly into the Windows kernel and started.

**Conclusion**

Whether you are an APT group, cybercriminal, security researcher, or other. At some point during your operation you will want to load a driver or rootkit onto a compromised system, using the SCM or calling the SCM related API functions can be noisy and may lead to detection by the hosts AV or EDR detection systems, alternatively you can call the undocumented NT function NtLoadDriver which can be used to directly load a kernel driver into the system. Prior to calling NtLoadDriver a few things need to be set up, but after obtaining the required access token privileges, creating the Required Registry subkeys and value, and resolving NtLoadDriver directly from Ntdll.dll, you can load a driver onto the system at will.

The exact technique has been used many times in the past by cybercriminals and APT groups to load rootkits onto a compromise victim system by first dropping and **loading** a signed but vulnerable legitimate driver, and then using that driver to load their rootkit through a non-convential method (bypassing or disabling DSE and then loading it using NtLoadDriver/SCM). The first hurdle is always loading the initial driver while bypassing detection, using DrvLoader provides an easy solution to that problem.

**References**
- Tomasz Nowak. “NTAPI Undocumented Functions - NtLoadDriver.” Https://Undocumented.Ntinternals.Net, undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FAPC%2FNtTestAlert.html.
- Savill, John. “What Are the ErrorControl, Start and Type Values under the Services Subkeys?” IT Pro, 24 Sept. 2018, www.itprotoday.com/compute-engines/what-are-errorcontrol-start-and-type-values-under-services-subkeys.
- Lastline. “Dissecting Turla Rootkit Malware Using Dynamic Analysis.” Lastline, 8 Apr. 2015, www.lastline.com/labsblog/dissecting-turla-rootkit-malware-using-dynamic-analysis.
