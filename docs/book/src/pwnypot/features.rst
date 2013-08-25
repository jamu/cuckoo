========
Features
========

The main features of PwnyPot are:

* :ref:`shellcode_detection`
* :ref:`shellcode_dumps`
* :ref:`dynamic_analysis`
* :ref:`rop_detection`
* :ref:`rop_gadgets`


.. _shellcode_detection:

Shellcode Detection by doing Export Address Table Validation
============================================================
  

.. _shellcode_dumps:

Shellcode Dumps
===============

  On detection of shellcode, PwnyPot will dump the shellcode in binary and disassembled format. 

.. _dynamic_analysis:

Dynamic Shellcode Analysis with API Hooks
=========================================

  When PwnyPot detects the execution of shellcode and malware execution is enabled in the configuration file, multiple Windows API functions are Hooked to monitor the activities of the shellcode. For all these functions we write all parameters to the analysis output. The following functions are hooked:

    * CreateProcessInternalW

    * URLDownloadToFileW

    * LoadLibraryExW

    * socket

    * connect 

    * listen

    * bind

    * accept

    * send

    * recv

.. _rop_detection:

ROP Detection
===============
  Pwnypot tries to detect Return-oriented Programming Exploits in multiple ways. 
  ROP chains are often used to call Windows APIs to circumvent DEP or ASLR. With DEP disabled injection of shellcode is easier, because most parts of the memory are marked as writable but not executable or not writable but executable. Most of the functions will fail in an exploit, if Permanent DEP is enabled. Nevertheless PwnyPot detects these methods, because older Windows Versions (up to Win XP) do not have permanent DEP enabled by Default. Furthermore it gives a more complete view of used methods of the malware. 
  The following APIs are Hooked by PwnyPot to detect possible DEP bypasses:
    
    * BOOL WINAPI SetProcessDEPPolicy (DWORD dwFlags)
        This is the most trivial, but also probably least working method for an attacker to disable DEP. It fails, if permanent DEP is enabled and the function does not even exist anymore in Windows Versions after Windows XP. The value of dwFlags must be 0 in order to disable DEP.

    * NTSTATUS WINAPI NtSetInformationProcess (
      HANDLE hProcess, 
      ULONG ProcessInformationClass, 
      __in_bcount(ProcessInformationLength)PVOID ProcessInformation, 
      ULONG ProcessInformationLength)
        This WINNT function can be used to change the DEP Policy of a Process. Therefore the ProcessInformationClass must be set to 0x22 which stands for setting the ProcessExecuteFlags. ProcessInformation then contains the Information which Execute Flags should be set. PwnyPots detects, if this value contains the flag to enable memory execution. This is eequivalent to disabling DEP. 


    * NTSTATUS NTAPI WriteProcessMemory (__in        HANDLE hProcess, __in      LPVOID lpBaseAddress, __in        LPCVOID lpBuffer, __in      SIZE_T nSize,  __out   SIZE_T \*lpNumberOfBytesWritten )
        This API function allows to write to a given memory address inside the process address space. Even if the page the address belongs to is marked as executable and not writable, this function can write. Internally it sets the correct flags (writable) to the corresponding page. This is extremely dangerous when the process has loaded DLLs which dont have ASLR enabled. One way to exploit this function is to overwrite the memory direct after the address of WriteProcessMemory itself inside KERNEL32.DLL, because this DLL has no ASLR enabled and is loaded into nearly any Windows process. PwnyPot protects against this type of WPM calls and reports also other calls.

    * VOID NTAPI LdrHotPatchRoutine ( PVOID * HotPatchBuffer)
        In each Windows 32-bit application on a Windows 64 bit system a fixed memory region at address 0x7ffe0000 exists, called SharedUserData. This memory region holds multiple function pointers, also to a function called LdrHotPatchRoutine. This function gets a pointer to a struct as a parameter and loads code (e.g. a DLL) from a given UNC path inside this struct. 
        Each call to this function is logged and also analyzed for unusual behaviour (like loading a DLL from some network location).

.. _rop_gadgets:

ROP Gadget Dumps
================

