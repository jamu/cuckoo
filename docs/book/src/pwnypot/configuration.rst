=============
Configuration
=============
Inside /conf/ lies the pwnypot.conf configuration file. The file already contains all existing configuration parameters. Inside Cuckoo, the configuration file is parsed in lib/cuckoo/core/scheduler.py, if a task is specified to run with PwnyPot dll injection. It saves the values together with other regular Cuckoo options into a dict which is handed over to the start_analysis function inside lib/cuckoo/core/guest.py. The configuration is then sent to the guest where it generates the analysis.conf and the $PID.ini. 
By saving the PwnyPot variables inside the $PID.ini inside the Windows Temp folder of the user we are logged in to, each new spawned process can easily find its configuration. The analysis.conf file is always saved in a random location. In order to find it we would need to parse the ini-file anyway. 

Global Section
==============

**skip_hbp_error**
    
    **Allowed Values: 0, 1**
    
    Allows to enable / disable skipping of Hardware Breakpoint Errors.

**init_delay**

    **Allowed Values: Integers**

    Sets the number of seconds, which the Shellcode Detector Thread should sleep before hooking the system calls. 

General Section
===============

**permanent_dep**

    **Allowed Values: 0, 1**

    If set to 1 permanent DEP is enabled on the processes, in which PwnyPot gets injected to.

**sehop** 
   
    **Allowed Values: 0, 1**

    Enables structured exception handler overwrite protection if set to 1.

**null_page**

    **Allowed Values: 0, 1**

    Protects against Null Page dereferencing if set to 1. This is done by EnableNullPageProtection in GeneralProtections.cpp by allocating null page and the first 0x1000 bytes proceeding.


**heap_spray**

    **Allowed Values: 0, 1**
    
    If set to 1, this configuration parameter enables heap spray protection by allocation common heap spray addresses.

**allow_malware_exec**

    **Allowed Values: 0, 1**

    If PwnyPot detects malicious behaviour, it normally kills the process. By setting this parameter to 1, PwnyPot keeps the process running on malware detection.


Shellcode Section
=================

**analysis_shellcode**

    **Allowed Values: 0, 1**

    If set to 1, PwnyPot gives further output of process activity on shellcode detection. This currently includes the following function hooks:
        * CreateThread
        * URLDownloadToFileW
        * socket
        * connect
        * listen
        * bind
        * accept
        * listen
        * recv

**syscall_validation** (not yet implemented)

    **Allowed Values: 0, 1**

    Enables / Disables Syscall Validation. Will be done via KiFastSyscall Hooks.

**eta_validation** 

    **Allowed Values: 0, 1**

    Enables / Disables Export Table Access Validation. When this option is enabled, the shellcode detector thread adds itself, or more explicitly the function DbgExceptionHandler in ETAV_DebugBreak.cpp,  as a Debug Exception Handler. This handler then checks whether it is called because of an access to the export table. If this is the case, it verifies whether the access is from a valid loaded module or not. If not, a global shellcode flag is set in order to proceed the analysis depending on the configuration.

    If you enable this option, do not forget to set a valid module with the parameter eta_module.

**eta_module** 

    **Allowed Values: String**

    Specifies the Module to watch for ETA Validation (e.g. Kernel32.dll).

**kill_shellcode** 

    **Allowed Values: 0, 1**

    If set to 1, a process which is determined to execute shellcode is directly terminated. No further analysis of shellcode is then possible. Also, there will be no dump of the shellcode. 

**dump_shellcode** 

    **Allowed Values: 0, 1**

    Enables / Disables dumping of Shellcode. The output consists of a binary dump, the instruction addresses, the hex coded instrunctions and also the disassembled instructions. 
    Shellcode will not be dumped, if kill_shellcode is set to 1.

**allow_malware_download** 

    **Allowed Values: 0, 1**

    Enables / Disables downloading of malware. This is done by hooking URLDownloadToFileW. 

ROP Section
===========

**detect_rop** 

    **Allowed Values: 0, 1**

    Enables / Disables ROP detection. 

**dump_rop** 

    **Allowed Values: 0, 1**

    Enables / Disables used ROP gadgets.

**kill_rop** 

    **Allowed Values: 0, 1**

    Enable / Disable killing of ROP shellcode on detection.

**rop_mem_far** 

    **Allowed Values: Integer**

**forward_execution** (not yet implemented)

    **Allowed Values: 0, 1**

**fe_far** (not yet implemented)

    **Allowed Values: Integer**

**call_validation** (not yet implemented)

    **Allowed Values: 0, 1**

**stack_monitor** 

    **Allowed Values: 0, 1**

    Enables / Disables monitoring of stack boundaries. Each call is checked for not having the stack pointer address out of range of the stack.

**max_rop_inst** 

    **Allowed Values: Integer**

**max_rop_mem** 

    **Allowed Values: Integer**

**pivot_detection** (not yet implemented)

    **Allowed Values: 0, 1**

**pivot_threshold** (not yet implemented)

    **Allowed Values: Integer**

**pivot_inst_threshold** (not yet implemented)

    **Allowed Values: Integer**


Memory Section
==============

**text_rwx** (not yet implemented)

    **Allowed Values: 0, 1**

    Enables / Disables protection of permission changes on the text section.

**stack_rwx**

    **Allowed Values: 0, 1**

    Enables / Disables protection of permission changes on the stack.

**text_randomization** (not yet implemented)

    **Allowed Values: 0, 1**

    Enables / Disables protection of permission changes on the text section.