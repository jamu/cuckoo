=============
Use Cuckoo with PwnyPot
=============
PwnyPot is a high interaction client honeypot for Windows operating systems. Despite other High-Interaction honeyClients which detect malicious servers based on system changes (file system and registry modifications, invoked/killed processes, ...), PwnyPot uses a new approach. To accomplish this, PwnyPot uses exploit detection methods to detect drive-by downloads at exploitation stage and dump malware file. Using this approach, PwnyPot eliminates some limitations of current HoneyClients and improves the detection speed of High-Interaction client Honeypots. Some of the methods used in PwnyPot have been first implemented in MS EMET. 

Features
========
* Shellcode Detection
* Shellcode Dumps
* ROP Detection
* ROP Gadget Dumps


Installation
============
To use Cuckoo with support for PwnyPot you need to pull the mcedp_integration branch from the git-repository `github.com/jamu/cuckoo`_.
It provides you with the latest development branch of cuckoo combined with all files to configure Pwnypot through the cuckoo submission API. It already contains MCEDP.dll inside the folder 'dll' of the windows analyzer module.

Configuration
=============
Inside /conf/ lies the pwnypot.conf configuration file. The file already contains all existing configuration parameters. Inside Cuckoo, the configuration file is parsed in lib/cuckoo/core/scheduler.py, if a task is specified to run with PwnyPot dll injection. It saves the values together with other regular cuckoo options into a dict which is handed over to the start_analysis function inside lib/cuckoo/core/guest.py. The configuration is then sent to the guest where it generates the analysis.conf and the $PID.ini. 
By saving the PwnyPot variables inside the $PID.ini inside the Windows Temp folder of the user we are logged in to, each new spawned process can easily find its configuration. The analysis.conf file is always saved in a random location. In order to find it we would need to parse the ini-file anyway. 

Global Section
--------------

**skip_hbp_error**
    
    **Allowed Values: 0, 1**
    
    Allows to enable / disable skipping of Hardware Breakpoint Errors.

**init_delay**

    **Allowed Values: Integers**

    Sets the number of seconds, which the Shellcode Detector Thread should sleep before hooking the system calls. 

General Section
---------------

**permanent_dep**

    **Allowed Values: 0, 1**

    If set to 1 permanent DEP is enabled on the processes, in which PwnyPot gets injected to.

**sehop** (not yet implemented)
   
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
-----------------

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

**eta_validation** 

    **Allowed Values: 0, 1**


**etaf_module** 

    **Allowed Values: 0, 1**

**kill_shellcode** 

    **Allowed Values: 0, 1**

**dump_shellcode** 

    **Allowed Values: 0, 1**

**allow_malware_download** 

    **Allowed Values: 0, 1**

ROP Section
-----------

**detect_rop** 

    **Allowed Values: 0, 1**


**dump_rop** 

    **Allowed Values: 0, 1**

**kill_rop** 

    **Allowed Values: 0, 1**

**rop_mem_far** 

    **Allowed Values: Integer**

**forward_execution** 

    **Allowed Values: 0, 1**

**fe_far** 

    **Allowed Values: Integer**

**call_validation** 

    **Allowed Values: 0, 1**

**stack_monitor** 

    **Allowed Values: 0, 1**


**max_rop_inst** 

    **Allowed Values: Integer**

**max_rop_mem** 

    **Allowed Values: Integer**

**pivot_detection**

    **Allowed Values: 0, 1**

**pivot_threshold**

    **Allowed Values: Integer**

**pivot_inst_threshold**

    **Allowed Values: Integer**


Memory Section
--------------

**text_rwx**

    **Allowed Values: 0, 1**

**stack_rwx**

    **Allowed Values: 0, 1**

**text_randomization**

    **Allowed Values: 0, 1**
    
    
Usage
=====
You can start the analysis through the cuckoo submit.py script in /utils/. Add the following option to use PwnyPot as analysis dll instead of Cuckoo::
    
    $ ./utils/submit.py --package pdf --options dll=MCEDP.dll mal_file.pdf 

If you do not specify the dll parameter, cuckoo.dll will be injected as default.
After the successful analysis you can find all processed results inside the file storage/analyses/id/reports/results.html. You can also start the web interface with ::
    $ ./utils/web.py
and open your browser with localhost:8080 to view all analyses.


Build PwnyPot
=============
If you want to build PwnyPot by yourself, checkout the cuckoo_integration branch of `github.com/jamu/MCEDP`_. You need a Windows operation system with the Windows SDK installed in order to build it. 
There are two build-setups inside the project directory: Release and CuckooRelease. Release contains the standalone PwnyPot version, which can be used to test stuff directly without the whole setup with cuckoo. CuckooRelease outputs MCEDP.dll which needs to be used with Cuckoo. 
The simplest way To start the building process is to execute the following Command:: 
    C:\Windows\Microsoft.NET\Framework\v4.X\MSBuild path_to_sln_file /p:Configuration=[CuckooRelease|Release]

Afterwards copy the resulting dll file into the right location, which is the dll folder inside cuckoo/analyzer/windows for Cuckoo or C:\Program Files\MCEDP\ for the standalone version.


Developers
==========
If you have any questions regarding PwnyPot please contact one of the developers below. PwnyPot is still under heavy development and may contain bugs. We appreciate any hints or descriptions of such.

    +------------------------------+--------------------+--------------------------------------+
    | Name                         | Role               | Contact                              |
    +==============================+====================+======================================+
    | Shariyar Jalayeri            | Lead Developer     | ``shahriyar.j at gmail dot com``     |
    +------------------------------+--------------------+--------------------------------------+
    | Tobias Jarmuzek              | Developer          | ``tobias.jarmuzek at gmail dot com`` |
    +------------------------------+--------------------+--------------------------------------+


Supporters
==========

    * `The Honeynet Project`_

Links
=====

    * `github.com/jamu/MCEDP`_
    * `github.com/jamu/cuckoo`_
    * `github.com/shjalayeri/MCEDP`_
    * `honeynet.net`_

.. _`github.com/jamu/MCEDP`: http://github.com/jamu/MCEDP
.. _`github.com/jamu/cuckoo`: http://github.com/jamu/cuckoo
.. _`github.com/shjalayeri/MCEDP`: http://github.com/shjalayeri/MCEDP
.. _`honeynet.net`: http://www.honeynet.net
.. _`The Honeynet Project`: http://www.honeynet.org
