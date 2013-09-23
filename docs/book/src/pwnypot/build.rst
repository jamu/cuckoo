Build PwnyPot
=============
If you want to build PwnyPot by yourself, checkout the cuckoo_integration branch of `github.com/jamu/PwnyPot`_. You need a Windows operation system with the Windows SDK installed in order to build it. 
There are two build-setups inside the project directory: Release and CuckooRelease. Release contains the standalone PwnyPot version, which can be used to test stuff directly without the whole setup with Cuckoo.CuckooRelease outputs PwnyPot.dll which needs to be used with Cuckoo. 
The simplest way To start the building process is to execute the following Command:: 
  
  C:\Windows\Microsoft.NET\Framework\v4.X\MSBuild path_to_sln_file /p:Configuration=[CuckooRelease|Release]

Afterwards copy the resulting dll file into the right location, which is the dll folder inside *cuckoo/analyzer/windows* for Cuckoo or *C:\\Program Files\\MCEDP\\* for the standalone version.


.. _github.com/jamu/PwnyPot: http://github.com/jamu/PwnyPot