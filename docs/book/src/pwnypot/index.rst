=============
Use Cuckoo with PwnyPot
=============

Installation
============
To use Cuckoo with support for MCEDP you need to pull the mcedp_integration branch from the git-repository `github.com/jamu/cuckoo`_.
It provides you with the latest development branch of cuckoo combined with all files to configure Pwnypot through the cuckoo submission API. It already contains MCEDP.dll inside the folder 'dll' of the windows analyzer module.

Configuration
=============
Inside /conf/ lies the pwnypot.conf configuration file. The file already contains all existing configuration parameters. 


Usage
=====
You can start the analysis through the cuckoo submit.py script in /utils/. Add the following option to use PwnyPot as analysis dll instead of Cuckoo::
    
    ./utils/submit.py --package pdf --options dll=MCEDP.dll mal_file.pdf 

If you do not specify the dll parameter, cuckoo.dll will be injected as default.
After the successful analysis you can find all processed results inside the file storage/analyses/id/reports/results.html. You can also start the web interface with ::
    ./utils/web.py
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
