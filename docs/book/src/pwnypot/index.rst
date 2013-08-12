=============
Use Cuckoo with PwnyPot
=============

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
    
    ./submit.py --options dll=MCEDP.dll mal_file.pdf 

If you do not specify the dll parameter, cuckoo.dll will be injected as default.



Future Work
===========
There are still some items on our To-Do-list. 

Developers
==========
If you have any questions regarding PwnyPot please contact one of the developers below. PwnyPot is still under heavy development and may contain bugs. We appreciate any hints or descriptions of possible bugs.

    +------------------------------+--------------------+--------------------------------------+
    | Name                         | Role               | Contact                              |
    +==============================+====================+======================================+
    | Shariyar Jalayeri            | Lead Developer     | ``shahriyar.j at gmail dot com``     |
    +------------------------------+--------------------+--------------------------------------+
    | Tobias Jarmuzek              | Developer          | ``tobias.jarmuzek at gmail dot com`` |
    +------------------------------+--------------------+--------------------------------------+


Build PwnyPot
=============
If you want to build PwnyPot by yourself, checkout the cuckoo_integration branch of `github.com/jamu/MCEDP`_. You need a Windows operation system to build it. 


Supporters
==========

    * `The Honeynet Project`_


.. _`The Honeynet Project`: http://www.honeynet.org
