

=======================
Use Cuckoo with PwnyPot
=======================
PwnyPot is a high interaction client honeypot for Windows operating systems. Despite other High-Interaction honeyClients which detect malicious servers based on system changes (file system and registry modifications, invoked/killed processes, ...), PwnyPot uses a new approach. To accomplish this, PwnyPot uses exploit detection methods to detect drive-by downloads at exploitation stage and dump malware file. Using this approach, PwnyPot eliminates some limitations of current HoneyClients and improves the detection speed of High-Interaction client Honeypots. Some of the methods used in PwnyPot have been first implemented in MS EMET. 

PwnyPot can be used to analyze behaviour in nearly any Windows application. By now, most analysis and tests have been performed for the most prevalent ones like Internet Explorer, Adobe PDF Reader, Mozilla Firefox and the Microsoft Office Product series.

How it works
============
When a task with the PwnyPot.dll option is sent to the guest via Cuckoo, the Cuckoo agent injects PwnyPot.dll into the desired process. If PwnyPot detects malware, and the option allow_malware_exec is true, the malware is executed in a new process and cuckoomon.dll is injected in order to analyze the behaviour of the malware.