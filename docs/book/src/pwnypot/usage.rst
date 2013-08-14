Usage
=====
You can start the analysis through the Cuckoo submit.py script in /utils/. Add the following option to use PwnyPot as analysis dll instead of Cuckoo::
    
    $ ./utils/submit.py --package pdf --options dll=MCEDP.dll mal_file.pdf 

If you do not specify the dll parameter, cuckoo.dll will be injected as default.
After the successful analysis you can find all processed results inside the file storage/analyses/id/reports/results.html. You can also start the web interface with ::
    $ ./utils/web.py
and open your browser with localhost:8080 to view all analyses.