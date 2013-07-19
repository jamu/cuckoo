# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.objects import File
from xml.dom import minidom

import logging
log = logging.getLogger(__name__)

class Pwnypot(Processing):
    """Analysis of all files received by MCEDP.dll."""

    def run(self):
        """Run analysis.
        @return: pwnypot results dict 
        """
        self.key = "pwnypot"
        results = {}
        log_files = {}
        binaries = {}

        for dir_name, dir_names, file_names in os.walk(self.logs_path):
            for file_name in file_names:
                file_path = os.path.join(dir_name, file_name)
                if "LogInfo.txt" in file_name:                        
                    fd = open(file_path,"r")
                    file_content = fd.read()
                    fd.close()

                    if len(file_content)>0:
                        log_files[file_name] = file_content

                if ".bin" in file_name:          
                    fd = open(file_path,"r")
                    file_content = fd.read()
                    fd.close()                    
                    if len(file_content)>0:
                        binaries[file_name] = File(file_path=file_path).get_all()
                        disass_path = os.path.join(dir_name,file_name.replace(".bin","Disass.txt"))                        
                        if os.path.exists(disass_path):
                            fd = open(disass_path,"r")
                            binaries[file_name]["disass"] = fd.read()
                            fd.close()

                        xml_path = os.path.join(dir_name,file_name.replace(".bin","Analysis.xml"))
                        if os.path.exists(xml_path):
                            xmldoc = minidom.parse(xml_path)
                            itemlist = xmldoc.getElementsByTagName('exec_cmd') 
                            for s in itemlist :
                                binaries[file_name]["xml"] = "Executing Command: %s" % s.childNodes[0].nodeValue 
                                               


        results["log_files"] = log_files
        results["binaries"] = binaries
        return results
