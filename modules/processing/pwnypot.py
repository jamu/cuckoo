# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.objects import File
import xml.etree.ElementTree as ET

import logging
log = logging.getLogger(__name__)

# analysis information types as defined in PwnyPot (Hook.cpp)
ROP = "0"
EXEC = "1"
URL_DOWNLOAD_TO_FILE = "2"
SOCKET = "3"
CONNECT = "4"
LISTEN = "5"
BIND = "6"
ACCEPT = "7"
SEND = "8"
RECV = "9"

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
                if "LogInfo.txt" in file_name or "Rop" in file_name:                        
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
                        binaries[file_name]["pid"] = file_name.split("_")[0]
                        disass_path = os.path.join(dir_name,file_name.replace(".bin","Disass.txt"))                        
                        if os.path.exists(disass_path):
                            fd = open(disass_path,"r")
                            binaries[file_name]["disass"] = fd.read()
                            fd.close()

                        xml_path = os.path.join(dir_name,file_name.replace(".bin","Analysis.xml"))

                        if os.path.exists(xml_path):
                            tree = ET.parse(xml_path)
                            xml = tree.getroot()
                            binaries[file_name]["rop_chains"] = []
                            binaries[file_name]["execs"] = []
                            binaries[file_name]["downloads"] = []
                            binaries[file_name]["sockets"] = []
                            binaries[file_name]["connects"] = []
                            binaries[file_name]["listens"] = []
                            binaries[file_name]["binds"] = []
                            binaries[file_name]["sends"] = []
                            binaries[file_name]["recvs"] = []
                            for row in xml.iter("row"):
                                if row.attrib.get('type') == ROP:
                                    rop = {}
                                    rop["module_name"] = row.attrib.get("module")
                                    rop["function"] = row.attrib.get("function")   
                                    rop_gadgets = []
                                    for g in row.iter("rop_gadget"):
                                        if g.attrib.get("offset")!=None:
                                            gadget = {}
                                            gadget["offset"] = g.attrib.get("offset")
                                            gadget["instructions"] = g[0].text
                                            rop_gadgets.append(gadget)
                                    rop["gadgets"] = rop_gadgets
                                    binaries[file_name]["rop_chains"].append(rop)

                                if row.attrib.get('type') == EXEC:
                                    binaries[file_name]["execs"].append("Executing Command: %s" % row.attrib["exec_cmd"])

                                if row.attrib.get('type') == URL_DOWNLOAD_TO_FILE:
                                    binaries[file_name]["downloads"].append("Download url: %s filename: %s" % (row.attrib["download_url"], row.attrib["download_filename"]))

                                if row.attrib.get('type') == SOCKET:
                                    binaries[file_name]["sockets"].append("Socket created: %s type: %s" % (row.attrib["AF"], row.attrib["socket_type"]))

                                if row.attrib.get('type') == CONNECT:
                                    binaries[file_name]["connects"].append("Connect to %s:%s" % (row.attrib["connect_ip"], row.attrib["connect_port"]))

                                if row.attrib.get('type') == LISTEN:
                                    binaries[file_name]["listens"].append("Listening: %s" % (row[0].text))

                                if row.attrib.get('type') == BIND:
                                    binaries[file_name]["binds"].append("Binding on %s:%s" % (row.attrib["bind_ip"], row.attrib["bind_port"]))


                        log_path = os.path.join(dir_name,file_name.replace("Shellcode.bin","LogShellcode.txt"))
                        if os.path.exists(log_path):
                            fd = open(log_path, "r")
                            binaries[file_name]["log"] = fd.read()
                            fd.close()
                                               


        results["log_files"] = log_files
        results["binaries"] = binaries
        return results    
