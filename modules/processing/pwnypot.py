# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.objects import File
import xml.etree.ElementTree as ET
import string

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

                if "ShellcodeAnalysis.xml" in file_name:   
                    binaries[file_name] = {}
                    bin_path = os.path.join(dir_name, file_name.replace("Analysis.xml", ".bin"))
                    if os.path.exists(bin_path):    
                        fd = open(bin_path,"r")
                        file_content = fd.read()
                        fd.close()                    
                        if len(file_content)>0:
                            binaries[file_name]["shellcode"] = File(file_path=bin_path).get_all()
                            disass_path = os.path.join(dir_name,file_name.replace("Analysis.xml","Disass.txt"))                        
                            if os.path.exists(disass_path):
                                fd = open(disass_path,"r")
                                binaries[file_name]["disass"] = fd.read()
                                fd.close()
                    
                    if (binaries[file_name].get("shellcode") == None):
                        binaries[file_name]["shellcode"] = None

                    binaries[file_name]["pid"] = file_name.split("_")[0]
                    xml_path = os.path.join(dir_name, file_name)

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
                        binaries[file_name]["accepts"] = []
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
                                        gadget["instructions"] = g.find("rop_inst").text
                                        gadget["stack_values"] = []
                                        for s in g.iter("stack_val"):
                                            value = s.attrib.get("value")
                                            stack_value = (s.attrib.get("address"), value)
                                            ascii = ""
                                            for i in range(1,5):
                                                try:
                                                    char = value[i*2:2+i*2].decode("hex").encode("utf-8")
                                                    if char in string.printable[:len(string.printable)-2] and char!=" ":
                                                        ascii += char
                                                    else:
                                                        ascii += "."
                                                except Exception as e:
                                                    ascii += "."
                                                    pass
                                            stack_value = stack_value + (ascii,)
                                            gadget["stack_values"].append(stack_value)
                                        rop_gadgets.append(gadget)

                                rop["gadgets"] = rop_gadgets
                                binaries[file_name]["rop_chains"].append(rop)

                            if row.attrib.get('type') == EXEC:
                                binaries[file_name]["execs"].append("Executing Command: %s" % row.attrib.get("exec_cmd"))

                            if row.attrib.get('type') == URL_DOWNLOAD_TO_FILE:
                                binaries[file_name]["downloads"].append("Download url: %s filename: %s" % (row.attrib.get("download_url"), row.attrib.get("download_filename")))

                            if row.attrib.get('type') == SOCKET:
                                binaries[file_name]["sockets"].append("Socket created: %s type: %s" % (row.attrib.get("AF"), row.attrib.get("socket_type")))

                            if row.attrib.get('type') == CONNECT:
                                binaries[file_name]["connects"].append("Connect to %s:%s" % (row.attrib.get("connect_ip"), row.attrib.get("connect_port")))

                            if row.attrib.get('type') == LISTEN:
                                binaries[file_name]["listens"].append("Listening: %s" % (row[0].text))

                            if row.attrib.get('type') == BIND:
                                binaries[file_name]["binds"].append("Binding on %s:%s" % (row.attrib.get("bind_ip"), row.attrib.get("bind_port")))

                            if row.attrib.get('type') == ACCEPT:
                                binaries[file_name]["accepts"].append("Accept from %s:%s" % (row.attrib.get("accept_ip"), row.attrib.get("accept_port")))

                            if row.attrib.get('type') == SEND:
                                sent = {}
                                sent["msg"] = "Send to %s:%s" % (row.attrib.get("send_ip"), row.attrib.get("send_port"))
                                dump_path = os.path.join(dir_name, file_name.replace("Shellcode.bin", "dump-%s.txt" %(row.attrib.get("data_uid"))))
                                if os.path.exists(dump_path):
                                    fd = open(dump_path,"r")
                                    try:
                                        sent["dump"] = u"%s" %(fd.read().encode('utf-8'))
                                    except Exception as e:
                                        received["dump"] = u"encoding error"
                                    fd.close()
                                
                                binaries[file_name]["sends"].append(sent)

                            if row.attrib.get('type') == RECV:
                                received = {}
                                received["msg"] = "Received on %s:%s" % (row.attrib.get("recv_ip"), row.attrib.get("recv_port"))
                                dump_path = os.path.join(dir_name, file_name.replace("Shellcode.bin", "dump-%s.txt" %(row.attrib.get("data_uid"))))
                                if os.path.exists(dump_path):
                                    fd = open(dump_path,"r")
                                    try:
                                        received["dump"] = u"%s" %(fd.read().encode('utf-8'))
                                    except Exception as e:
                                        received["dump"] = u"encoding error"
                                    fd.close()
                                
                                binaries[file_name]["recvs"].append(received)


                        log_path = os.path.join(dir_name,file_name.replace("ShellcodeAnalysis.xml","LogShellcode.txt"))
                        if os.path.exists(log_path):
                            fd = open(log_path, "r")
                            binaries[file_name]["log"] = fd.read()
                            fd.close()
                                               


        results["log_files"] = log_files
        results["binaries"] = binaries
        return results    
