# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.objects import File
import xml.etree.ElementTree as ET
from collections import OrderedDict
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
API = "10"
HOTPATCH = "11"
SEH = "12"
SOCKET_RANGE = range(3,10)

class Pwnypot(Processing):
    """Analysis of all files received by PwnyPot.dll."""

    def run(self):
        """Run analysis.
        @return: pwnypot results dict 
        """
        self.key = "pwnypot"
        results = {}
        log_files = {}
        binaries = {}
        results["executed_shellcode"] = False

        # walk through all files in analysis directory
        for dir_name, dir_names, file_names in os.walk(self.logs_path):
            for file_name in file_names:
                file_path = os.path.join(dir_name, file_name)
                # read generel Logfiles
                if "LogInfo" in file_name or "Rop" in file_name:                        
                    fd = open(file_path,"r")
                    file_content = fd.read()
                    fd.close()

                    if len(file_content)>0:
                        log_files[file_name] = file_content

                # malicious activation exist
                if "ShellcodeAnalysis" in file_name:   
                    binaries[file_name] = {}
                    binaries[file_name]["pid"] = file_name.split("_")[0]
                    bin_path = os.path.join(dir_name, file_name.replace("Analysis", "Bin"))
                    # check for shellcode and disassembly
                    if os.path.exists(bin_path):    
                        fd = open(bin_path,"r")
                        file_content = fd.read()
                        fd.close()                    
                        if len(file_content)>0:
                            # read disassmbly of shellcode
                            binaries[file_name]["shellcode"] = File(file_path=bin_path).get_all()
                            disass_path = os.path.join(dir_name,file_name.replace("Analysis","Disass"))                        
                            if os.path.exists(disass_path):
                                fd = open(disass_path,"r")
                                binaries[file_name]["disass"] = fd.read()
                                fd.close()
                    
                    if (binaries[file_name].get("shellcode") == None):
                        binaries[file_name]["shellcode"] = None

                    xml_path = os.path.join(dir_name, file_name)

                    # parse Analysis XML file
                    if os.path.exists(xml_path):
                        tree = ET.parse(xml_path)
                        xml = tree.getroot()
                        binaries[file_name]["rop_chains"] = []
                        binaries[file_name]["execs"] = []
                        binaries[file_name]["downloads"] = []
                        binaries[file_name]["sockets"] = []
                        binaries[file_name]["connections"] = OrderedDict()
                        binaries[file_name]["apis"] = []
                        binaries[file_name]["seh"] = []
                        # parse analysis information types
                        for row in xml.iter("row"):
                            analysis_type = row.attrib.get('type')
                            if analysis_type == ROP:
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
                                                    if char in string.printable[:len(string.printable)-2] and char!=" " and value[i*2:2+i*2]!="0A":
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

                            if analysis_type == EXEC:
                                binaries[file_name]["execs"].append("Executing Command: %s" % row.attrib.get("exec_cmd"))
                                if row.attrib.get("exec_pid")!=None:
                                    results["executed_shellcode"] = True

                            if analysis_type == URL_DOWNLOAD_TO_FILE:
                                binaries[file_name]["downloads"].append("Download url: %s filename: %s" % (row.attrib.get("download_url"), row.attrib.get("download_filename")))

                            if int(analysis_type) in SOCKET_RANGE:
                                try:                                 
                                    tmp = binaries[file_name]["connections"][row.attrib.get("socket")] 
                                except:
                                    binaries[file_name]["connections"][row.attrib.get("socket")] = OrderedDict()

                            if analysis_type == SOCKET:
                                binaries[file_name]["connections"][row.attrib.get("socket")]["socket"] = {"AF":row.attrib.get("AF"),"type":row.attrib.get("socket_type")}

                            if analysis_type == CONNECT:
                                binaries[file_name]["connections"][row.attrib.get("socket")]["connect"] = {"ip":row.attrib.get("connect_ip"),"port":row.attrib.get("connect_port")}

                            if analysis_type == LISTEN:
                                binaries[file_name]["connections"][row.attrib.get("socket")]["listen"] = row[0].text

                            if analysis_type == BIND:
                                binaries[file_name]["connections"][row.attrib.get("socket")]["bind"] = {"ip":row.attrib.get("bind_ip"), "port": row.attrib.get("bind_port")}

                            if analysis_type == ACCEPT:
                                binaries[file_name]["connections"][row.attrib.get("socket")]["accept"] = {"ip":row.attrib.get("accept_ip"), "port": row.attrib.get("accept_port")}

                            if analysis_type == SEND:
                                binaries[file_name]["connections"][row.attrib.get("socket")]["send"] = {"ip":row.attrib.get("send_ip"), "port": row.attrib.get("send_port")}
                                # check for existing network dump
                                dump_path = os.path.join(dir_name, file_name.replace("ShellcodeAnalysis", "_dump-%s" %(row.attrib.get("data_uid"))))
                                if os.path.exists(dump_path):
                                    fd = open(dump_path,"r")
                                    try:
                                        binaries[file_name]["connections"][row.attrib.get("socket")]["send"]["dump"] = u"%s" %(fd.read().encode('utf-8'))
                                    except Exception as e:
                                        send["dump"] = u"encoding error"
                                    fd.close()
                                

                            if analysis_type == RECV:
                                binaries[file_name]["connections"][row.attrib.get("socket")]["recv"] = {"ip":row.attrib.get("recv_ip"), "port": row.attrib.get("recv_port")}
                                # check for existing network dump
                                dump_path = os.path.join(dir_name, file_name.replace("ShellcodeAnalysis", "_dump-%s" %(row.attrib.get("data_uid"))))
                                if os.path.exists(dump_path):
                                    fd = open(dump_path,"r")
                                    try:
                                        binaries[file_name]["connections"][row.attrib.get("socket")]["recv"]["dump"] = u"%s" %(fd.read().encode('utf-8'))
                                    except Exception as e:
                                        binaries[file_name]["connections"][row.attrib.get("socket")]["recv"]["dump"] = u"encoding error"
                                    fd.close()
                                
                            if analysis_type == API:
                                if row.attrib.get("api")!=None:
                                    binaries[file_name]["apis"].append("API: %s - Parameter: %s" %(row.attrib.get("api"),row.attrib.get("value")))

                            if analysis_type == SEH:
                                seh = {}
                                seh["chain_start"] = row.attrib.get("chain_start")

                                seh["invalid_handler_address"] = row[0].attrib.get("address")
                                seh["invalid_handler_value"] = row[0].attrib.get("value")

                                seh["next_address"] = row[1].attrib.get("address")
                                seh["next_value"] = row[1].attrib.get("value")
                                binaries[file_name]["seh"].append(seh)

                        log_path = os.path.join(dir_name,file_name.replace("ShellcodeAnalysis","LogShellcode"))
                        if os.path.exists(log_path):
                            fd = open(log_path, "rb")
                            binaries[file_name]["log"] = fd.read()
                            fd.close()
                                               

        if log_files:
            results["log_files"] = log_files
        if binaries:
            results["binaries"] = binaries
        return results    
