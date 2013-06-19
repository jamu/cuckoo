# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import logging 

from lib.common.abstracts import Package
from lib.api.process import Process
from lib.common.exceptions import CuckooPackageError

log = logging.getLogger(__name__)

class IE(Package):
    """Internet Explorer analysis package."""

    def start(self, url):
        free = self.options.get("free", False)
        dll = self.options.get("dll",None)
        suspended = True
        if free:
            suspended = False

        p = Process()
        if not p.execute(path=os.path.join(os.getenv("ProgramFiles"), "Internet Explorer", "iexplore.exe"), args="\"%s\"" % url, suspended=suspended):
            raise CuckooPackageError("Unable to execute initial Internet Explorer process, analysis aborted")

        if not free and suspended:
            if dll:
                p.inject(os.path.join("dll",dll))
            else:
                p.inject()
            p.resume()
            return p.pid
        else:
            return None

    def check(self):
        return True

    def finish(self):
        if self.options.get("procmemdump", False):
            for pid in self.pids:
                p = Process(pid=pid)
                p.dump_memory()

        return True
