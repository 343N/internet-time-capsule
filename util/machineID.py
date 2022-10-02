import os
import uuid
import subprocess

class MachineID():

    _id = None

    @classmethod
    def get(cls):
        if (cls._id):
            return cls._id
        if (os.name == 'nt'):
            return cls.getWindowsID()
        else:
            return cls.getLinuxID()

    @classmethod
    def getWindowsID(cls):
        cmd = 'wmic csproduct get uuid'
        uuid = str(subprocess.check_output(cmd))
        return uuid[uuid.index('\\n')+2:uuid.rindex('\\r')]
        

    def getLinuxID(cls):
        with open('/etc/machine-id', 'r') as f:
            return f.read()