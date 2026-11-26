"""Reuse the supervisor's authenticated connection for successive benchmark observations."""

import os
from pathlib import Path
import shlex
import subprocess
import time


HOST = 'hy@clnode176.clemson.cloudlab.us'
WORKERS = {HOST, 'hy@clnode159.clemson.cloudlab.us', 'hy@clnode163.clemson.cloudlab.us'}


def call(host, command, *, data, timeout, stream=None):
    if host not in WORKERS:
        raise ValueError('Unexpected benchmark worker')
    sockets = Path('/tmp') / f'tdn-benchmark-ssh-{os.getuid()}'
    sockets.mkdir(mode=0o700, exist_ok=True)
    stat = sockets.lstat()
    if not sockets.is_dir() or sockets.is_symlink() or stat.st_uid != os.getuid() or stat.st_mode & 0o077:
        raise ValueError('The supervisor connection requires an owner-only socket directory')
    argv = ['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=18',
            '-o','ControlMaster=auto','-o','ControlPersist=180','-o','ControlPath='+str(sockets/'%C'),
            host,shlex.join(command)]
    for delay in (0,2,5):
        if delay:
            time.sleep(delay)
        result = subprocess.run(argv,input=data,stdout=stream if stream is not None else subprocess.PIPE,
                                stderr=subprocess.PIPE,timeout=timeout)
        err = result.stderr.decode(errors='replace').lower()
        before_command = ('connection timed out during banner exchange' in err or
                          ('connect to host' in err and ('connection timed out' in err or 'connection refused' in err)))
        if result.returncode != 255 or not before_command:
            return result
    return result
