import os,pathlib,signal,shutil
p=pathlib.Path('/tmp/tunnel-bench-20261031')
assert p.resolve()==pathlib.Path('/tmp/tunnel-bench-20261031')
for proc in pathlib.Path('/proc').iterdir():
    if not proc.name.isdigit():continue
    try:
        if (proc/'cwd').resolve()==p and b'curl\0' in (proc/'cmdline').read_bytes():
            os.kill(int(proc.name),signal.SIGTERM)
    except (OSError,ProcessLookupError):pass
if p.exists():shutil.rmtree(p)
print('Removed isolated test directory; stopped its download processes.')
