import pathlib,shutil
p=pathlib.Path('/tmp/tunnel-protocols-20261031')
assert p.resolve()==pathlib.Path('/tmp/tunnel-protocols-20261031')
if p.exists():shutil.rmtree(p)
print('Removed isolated protocol-test directory and its temporary credentials.')
