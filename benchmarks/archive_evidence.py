"""Create/verify an allowlisted, byte-preserving benchmark evidence manifest."""
import argparse,hashlib,json,pathlib,re,sys,zipfile
ROOT=pathlib.Path(__file__).resolve().parent
SUFFIXES={'.md','.json','.py','.log','.txt','.toml'}
EXTRA={'server.properties','client.properties','cert.pem','tunnel-current.jar'}
EXCLUDE={'deps-install.log'}
def candidates():
    result=[ROOT/'README.md',ROOT/'archive_evidence.py']
    for name in ['20261031','20261031-protocols']:
        result += [p for p in (ROOT/name).iterdir() if p.is_file() and p.name not in EXCLUDE and (p.suffix in SUFFIXES or p.name in EXTRA)]
    return sorted(result,key=lambda p:p.relative_to(ROOT).as_posix())
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def audit(p):
    if p.suffix=='.jar':
        with zipfile.ZipFile(p) as z:
            assert not any(n.endswith(('.pem','.key')) or pathlib.PurePosixPath(n).name=='token' for n in z.namelist()),'Unexpected credential entry in tested JAR'
        return
    raw=p.read_bytes()
    s=raw.decode('utf-16') if raw.startswith((b'\xff\xfe',b'\xfe\xff')) else raw.decode('utf-8-sig',errors='replace')
    for pattern in [r'-----BEGIN [A-Z ]*PRIVATE KEY-----',r'\b(?:ghp_|github_pat_)[A-Za-z0-9_]{20,}',r'\bAKIA[A-Z0-9]{16}\b',r'\bsk-(?:proj-)?[A-Za-z0-9_-]{24,}']:
        if re.search(pattern,s):raise ValueError('Potential credential in '+str(p.relative_to(ROOT)))
    if p.name=='cert.pem' and '-----BEGIN CERTIFICATE-----' not in s:raise ValueError('Expected public certificate')
    if p.suffix=='.toml':
        for token in re.findall(r'auth\.token\s*=\s*"([^"]+)"',s):
            if token!='REPLACE_WITH_FRESH_TEST_TOKEN':raise ValueError('Non-placeholder authentication token in '+str(p))
def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--verify',action='store_true');args=parser.parse_args()
    target=ROOT/'evidence-manifest.json'
    if args.verify:
        manifest=json.loads(target.read_text(encoding='utf-8'))
        expected={x['path'] for x in manifest['files']};actual={p.relative_to(ROOT).as_posix() for p in candidates()}
        assert expected==actual,'Evidence file list changed; review before regenerating the manifest'
        for entry in manifest['files']:
            rel=pathlib.PurePosixPath(entry['path']);assert not rel.is_absolute() and '..' not in rel.parts
            p=ROOT.joinpath(*rel.parts);assert p.stat().st_size==entry['bytes'] and digest(p)==entry['sha256'],entry['path'];audit(p)
        print('Verified',len(manifest['files']),'evidence files; hashes and credential checks passed');return
    files=[]
    for p in candidates():
        audit(p);files.append({'path':p.relative_to(ROOT).as_posix(),'bytes':p.stat().st_size,'sha256':digest(p)})
    manifest={'schema_version':1,'test_date':'2026-10-31','source_baseline_commit':'0d3312a','tested_jar_sha256':'f68d57f872ddf0d8816142a63de10d2e6587b44835ae10fbc5f0aac5221cfe1f','data_policy':'Original measurement bytes; auth token placeholders in archived TOML; no private keys. Preflight and retest data are separately identified.','files':files}
    assert digest(ROOT/'20261031/tunnel-current.jar')==manifest['tested_jar_sha256']
    target.write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print('Manifest written:',len(files),'files,',sum(x['bytes'] for x in files),'bytes')
if __name__=='__main__':main()
