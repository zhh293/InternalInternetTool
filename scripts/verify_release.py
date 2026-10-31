"""Exercise the shipped launcher, Unicode paths, init protection and real TCP/TLS relay."""
import hashlib, os, pathlib, re, shutil, socket, socketserver, subprocess, tarfile, tempfile, threading, time, zipfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
def main():
    archives=list((ROOT/'target/release').glob('*.tar.gz'))+list((ROOT/'target/release').glob('*.zip'))
    if not archives:raise SystemExit('Build a release archive first')
    # CI verifies its runtime archive; a local universal-only build uses installed Java.
    archive=next((a for a in archives if a.name!='tunnel-java.zip'),archives[0])
    with tempfile.TemporaryDirectory(prefix='tunnel verify 空格 ',dir=ROOT/'target') as tmp:
        tmp=pathlib.Path(tmp)
        if archive.suffix=='.zip':
            with zipfile.ZipFile(archive) as z:
                assert all(n.startswith('tunnel/') and '..' not in pathlib.PurePosixPath(n).parts for n in z.namelist())
                z.extractall(tmp)
        else:
            with tarfile.open(archive) as t:t.extractall(tmp,filter='data')
        app=tmp/'tunnel';launcher=app/('tunnel.cmd' if os.name=='nt' else 'tunnel')
        if os.name!='nt':launcher.chmod(0o755)
        assert not any(p.name in ('token','server.key','KeyPair-b8db.pem') for p in app.rglob('*'))
        def command(*args):
            items=[str(launcher),*map(str,args)]
            return subprocess.list2cmdline(items) if os.name=='nt' else items
        def run(*args,ok=True):
            r=subprocess.run(command(*args),shell=os.name=='nt',cwd=tmp,capture_output=True,timeout=45)
            if ok and r.returncode:raise RuntimeError(r.stdout.decode(errors='replace')+r.stderr.decode(errors='replace'))
            if not ok:assert r.returncode!=0
            return r.stdout.decode(errors='replace')
        assert 'Usage: tunnel' in run('--help')
        assert 'Usage: tunnel' in run('/help')
        assert 'Usage: tunnel' in run('-h')
        assert '--local-port' in run('init-client','/help')
        assert 'OpenSSL' in run('help','init-server')
        assert not (tmp/'state').exists(), 'Help must not initialize configuration or credentials'
        assert 'tunnel ' in run('--version')
        run('not-a-command',ok=False)
        if not shutil.which('openssl'):
            print('Launcher verified; OpenSSL not found, initialization/TLS integration check skipped explicitly')
            return
        state=tmp/'状态 server';clientstate=tmp/'状态 client'
        reserved=[]
        for i in range(3):
            s=socket.socket();s.bind(('127.0.0.1',0));reserved.append(s)
        control,work,public=[s.getsockname()[1] for s in reserved]
        run('init-server','--server','127.0.0.1','--dir',state,'--public-port',public)
        before={f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in state.iterdir()}
        run('init-server','--server','127.0.0.1','--dir',state,'--public-port',public,ok=False)
        assert before=={f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in state.iterdir()}
        class Echo(socketserver.BaseRequestHandler):
            def handle(self):
                while True:
                    try:d=self.request.recv(65536)
                    except OSError:return
                    if not d:return
                    try:self.request.sendall(d)
                    except OSError:return
        class TCP(socketserver.ThreadingTCPServer):daemon_threads=True
        target=TCP(('127.0.0.1',0),Echo)
        threading.Thread(target=target.serve_forever,daemon=True).start()
        run('init-client','--server','127.0.0.1','--dir',clientstate,'--token-file',state/'token','--ca-file',state/'server.crt','--public-port',public,'--local-port',target.server_address[1])
        serverconfig=state/'server.properties';clientconfig=clientstate/'client.properties'
        with serverconfig.open('a',encoding='ascii') as f:f.write(f'\nbindHost=127.0.0.1\npublicBindHost=127.0.0.1\nmanagementPort=0\ncontrolPort={control}\nworkPort={work}\n')
        with clientconfig.open('a',encoding='ascii') as f:f.write(f'\ncontrolPort={control}\nworkPort={work}\n')
        for s in reserved:s.close()
        children=[];logs=[]
        try:
            for role,config in [('server',serverconfig),('client',clientconfig)]:
                log=open(tmp/(role+'.log'),'wb')
                logs.append(log)
                # Launch Java directly here so terminating the test never leaves a cmd/sh child behind.
                java=app/'runtime/bin'/('java.exe' if os.name=='nt' else 'java')
                if java.exists():binary=str(java)
                else:
                    # Oracle's Windows javapath can be a spawning stub; execute the real JVM
                    # so Popen.terminate()/wait() also guarantees its JAR handles are released.
                    probe=subprocess.run([shutil.which('java'),'-XshowSettings:properties','-version'],capture_output=True,timeout=15)
                    home=re.search(r'(?m)^\s*java.home = (.+)$',probe.stderr.decode(errors='replace')).group(1).strip()
                    binary=str(pathlib.Path(home)/'bin'/('java.exe' if os.name=='nt' else 'java'))
                children.append(subprocess.Popen([binary,'-Xmx128m','-XX:MaxDirectMemorySize=64m','-XX:ActiveProcessorCount=2','-jar',str(app/'tunnel.jar'),role,'-c',str(config)],cwd=tmp,stdout=log,stderr=subprocess.STDOUT))
            deadline=time.monotonic()+20
            while True:
                try:
                    with socket.create_connection(('127.0.0.1',public),timeout=1):break
                except OSError:
                    if time.monotonic()>deadline:raise RuntimeError('Packaged relay did not become ready; '+''.join((tmp/(x+'.log')).read_text(errors='replace') for x in ['server','client']))
                    time.sleep(.2)
            for n in [64,65536]:
                b=os.urandom(n)
                with socket.create_connection(('127.0.0.1',public),timeout=8) as s:
                    s.settimeout(8);s.sendall(b);out=b''
                    while len(out)<n:
                        d=s.recv(n-len(out))
                        if not d:raise EOFError('truncated relay data')
                        out+=d
                    assert out==b
        finally:
            for child in children:child.terminate()
            for child in children:
                try:child.wait(timeout=10)
                except subprocess.TimeoutExpired:child.kill();child.wait()
            for log in logs:log.close()
            target.shutdown();target.server_close()
        print('Verified:',archive.name,'launcher/version/init/no-overwrite/Unicode paths/TCP-TLS integrity')
if __name__=='__main__':main()
