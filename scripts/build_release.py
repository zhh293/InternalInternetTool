"""Build an allowlisted distribution, optionally with this host's open-source JDK runtime."""
import argparse, hashlib, os, pathlib, platform, shutil, subprocess, tarfile, tempfile, zipfile
import xml.etree.ElementTree as ET

ROOT=pathlib.Path(__file__).resolve().parents[1]
NS={'m':'http://maven.apache.org/POM/4.0.0'}
VERSION=ET.parse(ROOT/'pom.xml').getroot().findtext('m:version',namespaces=NS)
MODULES='java.base,java.logging,java.management,java.naming,java.net.http,java.security.jgss,java.sql,java.xml,jdk.crypto.ec,jdk.httpserver,jdk.unsupported'

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime',action='store_true',help='Bundle a jlink runtime from JAVA_HOME for the current OS/architecture')
    parser.add_argument('--jar',type=pathlib.Path,default=ROOT/'target'/('tunnel-'+VERSION+'.jar'))
    parser.add_argument('--output',type=pathlib.Path,default=ROOT/'target'/'release')
    args=parser.parse_args()
    if not args.jar.is_file():parser.error('Run mvn package first; shaded JAR is missing')
    with zipfile.ZipFile(args.jar) as jar:
        manifest=jar.read('META-INF/MANIFEST.MF').decode()
        if 'Main-Class: dev.tunnel.Main' not in manifest:parser.error('JAR has no release entry point; rebuild with mvn package')
        if jar.read('tunnel-version.properties').decode().strip()!='version='+VERSION:parser.error('JAR version does not match pom.xml')
    system={'Windows':'windows','Linux':'linux','Darwin':'darwin'}.get(platform.system())
    arch={'AMD64':'amd64','x86_64':'amd64','aarch64':'arm64','arm64':'arm64'}.get(platform.machine())
    if args.runtime and (not system or not arch):parser.error('Unsupported platform')
    flavor=system+'-'+arch if args.runtime else 'java'
    name='tunnel-'+flavor
    args.output.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='tunnel-release-',dir=args.output) as tmp:
        app=pathlib.Path(tmp)/'tunnel';app.mkdir()
        # Never archive the workspace: local PEM files, benchmarks, state and diagnostics stay out.
        shutil.copyfile(args.jar,app/'tunnel.jar')
        for filename in ['tunnel','tunnel.cmd']:
            data=(ROOT/'distribution'/filename).read_text(encoding='utf-8').replace('\r\n','\n')
            (app/filename).write_bytes(data.replace('\n','\r\n').encode() if filename.endswith('.cmd') else data.encode())
        (app/'tunnel').chmod(0o755)
        (app/'config').mkdir()
        for f in ['server.properties.example','client.properties.example']:shutil.copyfile(ROOT/'config'/f,app/'config'/f)
        shutil.copyfile(ROOT/'docs'/'快速启动与发布.md',app/'QUICKSTART.md')
        (app/'VERSION').write_text(VERSION+'\n')
        if args.runtime:
            home=pathlib.Path(os.environ.get('JAVA_HOME',''))
            jlink=home/'bin'/('jlink.exe' if system=='windows' else 'jlink')
            if not jlink.is_file():parser.error('Set JAVA_HOME to an OpenJDK 17+ distribution containing jlink')
            release=(home/'release').read_text()
            if 'BUILD_TYPE="commercial"' in release:parser.error('Use an open-source JDK such as Temurin for redistributable runtime bundles')
            subprocess.run([str(jlink),'--add-modules',MODULES,'--strip-debug','--no-header-files','--no-man-pages','--compress=2','--output',str(app/'runtime')],check=True)
            java=app/'runtime'/'bin'/('java.exe' if system=='windows' else 'java')
            subprocess.run([str(java),'-jar',str(app/'tunnel.jar'),'--version'],check=True)
        archive=args.output/(name+('.zip' if not args.runtime or system=='windows' else '.tar.gz'))
        if archive.suffix=='.zip':
            with zipfile.ZipFile(archive,'w',compression=zipfile.ZIP_DEFLATED) as z:
                for f in sorted(app.rglob('*')):
                    if f.is_file():z.write(f,f.relative_to(app.parent))
        else:
            with tarfile.open(archive,'w:gz') as t:t.add(app,arcname='tunnel')
    checksum=archive.with_name(archive.name+'.sha256')
    checksum.write_text(hashlib.sha256(archive.read_bytes()).hexdigest()+'  '+archive.name+'\n',encoding='ascii')
    print(archive);print(checksum)

if __name__=='__main__':main()
