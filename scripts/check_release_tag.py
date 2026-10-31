import os,pathlib,xml.etree.ElementTree as ET
p=pathlib.Path(__file__).resolve().parents[1]
version=ET.parse(p/'pom.xml').getroot().findtext('{http://maven.apache.org/POM/4.0.0}version')
tag=os.environ['RELEASE_TAG']
if tag!='v'+version:raise SystemExit('Tag '+tag+' does not match pom version '+version)
print('Release tag verified:',tag)
