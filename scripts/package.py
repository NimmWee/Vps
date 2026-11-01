"""Build deterministic runtime bundle; update the bootstrap checksum."""
import gzip,hashlib,io,json,pathlib,tarfile
root=pathlib.Path(__file__).resolve().parents[1]
version='1.0.0';out=root/'dist'/('vps-vk-v'+version+'.tar.gz');out.parent.mkdir(exist_ok=True)
files=[root/'src/vps_vk.py',root/'LICENSE',root/'NOTICE.md']+list((root/'artifacts').glob('*'))+list((root/'third_party').glob('*'))
for path in files:
 if path.is_file() and not path.name.startswith('freeturn-linux-'):
  path.write_bytes(path.read_bytes().replace(b'\r\n',b'\n'))
buffer=io.BytesIO()
with tarfile.open(fileobj=buffer,mode='w') as tar:
 for path in sorted(files):
  if not path.is_file():continue
  name=path.relative_to(root).as_posix();data=path.read_bytes();info=tarfile.TarInfo(name)
  info.size=len(data);info.mode=0o755 if path.name.startswith('freeturn-linux-') else 0o644;info.mtime=0
  tar.addfile(info,io.BytesIO(data))
with out.open('wb') as f:
 with gzip.GzipFile(fileobj=f,mode='wb',filename='',mtime=0) as gz:gz.write(buffer.getvalue())
digest=hashlib.sha256(out.read_bytes()).hexdigest()
script=root/'install.sh';text=script.read_text()
import re
text,n=re.subn(r'BUNDLE_SHA256="[^"]*"','BUNDLE_SHA256="'+digest+'"',text)
assert n==1
script.write_text(text,encoding='utf-8',newline='\n')
print(json.dumps({'bundle':out.name,'sha256':digest,'bytes':out.stat().st_size}))
