import hashlib,json,pathlib,re,tarfile
root=pathlib.Path(__file__).resolve().parents[1]
manifest=json.loads((root/'artifacts/manifest.json').read_text())
for name,digest in manifest['sha256'].items():
 assert pathlib.PurePosixPath(name).name==name
 assert hashlib.sha256((root/'artifacts'/name).read_bytes()).hexdigest()==digest,name
bundle=root/'dist/vps-vk-v1.0.0.tar.gz'
digest=re.search(r'BUNDLE_SHA256="([a-f0-9]{64})"',(root/'install.sh').read_text()).group(1)
assert hashlib.sha256(bundle.read_bytes()).hexdigest()==digest
with tarfile.open(bundle,'r:gz') as tar:
 for member in tar.getmembers():
  assert member.isfile() and not pathlib.PurePosixPath(member.name).is_absolute() and '..' not in pathlib.PurePosixPath(member.name).parts
  assert tar.extractfile(member).read()==(root/member.name).read_bytes(),member.name
print('Binary checksums, bootstrap checksum and runtime source bundle match.')
