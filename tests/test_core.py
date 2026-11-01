import base64,copy,importlib.util,json,pathlib,shutil,sys,tempfile,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'src'))
import vps_vk as app

def b64(n):return base64.b64encode(bytes([n])*32).decode()
def fixture():
 return {'version':1,'instance':'main','endpoint':'93.184.216.34','port':56001,'backend_port':51830,'subnet':'10.77.43.0/24','wan':'eth0','obf_key':'a'*64,'server_private':b64(1),'server_public':b64(2),'vk_link':'https://vk.ru/call/join/test-room','clients':{name:{'private_key':b64(i),'public_key':b64(i+1),'preshared_key':b64(i+2),'cid':str(i)*32} for name,i in [('iphone',3),('android',6)]}}

class CoreTests(unittest.TestCase):
 def test_endpoint_rejects_shell_and_nonpublic_ips(self):
  for bad in ['127.0.0.1','10.0.0.1','x;reboot','host name','-option','https://host','a/b','a:22','a\n']:
   with self.subTest(bad=bad),self.assertRaises(ValueError):app.validate_endpoint(bad)
  self.assertEqual(app.validate_endpoint('vpn.example.org'),'vpn.example.org')
  self.assertEqual(app.validate_endpoint('93.184.216.34'),'93.184.216.34')
 def test_state_rejects_unexpected_fields_duplicate_keys_and_bad_network(self):
  self.assertEqual(app.validate_state(fixture()),fixture())
  for mutate in [lambda s:s.update(command='reboot'),lambda s:s.update(subnet='0.0.0.0/0'),lambda s:s.update(port=s['backend_port']),lambda s:s['clients']['android'].update(private_key=s['clients']['iphone']['private_key']),lambda s:s.update(wan='eth0;id'),lambda s:s.update(instance='../x')]:
   s=fixture();mutate(s)
   with self.assertRaises(ValueError):app.validate_state(s)
 def test_phone_links_have_independent_keys_and_correct_transport(self):
  links=app.profile_links(fixture())
  ios=json.loads(base64.b64decode(links['iphone'].split('data=',1)[1]))['settings']
  payload=links['android'].split('://',1)[1]
  android=json.loads(base64.urlsafe_b64decode(payload+'='*(-len(payload)%4)))
  self.assertTrue(ios['useWrapS']);self.assertFalse(ios['useUDP'])
  self.assertEqual(android['provider'],'vk');self.assertEqual(android['obf'],'rtpopus3')
  self.assertEqual(ios['peerAddress'],android['peer'])
  self.assertNotIn(ios['privateKey'],android['wg'])
  self.assertIn('AllowedIPs = 0.0.0.0/0, ::/0',android['wg'])
  self.assertNotIn('Jc',android['wg'])
 def test_ip_migration_preserves_keys_but_updates_both_links(self):
  s=fixture();original=copy.deepcopy(s)
  moved=app.migrate_state(s,'93.184.216.35')
  self.assertEqual(s,original);self.assertEqual(moved['clients'],original['clients'])
  self.assertEqual(moved['server_private'],original['server_private'])
  self.assertNotEqual(app.profile_links(s),app.profile_links(moved))
 def test_backup_schema_never_accepts_code_or_paths(self):
  raw=json.dumps({'version':1,'state':fixture()}).encode()
  self.assertEqual(app.parse_backup(raw),fixture())
  for payload in [{'version':2,'state':fixture()},{'version':1,'state':fixture(),'files':{'/etc/cron.d/pwn':'x'}}]:
   with self.assertRaises(ValueError):app.parse_backup(json.dumps(payload).encode())
 def test_atomic_write_refuses_symlink(self):
  with tempfile.TemporaryDirectory() as td:
   p=pathlib.Path(td);target=p/'target';target.write_text('original')
   try:(p/'link').symlink_to(target)
   except OSError:self.skipTest('symlink unavailable')
   with self.assertRaises(ValueError):app.atomic_write(p/'link','new',0o600)
   self.assertEqual(target.read_text(),'original')
 def test_firewall_is_scoped_and_blocks_backend_and_ipv6(self):
  rules=app.network_rules(fixture())
  text='\n'.join(' '.join(r) for r in rules)
  self.assertNotIn('--dport 22',text);self.assertNotIn('-F',text)
  self.assertIn('--dport 51830 -j DROP',text)
  self.assertIn('-s 10.77.43.0/24',text)
  self.assertIn('ip6tables',text)
  self.assertTrue(all('--comment' in r for r in rules))
 @unittest.skipUnless(shutil.which('openssl'),'OpenSSL required')
 def test_encrypted_backup_authenticates_before_decrypting(self):
  raw=json.dumps({'version':1,'state':fixture()}).encode()
  encrypted=app.encrypt_backup(raw,'a long test passphrase')
  self.assertNotIn(fixture()['server_private'].encode(),encrypted)
  self.assertEqual(app.decrypt_backup(encrypted,'a long test passphrase'),raw)
  with self.assertRaises(ValueError):app.decrypt_backup(encrypted,'wrong passphrase')
  tampered=bytearray(encrypted);tampered[-1]^=1
  with self.assertRaises(ValueError):app.decrypt_backup(bytes(tampered),'a long test passphrase')

if __name__=='__main__':unittest.main()
