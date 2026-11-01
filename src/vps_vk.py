#!/usr/bin/env python3
"""Small VK TURN / WireGuard lifecycle manager. Python standard library only."""
import argparse,base64,copy,datetime,getpass,hashlib,hmac,ipaddress,json,os,pathlib,re,secrets,shutil,socket,stat,subprocess,sys,tempfile,time,urllib.parse,urllib.request

VERSION='1.0.0'
LIB=pathlib.Path('/usr/local/lib/vps-vk')
MAGIC=b'VPSVK1\n'
STATE_KEYS={'version','instance','endpoint','port','backend_port','subnet','wan','obf_key','server_private','server_public','vk_link','clients'}
CLIENT_KEYS={'private_key','public_key','preshared_key','cid'}

def run(args,data=None,check=True,timeout=60):
    p=subprocess.run([str(a) for a in args],input=data,capture_output=True,text=True,timeout=timeout)
    if check and p.returncode:
        # Never include command arguments: they may contain a private key.
        raise RuntimeError(pathlib.Path(str(args[0])).name+' failed (exit '+str(p.returncode)+'): '+p.stderr[:350])
    return p

def atomic_write(path,data,mode=0o600):
    path=pathlib.Path(path)
    if path.is_symlink():raise ValueError('Refusing symlink: '+str(path))
    if isinstance(data,str):data=data.encode()
    fd,tmp=tempfile.mkstemp(prefix='.'+path.name+'-',dir=path.parent)
    try:
        os.chmod(tmp,mode)
        with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
        os.replace(tmp,path)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)

def validate_endpoint(value):
    if not isinstance(value,str) or value!=value.strip():raise ValueError('Invalid endpoint')
    try:
        addr=ipaddress.ip_address(value)
        if addr.version!=4 or not addr.is_global:raise ValueError('Endpoint must be public IPv4')
        return value
    except ValueError:
        if re.fullmatch(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}',value) and len(value)<=253:return value.lower()
        raise ValueError('Use a public IPv4 address or DNS name') from None

def valid_key(value):
    try:return isinstance(value,str) and len(base64.b64decode(value,validate=True))==32
    except Exception:return False

def validate_state(s):
    if not isinstance(s,dict) or set(s)!=STATE_KEYS or s['version']!=1:raise ValueError('Unsupported state schema')
    if not isinstance(s['instance'],str) or not re.fullmatch(r'[a-z][a-z0-9]{0,7}',s['instance']):raise ValueError('Invalid instance')
    validate_endpoint(s['endpoint'])
    for k in ['port','backend_port']:
        if type(s[k]) is not int or not 1024<=s[k]<=65535:raise ValueError('Invalid UDP port')
    if s['port']==s['backend_port']:raise ValueError('Ports must differ')
    net=ipaddress.ip_network(s['subnet'],strict=True)
    allowed=[ipaddress.ip_network(x) for x in ['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16']]
    if net.version!=4 or net.prefixlen!=24 or not any(net.subnet_of(x) for x in allowed):raise ValueError('Use an unused RFC1918 /24 subnet')
    if not re.fullmatch(r'[a-zA-Z0-9_.-]{1,15}',s['wan']):raise ValueError('Invalid uplink interface')
    if not re.fullmatch(r'[0-9a-f]{64}',s['obf_key']):raise ValueError('Invalid obfuscation key')
    if not valid_key(s['server_private']) or not valid_key(s['server_public']):raise ValueError('Invalid server key')
    room=urllib.parse.urlparse(s['vk_link'])
    if room.scheme!='https' or room.netloc not in ['vk.ru','vk.com'] or not room.path.startswith('/call/join/') or len(room.path)<=11 or any(c.isspace() for c in s['vk_link']):raise ValueError('Invalid VK call link')
    if not isinstance(s['clients'],dict) or set(s['clients'])!={'iphone','android'}:raise ValueError('Exactly two phone clients required')
    for p in s['clients'].values():
        if not isinstance(p,dict) or set(p)!=CLIENT_KEYS:raise ValueError('Invalid client schema')
        if not all(valid_key(p[k]) for k in ['private_key','public_key','preshared_key']):raise ValueError('Invalid client key')
        if not re.fullmatch(r'[0-9a-f]{32}',p['cid']):raise ValueError('Invalid Client ID')
    for k in CLIENT_KEYS:
        if s['clients']['iphone'][k]==s['clients']['android'][k]:raise ValueError('Phone credentials must differ')
    return s

def migrate_state(s,endpoint):
    result=copy.deepcopy(validate_state(s));result['endpoint']=validate_endpoint(endpoint)
    return validate_state(result)

def address(s,last):return str(ipaddress.ip_network(s['subnet']).network_address+last)
def v6prefix(s):
    octets=str(ipaddress.ip_network(s['subnet']).network_address).split('.')
    return 'fd77:'+format(int(octets[1]),'x')+':'+format(int(octets[2]),'x')+'::'

def wireguard_client(s,name):
    p=s['clients'][name];last=2 if name=='iphone' else 3
    return ('[Interface]\nPrivateKey = '+p['private_key']+'\nAddress = '+address(s,last)+'/32, '+v6prefix(s)+str(last)+'/128\nDNS = 1.1.1.1, 8.8.8.8\nMTU = 1280\n\n[Peer]\nPublicKey = '+s['server_public']+'\nPresharedKey = '+p['preshared_key']+'\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 127.0.0.1:9000\nPersistentKeepalive = 25\n')

def profile_links(s):
    validate_state(s);peer=s['endpoint']+':'+str(s['port']);p=s['clients']['iphone']
    settings={'serverName':'VK VPS iPhone','privateKey':p['private_key'],'peerPublicKey':s['server_public'],'presharedKey':p['preshared_key'],'tunnelAddress':address(s,2)+'/32','vkLink':s['vk_link'],'peerAddress':peer,'useDTLS':True,'useWrap':False,'useSrtp':False,'useWrapA':False,'useWrapS':True,'obfProfile':'rtpopus3','wrapKeyHex':s['obf_key'],'clientID':p['cid'],'useUDP':False,'dnsServers':'1.1.1.1,8.8.8.8','numConnections':6}
    ios='vkturnproxy://import?data='+base64.b64encode(json.dumps({'version':1,'type':'connection','settings':settings},separators=(',',':')).encode()).decode()
    p=s['clients']['android'];data={'v':1,'provider':'vk','peer':peer,'transport':'tcp','mode':'udp','obf':'rtpopus3','key':s['obf_key'],'n':6,'spc':3,'cid':p['cid'],'dns':'auto','mcap':True,'name':'VK VPS Android','vk':s['vk_link'],'wg':wireguard_client(s,'android')}
    android='freeturn://'+base64.urlsafe_b64encode(json.dumps(data,separators=(',',':')).encode()).decode().rstrip('=')
    return {'iphone':ios,'android':android}

def parse_backup(raw):
    if len(raw)>1048576:raise ValueError('Backup exceeds size limit')
    obj=json.loads(raw)
    if not isinstance(obj,dict) or set(obj)!={'version','state'} or obj['version']!=1:raise ValueError('Unsupported backup schema')
    return validate_state(obj['state'])

def openssl(data,password,decrypt=False):
    with tempfile.TemporaryDirectory(prefix='vps-vk-crypto-') as td:
        p=pathlib.Path(td)/'pass';p.write_bytes(password.encode());p.chmod(0o600)
        args=['openssl','enc','-aes-256-cbc','-pbkdf2','-iter','200000','-pass','file:'+str(p)]
        if decrypt:args.append('-d')
        r=subprocess.run(args,input=data,capture_output=True,timeout=60)
        if r.returncode:raise ValueError('Backup encryption/decryption failed')
        return r.stdout

def encrypt_backup(data,password):
    if len(password)<12:raise ValueError('Use a backup passphrase of at least 12 characters')
    salt=secrets.token_bytes(16);cipher=openssl(data,password)
    key=hashlib.pbkdf2_hmac('sha256',password.encode(),salt,200000,32)
    body=MAGIC+salt+cipher
    return MAGIC+salt+hmac.new(key,body,hashlib.sha256).digest()+cipher

def decrypt_backup(data,password):
    if len(data)>2097152 or len(data)<len(MAGIC)+64 or not data.startswith(MAGIC):raise ValueError('Invalid encrypted backup')
    off=len(MAGIC);salt=data[off:off+16];tag=data[off+16:off+48];cipher=data[off+48:]
    key=hashlib.pbkdf2_hmac('sha256',password.encode(),salt,200000,32)
    if not hmac.compare_digest(tag,hmac.new(key,MAGIC+salt+cipher,hashlib.sha256).digest()):raise ValueError('Incorrect passphrase or damaged backup')
    return openssl(cipher,password,True)

def iface(s):return 'vkvpn0' if s['instance']=='main' else 'vk'+s['instance']+'0'
def units(s):
    name='vps-vk'+('' if s['instance']=='main' else '-'+s['instance'])
    return name,name+'-network'
def paths(instance):
    if not re.fullmatch(r'[a-z][a-z0-9]{0,7}',instance):raise ValueError('Invalid instance')
    state=pathlib.Path('/var/lib/vps-vk')/instance
    return pathlib.Path('/etc/vps-vk')/instance,state
def load_state(instance):return validate_state(json.loads((paths(instance)[1]/'state.json').read_text()))

def network_rules(s):
    tag='vps-vk-'+s['instance'];dev=iface(s);rules=[]
    def add(binary,table,chain,args):rules.append([binary,'-w','5','-t',table,'-I',chain,*args,'-m','comment','--comment',tag])
    add('iptables','filter','INPUT',['-i',dev,'-j','REJECT'])
    add('iptables','filter','INPUT',['!','-i','lo','-p','udp','--dport',str(s['backend_port']),'-j','DROP'])
    add('iptables','filter','INPUT',['-p','udp','--dport',str(s['port']),'-j','ACCEPT'])
    for dest in ['0.0.0.0/8','10.0.0.0/8','100.64.0.0/10','127.0.0.0/8','169.254.0.0/16','172.16.0.0/12','192.168.0.0/16','224.0.0.0/4','240.0.0.0/4']:
        add('iptables','filter','FORWARD',['-i',dev,'-d',dest,'-j','REJECT'])
    add('iptables','filter','FORWARD',['-i',dev,'-o',s['wan'],'-s',s['subnet'],'-j','ACCEPT'])
    add('iptables','filter','FORWARD',['-i',s['wan'],'-o',dev,'-d',s['subnet'],'-m','conntrack','--ctstate','ESTABLISHED,RELATED','-j','ACCEPT'])
    add('iptables','filter','FORWARD',['-i',dev,'-j','DROP']);add('iptables','filter','FORWARD',['-o',dev,'-j','DROP'])
    add('iptables','nat','POSTROUTING',['-s',s['subnet'],'-o',s['wan'],'-j','MASQUERADE'])
    add('iptables','mangle','FORWARD',['-o',dev,'-p','tcp','--tcp-flags','SYN,RST','SYN','-j','TCPMSS','--clamp-mss-to-pmtu'])
    add('ip6tables','filter','INPUT',['-i',dev,'-j','REJECT'])
    add('ip6tables','filter','INPUT',['!','-i','lo','-p','udp','--dport',str(s['backend_port']),'-j','DROP'])
    add('ip6tables','filter','FORWARD',['-i',dev,'-j','DROP']);add('ip6tables','filter','FORWARD',['-o',dev,'-j','DROP'])
    return rules

def rule_exists(rule):
    args=rule.copy();args[5]='-C';return run(args,check=False).returncode==0
def remove_rule(rule):
    args=rule.copy();args[5]='-D'
    while rule_exists(rule):run(args)

def network_down(s):
    _,state=paths(s['instance']);record=state/'network.json'
    if not record.exists():return
    data=json.loads(record.read_text())
    for rule in reversed(data['rules']):remove_rule(rule)
    if run(['ip','link','show','dev',iface(s)],check=False).returncode==0:run(['ip','link','del','dev',iface(s)])
    data['active']=False;atomic_write(record,json.dumps(data))

def network_up(s):
    conf,state=paths(s['instance']);record=state/'network.json';dev=iface(s)
    if run(['ip','link','show','dev',dev],check=False).returncode==0:
        if not record.exists():raise RuntimeError('Interface already exists without an ownership record')
        network_down(s)
    wanted=ipaddress.ip_network(s['subnet'])
    for route in json.loads(run(['ip','-j','route','show','table','all']).stdout):
        if route.get('dst','default')=='default':continue
        try:other=ipaddress.ip_network(route['dst'])
        except ValueError:continue
        if other.version==4 and other.overlaps(wanted):raise RuntimeError('Subnet conflicts with an existing route')
    old=json.loads(record.read_text()) if record.exists() else {}
    data={'active':False,'previous_ip_forward':old.get('previous_ip_forward',pathlib.Path('/proc/sys/net/ipv4/ip_forward').read_text().strip()),'rules':network_rules(s)}
    atomic_write(record,json.dumps(data))
    try:
        run(['ip','link','add','dev',dev,'type','wireguard'])
        run(['wg','setconf',dev,conf/'wireguard.conf'])
        run(['ip','addr','add',address(s,1)+'/24','dev',dev])
        run(['ip','-6','addr','add',v6prefix(s)+'1/64','dev',dev])
        run(['ip','link','set','dev',dev,'mtu','1280','up'])
        for rule in reversed(data['rules']):
            if not rule_exists(rule):run(rule)
        run(['sysctl','-q','-w','net.ipv4.ip_forward=1'])
        data['active']=True;atomic_write(record,json.dumps(data))
    except Exception:network_down(s);raise

def mkdir(path,mode=0o700):
    path=pathlib.Path(path)
    if path.is_symlink():raise ValueError('Refusing directory symlink')
    path.mkdir(parents=True,exist_ok=True);path.chmod(mode)

def detect_network():
    route=json.loads(run(['ip','-j','route','get','1.1.1.1']).stdout)[0]
    wan=route['dev'];endpoint=route.get('prefsrc',route.get('src',''))
    try:validate_endpoint(endpoint)
    except ValueError:
        endpoint=urllib.request.urlopen('https://api.ipify.org',timeout=15).read(128).decode().strip();validate_endpoint(endpoint)
    return wan,endpoint

def keypair():
    private=run(['wg','genkey']).stdout.strip();public=run(['wg','pubkey'],private+'\n').stdout.strip()
    return private,public

def new_state(args):
    wan,endpoint=detect_network();private,public=keypair()
    s={'version':1,'instance':args.instance,'endpoint':args.endpoint or endpoint,'port':args.port,'backend_port':args.backend_port,'subnet':args.subnet,'wan':wan,'obf_key':secrets.token_hex(32),'server_private':private,'server_public':public,'vk_link':'','clients':{}}
    for name in ['iphone','android']:
        private,public=keypair();s['clients'][name]={'private_key':private,'public_key':public,'preshared_key':run(['wg','genpsk']).stdout.strip(),'cid':secrets.token_hex(16)}
    return s

def legacy_state(args):
    base=pathlib.Path('/var/lib/kit-freeturn/profiles');conf=pathlib.Path('/etc/kit-freeturn/wireguard.conf')
    if not conf.is_file() or not all((base/(x+'.json')).is_file() for x in ['iphone','android']):raise ValueError('Recognized legacy installation not found')
    interface=conf.read_text().split('[Peer]',1)[0]
    key=re.search(r'^PrivateKey\s*=\s*(\S+)',interface,re.M).group(1)
    port=int(re.search(r'^ListenPort\s*=\s*(\d+)',interface,re.M).group(1))
    p={name:json.loads((base/(name+'.json')).read_text()) for name in ['iphone','android']}
    wan,endpoint=detect_network();a=p['iphone'];b=p['android']
    if a['key']!=b['key'] or a['server_public_key']!=b['server_public_key']:raise ValueError('Inconsistent legacy credentials')
    s={'version':1,'instance':args.instance,'endpoint':args.endpoint or endpoint,'port':int(a['peer'].rsplit(':',1)[1]),'backend_port':port,'subnet':str(ipaddress.ip_network(a['address'],strict=False).supernet(new_prefix=24)),'wan':wan,'obf_key':a['key'],'server_private':key,'server_public':a['server_public_key'],'vk_link':'','clients':{name:{k:v[k] for k in CLIENT_KEYS} for name,v in p.items()}}
    return s

def check_keypairs(s):
    pairs=[(s['server_private'],s['server_public'])]+[(p['private_key'],p['public_key']) for p in s['clients'].values()]
    for private,public in pairs:
        if run(['wg','pubkey'],private+'\n').stdout.strip()!=public:raise ValueError('Private/public key mismatch')

def write_profiles(s,qr=False):
    _,state=paths(s['instance']);out=state/'profiles';mkdir(out)
    for name,link in profile_links(s).items():
        atomic_write(out/(name+'-import.txt'),link+'\n')
        if qr:
            if not shutil.which('qrencode'):raise ValueError('Install qrencode or omit --qr')
            run(['qrencode','-o',out/(name+'-qr.png'),'-s','7','-l','M'],link)
            (out/(name+'-qr.png')).chmod(0o600)
    return out

def render_config(s):
    conf,state=paths(s['instance']);mkdir(conf.parent,0o755);mkdir(conf,0o750);mkdir(state)
    import pwd
    user=pwd.getpwnam('vps-vk');os.chown(conf,0,user.pw_gid)
    atomic_write(state/'state.json',json.dumps(s,indent=2))
    atomic_write(conf/'obf.key',s['obf_key']+'\n',0o640)
    atomic_write(conf/'clients.json',json.dumps({'clients':{p['cid']:{'comment':name} for name,p in s['clients'].items()}}),0o640)
    for name in ['obf.key','clients.json']:os.chown(conf/name,0,user.pw_gid)
    wg='[Interface]\nPrivateKey = '+s['server_private']+'\nListenPort = '+str(s['backend_port'])+'\n'
    for name,last in [('iphone',2),('android',3)]:
        p=s['clients'][name];wg+='\n[Peer]\nPublicKey = '+p['public_key']+'\nPresharedKey = '+p['preshared_key']+'\nAllowedIPs = '+address(s,last)+'/32, '+v6prefix(s)+str(last)+'/128\n'
    atomic_write(conf/'wireguard.conf',wg)

def render_units(s):
    main,network=units(s);conf,_=paths(s['instance'])
    common='\n[Install]\nWantedBy=multi-user.target\n'
    n='[Unit]\nDescription=Scoped VK VPN network\nWants=network-online.target\nAfter=network-online.target ufw.service\nBefore='+main+'.service\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/python3 '+str(LIB/'vps_vk.py')+' network-up --instance '+s['instance']+'\nExecStop=/usr/bin/python3 '+str(LIB/'vps_vk.py')+' network-down --instance '+s['instance']+'\nUMask=0077\nTimeoutStartSec=60\nTimeoutStopSec=60\n'+common
    m='[Unit]\nDescription=FreeTurn for Android and iPhone\nRequires='+network+'.service\nAfter='+network+'.service network-online.target\nStartLimitIntervalSec=300\nStartLimitBurst=4\n\n[Service]\nType=simple\nUser=vps-vk\nGroup=vps-vk\nExecStart='+str(LIB/'freeturn')+' -listen 0.0.0.0:'+str(s['port'])+' -connect 127.0.0.1:'+str(s['backend_port'])+' -mode udp -obf-profile rtpopus3 -obf-key-file '+str(conf/'obf.key')+' -clients-file '+str(conf/'clients.json')+'\nEnvironment=GOMEMLIMIT=48MiB\nEnvironment=GOMAXPROCS=1\nRestart=on-failure\nRestartSec=5\nTimeoutStopSec=15\nMemoryHigh=64M\nMemoryMax=96M\nMemorySwapMax=0\nCPUQuota=50%\nTasksMax=64\nLimitNOFILE=1024\nUMask=0077\nNoNewPrivileges=yes\nPrivateTmp=yes\nPrivateDevices=yes\nProtectSystem=strict\nProtectHome=yes\nProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectControlGroups=yes\nRestrictSUIDSGID=yes\nRestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK\nCapabilityBoundingSet=\nLockPersonality=yes\nStandardOutput=null\nStandardError=journal\n'+common
    for name,data in [(main,m),(network,n)]:atomic_write(pathlib.Path('/etc/systemd/system')/(name+'.service'),data,0o644)
    run(['systemd-analyze','verify','/etc/systemd/system/'+main+'.service','/etc/systemd/system/'+network+'.service'])

def configure_fail2ban():
    import configparser
    jail=pathlib.Path('/etc/fail2ban/jail.d/zz-vps-vk.local');glob=pathlib.Path('/etc/fail2ban/fail2ban.local')
    old={p:p.read_bytes() if p.exists() else None for p in [jail,glob]}
    sshd=run(['/usr/sbin/sshd','-T'],check=False).stdout
    ports=re.findall(r'^port (\d+)$',sshd,re.M) or ['22']
    text='[sshd]\nenabled = true\nbackend = systemd\nport = '+','.join(ports)+'\nfilter = sshd[mode=normal]\nbanaction = nftables-multiport\nignoreip = 127.0.0.1/8 ::1\nusedns = no\nmaxretry = 3\nfindtime = 10m\nbantime = 30d\nbantime.increment = false\n'
    try:
        atomic_write(jail,text,0o644)
        parser=configparser.ConfigParser(interpolation=None)
        if glob.exists():parser.read(glob)
        if not parser.has_section('Definition'):parser.add_section('Definition')
        parser.set('Definition','dbpurgeage','3024000')
        import io
        output=io.StringIO();parser.write(output);atomic_write(glob,output.getvalue(),0o644)
        run(['fail2ban-client','-t']);run(['systemctl','enable','fail2ban']);run(['systemctl','restart','fail2ban'])
        for _ in range(50):
            if run(['fail2ban-client','ping'],check=False).returncode==0:break
            time.sleep(.1)
        for key,wanted in [('maxretry','3'),('findtime','600'),('bantime','2592000')]:
            if run(['fail2ban-client','get','sshd',key]).stdout.strip()!=wanted:raise RuntimeError('Effective SSH ban policy mismatch')
    except Exception:
        for p,data in old.items():
            if data is None:p.unlink(missing_ok=True)
            else:atomic_write(p,data,0o644)
        run(['systemctl','restart','fail2ban'],check=False);raise

def snapshot(s):
    stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    dest=pathlib.Path('/var/backups/vps-vk')/(s['instance']+'-'+stamp);mkdir(dest)
    conf,state=paths(s['instance']);files=[]
    for directory in [conf,state]:
        if directory.exists():
            for p in directory.rglob('*'):
                if p.is_symlink():raise ValueError('Unexpected symlink in configuration')
                if p.is_file():files.append(p)
    for name in units(s):
        p=pathlib.Path('/etc/systemd/system')/(name+'.service')
        if p.exists():files.append(p)
    for p in [pathlib.Path('/etc/fail2ban/jail.d/zz-vps-vk.local'),pathlib.Path('/etc/fail2ban/fail2ban.local')]:
        if p.exists():files.append(p)
    for p in files:
        target=dest/str(p).lstrip('/');mkdir(target.parent);shutil.copy2(p,target)
    for name,command in [('iptables',['iptables-save']),('ip6tables',['ip6tables-save']),('routes',['ip','-j','route']),('services',['systemctl','show','ssh','x-ui','kit-sub','nginx','-p','Id','-p','MainPID','-p','ActiveState','-p','NRestarts'])]:atomic_write(dest/(name+'.txt'),run(command).stdout)
    return dest

def install_payload(bundle):
    bundle=pathlib.Path(bundle);manifest=json.loads((bundle/'artifacts/manifest.json').read_text())
    arch=run(['dpkg','--print-architecture']).stdout.strip()
    if arch not in ['amd64','arm64']:raise ValueError('Supported architectures: amd64, arm64')
    name='freeturn-linux-'+arch;binary=bundle/'artifacts'/name
    if hashlib.sha256(binary.read_bytes()).hexdigest()!=manifest['sha256'][name]:raise ValueError('Transport checksum mismatch')
    mkdir(LIB,0o755)
    atomic_write(LIB/'freeturn',binary.read_bytes(),0o755)
    atomic_write(LIB/'vps_vk.py',(bundle/'src/vps_vk.py').read_bytes(),0o755)
    atomic_write(LIB/'manifest.json',json.dumps(manifest,indent=2),0o644)
    wrapper='#!/bin/sh\nexec /usr/bin/python3 /usr/local/lib/vps-vk/vps_vk.py "$@"\n'
    atomic_write(pathlib.Path('/usr/local/bin/vps-vk'),wrapper,0o755)

def check_environment():
    if os.geteuid()!=0:raise ValueError('Run as root')
    release={}
    for line in pathlib.Path('/etc/os-release').read_text().splitlines():
        if '=' in line:
            k,v=line.split('=',1);release[k]=v.strip('"')
    version=release.get('VERSION_ID','')
    if not ((release.get('ID')=='ubuntu' and version in ['22.04','24.04']) or (release.get('ID')=='debian' and version in ['12','13'])):raise ValueError('Supported: Ubuntu 22.04/24.04; Debian 12/13')
    if not pathlib.Path('/run/systemd/system').exists():raise ValueError('A systemd VPS is required')
    if shutil.disk_usage('/').free<100*1024*1024:raise ValueError('At least 100 MiB disk space is required')
    mem=re.search(r'MemTotal:\s+(\d+)',pathlib.Path('/proc/meminfo').read_text())
    if int(mem.group(1))<256*1024:raise ValueError('At least 256 MiB RAM is required (512 MiB+ recommended)')

def install(args,restored=None):
    check_environment();conf,state=paths(args.instance)
    had_state=(state/'state.json').exists();legacy=bool(args.adopt_legacy)
    if restored is not None:
        if had_state:raise ValueError('Restore requires an unused instance; existing keys will not be overwritten')
        s=copy.deepcopy(restored);s['instance']=args.instance
        wan,endpoint=detect_network();s['wan']=wan;s['endpoint']=args.endpoint or endpoint
    elif had_state:
        s=load_state(args.instance)
        if args.endpoint:s=migrate_state(s,args.endpoint)
        s['wan']=detect_network()[0]
    elif legacy:s=legacy_state(args)
    else:s=new_state(args)
    if args.vk_link_file:s['vk_link']=pathlib.Path(args.vk_link_file).read_text().strip()
    elif not s['vk_link']:s['vk_link']=getpass.getpass('VK call link (hidden): ').strip()
    validate_state(s);check_keypairs(s)
    active=run(['systemctl','is-active',units(s)[0]],check=False).stdout.strip()=='active'
    if not active:
        ports=run(['ss','-H','-lun']).stdout
        if not legacy and any(re.search(r':'+str(p)+r'\s',ports) for p in [s['port'],s['backend_port']]):raise ValueError('A requested UDP port is already in use; select unused --port and --backend-port')
    backup=snapshot(s)
    if not LIB.exists() or args.bundle:install_payload(args.bundle or pathlib.Path(__file__).resolve().parent.parent)
    import pwd
    try:pwd.getpwnam('vps-vk')
    except KeyError:run(['useradd','--system','--no-create-home','--shell','/usr/sbin/nologin','vps-vk'])
    main,network=units(s)
    if legacy:
        if had_state:raise ValueError('Legacy adoption requires a new managed instance')
        run(['systemctl','stop','kit-freeturn','kit-freeturn-network'])
    elif had_state:run(['systemctl','stop',main,network],check=False)
    try:
        render_config(s);render_units(s);run(['systemctl','daemon-reload'])
        configure_fail2ban();run(['systemctl','reset-failed',main],check=False)
        run(['systemctl','start',main]);time.sleep(2)
        for name in [main,network]:
            if run(['systemctl','is-active',name]).stdout.strip()!='active':raise RuntimeError('Service failed after startup')
        run(['systemctl','enable',main,network]);out=write_profiles(s,args.qr)
        if legacy:run(['systemctl','disable','kit-freeturn','kit-freeturn-network'])
    except Exception:
        run(['systemctl','stop',main,network],check=False)
        # Restore this manager's previous files; first-install state remains root-only for diagnosis.
        for top in ['etc','var']:
            source=backup/top
            if source.exists():
                for p in source.rglob('*'):
                    if p.is_file():
                        target=pathlib.Path('/')/p.relative_to(backup);target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,target)
        run(['systemctl','daemon-reload'],check=False)
        if active:
            render_config(load_state(args.instance))
            run(['systemctl','start',main],check=False)
        if legacy:run(['systemctl','start','kit-freeturn'],check=False)
        raise
    print(json.dumps({'status':'ready','instance':s['instance'],'endpoint':s['endpoint']+':'+str(s['port']),'profiles':str(out),'backup_before_changes':str(backup),'keys_preserved':had_state or legacy or restored is not None,'version':VERSION},ensure_ascii=False,indent=2))

def status(s):
    main,network=units(s)
    data={'version':VERSION,'instance':s['instance'],'endpoint':s['endpoint']+':'+str(s['port']),'interface':iface(s),'services':{n:run(['systemctl','is-active',n],check=False).stdout.strip() for n in [main,network,'fail2ban']},'peers':len(run(['wg','show',iface(s),'peers'],check=False).stdout.splitlines()),'resources':run(['systemctl','show',main,'-p','MemoryCurrent','-p','NRestarts','-p','Result']).stdout.strip(),'ssh_policy':{k:run(['fail2ban-client','get','sshd',k],check=False).stdout.strip() for k in ['maxretry','findtime','bantime']}}
    print(json.dumps(data,ensure_ascii=False,indent=2))
    return 0 if all(v=='active' for v in data['services'].values()) and data['peers']==2 else 1

def backup_command(s,output):
    password=getpass.getpass('Backup passphrase (12+ characters): ')
    if password!=getpass.getpass('Repeat passphrase: '):raise ValueError('Passphrases differ')
    target=pathlib.Path(output)
    if target.exists():raise ValueError('Output already exists')
    data=encrypt_backup(json.dumps({'version':1,'state':s}).encode(),password)
    atomic_write(target,data);del password
    print('Encrypted backup: '+str(target)+'\nDownload it off the VPS. A copy on this VPS alone is not a migration backup.')

def uninstall(s):
    main,network=units(s);run(['systemctl','disable','--now',main,network]);network_down(s)
    for name in [main,network]:(pathlib.Path('/etc/systemd/system')/(name+'.service')).unlink(missing_ok=True)
    run(['systemctl','daemon-reload'])
    print('Transport disabled; its rules and interface removed. Keys, profiles, backups and SSH Fail2ban are retained.')

def main():
    parser=argparse.ArgumentParser(description='Lightweight FreeTurn for Android + VK TURN Proxy for iPhone')
    parser.add_argument('command',choices=['install','status','profiles','backup','restore','uninstall','network-up','network-down'])
    parser.add_argument('file',nargs='?');parser.add_argument('--instance',default='main')
    parser.add_argument('--endpoint');parser.add_argument('--port',type=int,default=56001);parser.add_argument('--backend-port',type=int,default=51830)
    parser.add_argument('--subnet',default='10.77.43.0/24');parser.add_argument('--vk-link-file');parser.add_argument('--bundle')
    parser.add_argument('--adopt-legacy',action='store_true');parser.add_argument('--qr',action='store_true')
    parser.add_argument('--show',action='store_true',help='Print secret import links to this terminal')
    args=parser.parse_args()
    if not hasattr(os,'geteuid') or os.geteuid()!=0:raise ValueError('Run as root on the VPS')
    os.umask(0o077)
    if args.command not in ['network-up','network-down','status']:
        import fcntl
        lock=open('/run/lock/vps-vk.lock','a')
        fcntl.flock(lock,fcntl.LOCK_EX)
    if args.command=='install':install(args)
    elif args.command=='restore':
        if not args.file:raise ValueError('Specify the encrypted backup file')
        password=getpass.getpass('Backup passphrase: ')
        source=pathlib.Path(args.file)
        if source.stat().st_size>2097152:raise ValueError('Backup exceeds size limit')
        restored=parse_backup(decrypt_backup(source.read_bytes(),password));del password
        install(args,restored)
    else:
        s=load_state(args.instance)
        if args.command=='network-up':network_up(s)
        elif args.command=='network-down':network_down(s)
        elif args.command=='status':return status(s)
        elif args.command=='profiles':
            if args.endpoint:
                s=migrate_state(s,args.endpoint);atomic_write(paths(s['instance'])[1]/'state.json',json.dumps(s,indent=2))
            out=write_profiles(s,args.qr);print(str(out))
            if args.show:
                for name,link in profile_links(s).items():print(name+':\n'+link)
        elif args.command=='backup':
            if not args.file:raise ValueError('Specify an encrypted output path')
            backup_command(s,args.file)
        elif args.command=='uninstall':uninstall(s)
    return 0

if __name__=='__main__':
    try:sys.exit(main())
    except (ValueError,RuntimeError,FileNotFoundError,PermissionError,subprocess.TimeoutExpired) as e:
        print('ERROR: '+str(e),file=sys.stderr);sys.exit(1)
