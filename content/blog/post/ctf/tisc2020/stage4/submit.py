from pwn import *
import time
from calendar import timegm
import subprocess
import os


def get_domain(seed):
    cmds = """
    set verbose off
    break *0x0000000000661501
    break *0x0000000000661726
    run
    set $rdx={0}
    continue
    
    define fn
    x/1s $rax
    p $rcx
    end

    fn

    quit
    """
    cmdtxt = cmds.format(seed)
    if os.path.exists("cmd.txt"):
        os.system("rm cmd.txt")

    with open("cmd.txt","w+") as f:
        f.write(cmdtxt)
    
    while True:
        try:
            output = subprocess.check_output(["gdb", "--command=cmd.txt","--batch","anorocware"]).decode("utf-8")
            break
        except:
            time.sleep(5)
            pass
    
    output = output.split("\n")
    domainout = output[-3]
    lenout  = output[-2]
    domainout = domainout.split("\"")[1].split("\"")[0]
    lenout = lenout.split("=")[1]
    lenout = int(lenout, 16)
    domain = domainout[:lenout]

    return domain


def getseed(timestr):
    utc_time = time.strptime(timestr, "%Y-%m-%dT%H:%M:%S.%fZ")
    epoch_time = timegm(utc_time)

    return hex(epoch_time>>0xf)


token = "QEHqrUlewAbQxJUaHxNqcbHJioGMlhSLUEsyOIjoNlmDDICAQTcsiyoeaLcYhTQI"

r = remote("fqybysahpvift1nqtwywevlr7n50zdzp.ctf.sg", 31090)

r.sendline(token)

with open("log.txt","a+") as f:
    f.write("BEGINNING A NEW TRIAL")

while True:
    print (r.recvuntil("servers on "))
    timestr = r.recvuntil("Z").decode("utf-8")
    seed = getseed(timestr)
            
    print ("[+]timestr:", timestr)
    print ("[+]seed:", seed)
 
    domain = get_domain(seed)
    print (domain)
    
    with open("log.txt","a+") as f:
        f.write("timestr:"+timestr+"\n")
        f.write("seed:"+seed+"\n")
        f.write("domain:"+domain+"\n")
        f.write("-"*80+"\n")

    r.sendline(domain)



r.interactive()

