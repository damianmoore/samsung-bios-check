#!/usr/bin/env python

from re import findall
from subprocess import Popen, PIPE
from urllib import urlopen


def run_command(cmd):
    p = Popen(cmd.split(' '), stdout=PIPE, stdin=PIPE, stderr=PIPE)
    return p.communicate()[0].strip()


def main():
    bios_str = open('/sys/devices/virtual/dmi/id/bios_version').read().strip()
    if not findall(r'[0-9]{2}[A-z]{2,3}', bios_str):
        print 'Sorry, I only understand BIOS versions in the format [0-9]{2}[A-z]{2,3}. Yours is %s' % bios_str
        exit(1)
    bios_version = int(findall(r'[0-9]{2}', bios_str)[0])
    bios_model = findall(r'[A-Z]{2,3}', bios_str)[0]
    print 'BIOS version installed: %d (%s)' % (bios_version, bios_str)

    url = 'http://sbuservice.samsungmobile.com/BUWebServiceProc.asmx/GetContents?platformID=%s&PartNumber=AAAA' % bios_model
    response = urlopen(url).read()

    try:
        web_str = findall(r'<Version>([A-Z0-9]+)</Version>', response)[0]
        web_version = int(findall(r'[0-9]{2}', web_str)[0])
        print 'BIOS version available: %d (%s)' % (web_version, web_str)

        if web_version > bios_version:
            print '\nBIOS UPDATE AVAILABLE!'
        else:
            print '\nYour BIOS is up to date'
    except IndexError:
        print 'Sorry, got a bad response from the Samsung website:\n\n%s' % response
        exit(1)


if __name__ == '__main__':
    main()
