#!/usr/bin/env python

from re import findall
from subprocess import Popen, PIPE
from urllib import urlopen


def run_command(cmd):
    p = Popen(cmd.split(' '), stdout=PIPE, stdin=PIPE, stderr=PIPE)
    return p.communicate()[0].strip()


def dependencies_met(dependencies=[]):
    for dependency in dependencies:
        if not len(run_command('which %s' % dependency)):
            return False
    return True


def main():
    dependencies = ['dmidecode', ]
    if not dependencies_met(dependencies):
        print 'You need to have the following installed on your system: %s' % ', '.join(dependencies)
        exit(1)

    bios_str = run_command('dmidecode -s bios-version')
    if not bios_str:
        print 'Couldn\'t get BIOS version from dmidecode, try running as root (with sudo)'
        exit(1)
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
