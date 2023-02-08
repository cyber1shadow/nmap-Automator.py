import pyfiglet
ascii_banner = pyfiglet.figlet_format('nmap Automator')
print(ascii_banner)

ip_input = input('Enter Your IP:')

if ip_input.count('.') >=3:
    type = input('Enter THe type of Scan\n1)tcp scan\n2)udp scan:')
    ip_list = ip_input.split()
    scan_input = input('Enter Your Scan:')
    scan_type = scan_input.split()


    f = open("script Automator.py", "w")

    f.write(
"import nmap\n"+
"scanner = nmap.PortScanner()\n"
"ip_list = {}\n".format(ip_list)+
"scan_type = {}\n".format(scan_type)+
"type={}\n".format(type)+
'''
try:
    if type == 1:
        for ip in ip_list:
            for scan in scan_type:
                print('------------------')
                print('Starting Nmap : {} '.format(scanner.nmap_version()))
                scanner.scan(ip, '1-65535', scan)
                for host in scanner.all_hosts():
                    for proto in scanner[host].all_protocols():
                            print('Protocol : %s' % proto)
                            print('Nmap scan report for: %s ' %(ip),'(%s)' % scanner[ip].hostname())
                            print('Host is : %s ' % scanner[ip].state())
                            print('type Scan :',scan)
                            print('------------------')
                            lport = scanner[ip]['tcp'].keys()
                            for port in lport:
                                print('port : %s\tstate : %s\tservice : %s' % (
                                port, scanner[host][proto][port]['state'], scanner[host][proto][port]['name']))
                            print('Not shown: {} closed tcp ports'.format(65535-len(lport)))
    if type == 2:
        for ip in ip_list:
            for scan in scan_type:
                print('------------------')
                print('Starting Nmap : {} '.format(scanner.nmap_version()))
                scanner.scan(ip, '1-65535', scan)
                for host in scanner.all_hosts():
                    for proto in scanner[host].all_protocols():
                        print('Protocol : %s' % proto)
                        print('Nmap scan report for: %s ' % (ip), '(%s)' % scanner[ip].hostname())
                        print('Host is : %s ' % scanner[ip].state())
                        print('type Scan :', scan)
                        print('------------------')
                        lport = scanner[ip]['udp'].keys()
                        for port in lport:
                            print('port : %s\tstate : %s\tservice : %s' % (
                            port, scanner[host][proto][port]['state'], scanner[host][proto][port]['name']))
                        print('Not shown: {} closed udp ports'.format(65535 - len(lport)))
except KeyError:
    print('your ip is wrong')''')

    f.close
else:
    print('plese enter valid ip')
