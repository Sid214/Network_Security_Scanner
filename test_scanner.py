import sys
sys.path.insert(0, 'network_security_scanner/backend')
import scanner

print('=== Testing adapter detection ===')
net = scanner.detect_local_network_info()
print('Local IP: ', net['local_ip'])
print('Gateway:  ', net['gateway'])
print('Subnet:   ', net['subnet'])
print('Netmask:  ', net['netmask'])
print('Interface:', net['interface'])
print('Method:   ', net['detection_method'])
print('DNS:      ', net['dns_server'])
print()
print('=== ARP table ===')
arp = scanner.parse_arp_table()
for h in arp[:10]:
    print(' ', h['ip_address'], ' ', h['mac_address'])
print('Total ARP entries:', len(arp))
print()
print('=== Nmap check ===')
nmap = scanner.get_nmap_path()
print('Nmap:', nmap)
print()
print('=== Admin check ===')
print('Admin:', scanner.is_admin())
print()
print('=== Diagnostics ===')
diag = scanner.get_discovery_diagnostics()
for k, v in diag.items():
    if k not in ('arp_host_list', 'limitations', 'discovery_methods'):
        print(k+':', v)
