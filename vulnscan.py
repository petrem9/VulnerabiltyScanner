import portscanner

targets_ip = input('[+] * target ip: ')
port_number = int(input('[+] * nr of ports to scan(from 1 to): '))
vul_file = input('path to file with vulnerable software: ')
print('\n')

target = portscanner.PortScan(targets_ip, port_number)
target.scan()
with open(vul_file, 'r') as file:
    count = 0
    for banner in target.banners:
        file.seek(0)
        for line in file.readlines():
            if line.strip() in banner:
                print('[!!] vulnerable banner: "' + banner + '" on port: ' + str(target.open_ports[count]))
            count += 1
