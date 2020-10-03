# extract-mfg

Extract mfg.dat and AT&T root certs from BGW210 or NVG599.

This script assumes it is being run on a Windows PC with the **mfg_dat_decode.exe** program. It will exploit the gateway and download the certs as well run the **mfg_dat_decode.exe** program to save the EAP-TLS credentials into a local folder. The local folder will be named `<ModelNumber>_<SerialNumber>` and will exist in the same directory as the script.

If you include `--install_backdoor` as a command argument then it will install a telnet backdoor on port 28 that will persist with reboots and firmware upgrades.

You can also include `--update_firmware` as a command argument to install the latest firmware stored in this repo as the last step of the process. This will start a local HTTP server and the gateway will try to download the firmware (Windows firewall may block this by default). You need specify your local IP address, by using the `--server_address` command argument, for it to work correctly.

## Instructions

1. Downgrade your Gateway
   - BGW210-700 to version [1.0.29](Firmware/spTurquoise210-700_1.0.29.bin?raw=true)
   - NVG599 to version [9.2.2h0d83](Firmware/spnvg599-9.2.2h0d83.bin?raw=true) OR upgrade to version [9.2.2h0d79](Firmware/spnvg599-cferom-9.2.2h0d79.bin?raw=true)
2. Install Python3 if you don't already have it
3. Install Python dependencies:
	```
	pip install requests bs4 wget
	```
4. Run the script: 
	```
	python extract_mfg.py <ACCESS_CODE> <DEVICE_ADDRESS> --install_backdoor
	```

## Credits & References

- [Streiw](https://www.reddit.com/r/ATT/comments/g59rwm/bgw210700_root_exploitbypass): BGW210 Exploit Instructions
- [devicelocksmith](https://www.devicelocksmith.com/2018/12/eap-tls-credentials-decoder-for-nvg-and.html): EAP-TLS credentials decoder and the method to extract *mfg.dat*
- [earlz](http://earlz.net/view/2012/06/07/0026/rooting-the-nvg510-from-the-webui): Commands that can be run on the Arris gateways
- [nomotion](https://www.nomotion.net/blog/sharknatto/): Exploits discovered on Arris gateways
