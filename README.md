# Open SSTP Client for Android <img src="https://github.com/kittoku/Open-SSTP-Client/raw/master/images/icon.png" height="40">
This is an open-sourced Secure Socket Tunneling Protocol (MS-SSTP) client for Android, developed for accessing to 
[VPN Azure Cloud](https://www.vpnazure.net/). So no test with other servers is done. Its behavior may be still unstable.

## Installation
* You need to [allow unknown sources](https://developer.android.com/studio/publish/#unknown-sources) 
* Download .apk file [here](https://github.com/kittoku/Open-SSTP-Client/raw/master/releases/0.0.1/release/app-release.apk) and install it

## Usage
Fill `Host`, `Username` and `Password` fields and push `CONNECT` button. If a key icon gets to show on the right side of the status bar, 
establishing a VPN connection has been succeeded. To disconnect the connection, push `DISCONNECT` in the main activity or 
the notification.  
<br>
![a screenshot taken when establishing a connecting was successful](https://github.com/kittoku/Open-SSTP-Client/raw/master/images/example.jpg "success in connecting")

## Notice
For a time I will support only usage through VPN Azure Cloud.

## License
Licensed under MIT. Be sure you use this software at your own risk. 

## Known issues
* ~~heavy CPU usage due to using many coroutines~~ (Not so much in my device. Please let me know if it's problematic.)
* cannot access to a DHCP-disabled server 

## To do
* decrease coroutines to two for incoming/outgoing packets
* get able to access to a server with a self-signed certificate

## Release
0.0.1 - first release