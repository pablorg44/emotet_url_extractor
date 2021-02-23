# Emotet URL Extractor
This script tries to extract the URLs obfuscated in DOC macros from Emotet malware. I have modified Didier Stevens oledump tool (https://blog.didierstevens.com/programs/oledump-py/) to search the information in macros.

## Usage
To execute this script you only have to indicate the DOC macro to find the URLs:
```
python3 extract_urls_emotet.py DOC_FILE
```
You can find DOC files to test the script at app any run. Some examples:
https://app.any.run/tasks/261b1e0f-9bb2-449a-a084-cefbb971ae06/#
https://app.any.run/tasks/7c9e340a-af39-4475-a618-8883b103ba3b/#
#### Return value
```
[2021-02-23 19:23:09,290][INFO]: Generating options to oledump...
[2021-02-23 19:23:09,306][INFO]: Looking for macro with obfuscated base64 string...
[2021-02-23 19:23:10,935][INFO]: Checking base64 provided...
[2021-02-23 19:23:10,935][INFO]: Looking for pattern...
[2021-02-23 19:23:17,419][INFO]: Base64 found!
[2021-02-23 19:23:17,420][INFO]: Adjusting base64 padding...
[2021-02-23 19:23:17,737][INFO]: Cleaning base64...
URLs Emotet:
http://covisiononeness.org/new/F9v/
https://www.oshiscafe.com/wp-admin/5Dm/
https://lionrockbatteries.com/wp-snapshots/C/
https://www.schmuckfeder.net/reference/ubpV/
http://cirteklink.com/F0xAutoConfig/1Zb4/
https://nimbledesign.miami/wp-admin/C/
http://xunhong.net/sys-cache/D0/
```
