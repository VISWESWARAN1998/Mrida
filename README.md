# Mrida
An opensource antivirus implementation - Successor of CyberGod KSGMPRH

![NA]("/images/scan.png")
![NA]("/images/update.png")

Mrida is an open source antivirus implementation which uses YARA and LSH to detect malicious programs. It is programmed using C++ 14.

# Requesting to scan a file with YARA signatures:

```python
import requests
r = requests.post("http://127.0.0.1:5660/scan_file_for_yara", data={"file": "D:/test.eicar", "target": "windows"})
r.json()
```

### OUTPUT:
```json
{
  "detections": [
    {
      "author": "Visweswaran",
      "description": "BOT",
      "name": "bot"
    },
    {
      "author": "UNKNOWN AUTHOR",
      "description": "EXAMPLE - 1",
      "name": "example"
    }
  ],
  "message": true
}
```

# Getting List of packers:

```python
import requests
r = requests.post("http://127.0.0.1:5660/scan_file_for_packer", data={"file": "D:/git-bash.exe"})
r.json()
```

### OUTPUT:
```json
{
  "detected": [
    "Microsoft_Visual_Cpp_80_DLL"
  ]
}
```

# Getting Shannon Entropy for file:

```python
r = requests.post("http://127.0.0.1:5660/shannon_entropy_for_file", data={"file": "D:/git-bash.exe"})
r.json()
```

### OUTPUT:
```json
{
  "entropy": 4.221405214084764
}
```

# Check whether a domain is blocked or not
```
http://127.0.0.1:5660/is_domain_blocked?host=www.test.com
```

### OUTPUT:
```json
{
  "message": false
}
```

# Perform virustotal scan on all running process:
```python
r = requests.post("http://127.0.0.1:5660/proc_scan", data={"type": "gui", "api": "[YOUR KEY]"})
```

# Getting the tlsh similarity distance for two hashes
```
r = requests.get("http://127.0.0.1:5660/get_tlsh_distance?hash_one=B0648D22F7D290B5D063033049BCA2BAA67FFDBFD920825BB3C4631E4DB0791AE35F56&hash_two=B0648D22F7D290B5D063033049BCA2BAA67FFDB55920825BB3C4631E4DB0791AE35F56")
r.json()
```

### OUTPUT:
```json
{
  "message": 6
}
```

# Check the threat database for matching hash. If nothing is matched will return -1
```python
r = requests.get("http://127.0.0.1:5660/check_threat_db?tlsh=FC55ADF47998802EC02A4437B961A6D96B307C975C865813FEA8BB1D3CEF160FD09677&min_size=3500&max_size=3543005&type=application/x-msdownload")
r.json()
```

The antivirus makes use of the following opensource libraries:

1. [YARA by VirusTotal](https://github.com/VirusTotal/yara)
2. [YARA wrapper for C++ by Avast](https://github.com/avast/yaracpp)
3. [JSON for C++ by Niels Lohmann](https://github.com/nlohmann/json)
4. [HTTP library for C++ by yhirose](https://github.com/yhirose/cpp-httplib)
5. [TLSH by trendmicro](https://github.com/trendmicro/tlsh)


License: GPL 2.0