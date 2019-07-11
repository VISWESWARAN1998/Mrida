# Mrida
An opensource antivirus implementation - Successor of CyberGod KSGMPRH

Mrida is an open source antivirus implementation which uses YARA to detect malicious programs. It is programmed using C++ 14.

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

The antivirus makes use of the following opensource libraries:

1. [YARA by VirusTotal](https://github.com/VirusTotal/yara)
2. [YARA wrapper for C++ by Avast](https://github.com/avast/yaracpp)
3. [JSON for C++ by Niels Lohmann](https://github.com/nlohmann/json)
4. [HTTP library for C++ by yhirose](https://github.com/yhirose/cpp-httplib)