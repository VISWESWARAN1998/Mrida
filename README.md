# Mrida
An opensource antivirus implementation - Successor of CyberGod KSGMPRH

Mrida is an open source antivirus implementation which uses YARA to detect malicious programs. It is programmed using C++ 14.

# Requestiong to scan a threat:

```python
import requests
r = requests.post("http://127.0.0.1:5660/scan_file", data={"file": "D:/test.eicar"})
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

The antivirus makes use of the following opensource libraries:

1. [YARA by VirusTotal](https://github.com/VirusTotal/yara)
2. [YARA wrapper for C++ by Avast](https://github.com/avast/yaracpp)
3. [JSON for C++ by Niels Lohmann](https://github.com/nlohmann/json)
4. [HTTP library for C++ by yhirose](https://github.com/yhirose/cpp-httplib)