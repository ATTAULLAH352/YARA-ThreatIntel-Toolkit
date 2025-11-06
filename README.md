# 🛡️ cheat sheet for malware analysts and blue teamers. Includes real-world YARA rules, IOC scanning workflows, memory forensics, and network analysis using tools like Loki, THOR Lite, YAYA, Fenrir, Cuckoo Sandbox, Volatility, Wireshark, and VirusTotal — with actionable commands and expected outputs.

<p align="center">
  <img src="https://i.ibb.co/qL6MP5ML/IMG-20251106-220341.jpg" alt="Description" width="400"/>
</p>




## 1. YARA — Create & Run Rules

**Example Rule (`suspicious.yar`):**

```yara
rule SuspiciousExample {
  meta:
    author = "Atta"
    description = "Detects suspicious string and small file"
  strings:
    $s1 = "malware_test"
    $s2 = { 6A 40 68 ?? ?? ?? ?? }   // example byte pattern
  condition:
    any of ($s*) and filesize < 100KB
}
```

**Scan a file:**

```bash
yara suspicious.yar sample.exe
```

**Expected output:**

```
SuspiciousExample  sample.exe
```

**Recursively scan a directory:**

```bash
yara -r rules/ /home/atta/malware_samples/
```

---

## 2. Loki — Quick IOC + YARA Scan

**Linux scan:**

```bash
./loki.sh -p /home/atta/malware_samples --update
```

**Expected output snippet:**

```
[+] Scanning: /home/atta/malware_samples/sample.exe
[!] YARA match: SuspiciousExample
[+] Hash: SHA256: 9a1b2c3d...
```

**Windows scan:**

```cmd
loki.exe -p C:\malware_samples --update
```

---

## 3. THOR Lite — Advanced IOC/YARA Scan

**Windows scan:**

```cmd
thor64-lite.exe -p C:\malware_samples -o report.json
```

**Linux scan:**

```bash
./thor64-lite -p /home/atta/malware_samples -o report.json
```

**Expected output snippet (`report.json`):**

```json
{
  "file": "sample.exe",
  "yara_matches": ["SuspiciousExample"],
  "score": 15
}
```

---

## 4. YAYA — Manage & Run YARA Rule Sets

**Update & scan:**

```bash
yaya update
yaya add /home/atta/custom_rules
yaya scan /home/atta/malware_samples
yaya export /tmp/all_rules.yar
```

**Expected output snippet:**

```
Scanning 10 files...
YARA Match: SuspiciousExample -> sample.exe
Scan completed: 1 match found
```

---

## 5. Fenrir — Lightweight YARA Helper

**Search for patterns in rules:**

```bash
./fenrir.sh search "malware_test" /home/atta/yara_rules
```

**Expected output:**

```
Rule SuspiciousExample contains string: malware_test
```

---

## 6. Cuckoo Sandbox — Automated Malware Analysis

**Submit a sample:**

```bash
cuckoo submit /home/atta/malware_samples/sample.exe --timeout 300 --package windows
```

**Expected output snippet:**

```
[+] Submitted sample.exe for analysis
[+] Analysis ID: 12
[+] Access report: http://127.0.0.1:8000/analysis/12/
```

---

## 7. Volatility — Memory Forensics

**List processes from memory dump:**

```bash
volatility3 -f memory.dmp windows.pslist.PsList
```

**Expected output:**

```
PID   Name
0     System
4     smss.exe
1234  sample.exe
```

**Dump process memory by PID:**

```bash
volatility3 -f memory.dmp windows.memmap.MemMap --pid 1234
```

---

## 8. Wireshark / Tshark — Network Analysis

**Capture traffic (CLI):**

```bash
sudo tshark -i eth0 -w capture.pcap
```

**Filter suspicious HTTP traffic:**

```
ip.addr == 192.168.1.100 && tcp.port == 80
```

**Extract objects (GUI):**

```
File → Export Objects → HTTP
```

---

## 9. VirusTotal — Multi-Engine Scans

**Scan a file via CLI:**

```bash
vt file scan sample.exe
```

**Get file report by SHA256:**

```bash
vt file report 9a1b2c3d4e5f67890abcdef...
```

**Expected output snippet:**

```
malware_test.exe detected by 5/70 engines
```

---

## 💡 Quick Workflow Example

1. **Triage suspicious files:** Loki → `/home/atta/malware_samples`  
2. **Run curated YARA rules:** YAYA → scan & export rules  
3. **Behavioral analysis:** Cuckoo Sandbox → dynamic execution  
4. **Memory analysis:** Volatility → scan memory dumps, apply YARA rules  
5. **Network analysis:** Wireshark → capture and inspect traffic  
6. **Reputation lookup:** VirusTotal → verify hashes and detections  
7. **Full IOC sweep:** THOR Lite → scored YARA & IOC matches  

---

## 📚 References

- [YARA Docs](https://yara.readthedocs.io/)
- [Loki GitHub](https://github.com/Neo23x0/Loki)
- [THOR Lite Docs](https://www.nextron-systems.com/thor-lite/)
- [YAYA GitHub](https://github.com/infosec-au/yaya)
- [Cuckoo Sandbox](https://cuckoosandbox.org/)
- [Volatility 3](https://github.com/volatilityfoundation/volatility3)

---

>  Tip: Combine these tools in your malware triage pipeline for layered detection, forensic depth, and automation.
