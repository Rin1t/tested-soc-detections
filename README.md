# Tested SOC Detections

Three high-value Windows detection rules, each **tested against real attack logs** before release.
Every rule ships as **Sigma**, a ready-to-run **Splunk** search, and **Microsoft Sentinel / Defender XDR** KQL.

| Rule | ATT&CK | Level | Tested against real attacks |
|---|---|---|---|
| [Office application spawning a script interpreter](rules/proc_creation_win_office_spawns_script_interpreter.yml) | T1566.001, T1204.002 | High | Detected 2 real events in a malware log file |
| [Shadow copy or backup catalog deletion](rules/proc_creation_win_shadow_copy_deletion.yml) | T1490 | Critical | Detected 5 real attack events in 2 attack log files |
| [LSASS memory dump via comsvcs MiniDump](rules/proc_creation_win_lsass_dump_comsvcs.yml) | T1003.001 | Critical | Detected 3 real attacks in 3 attack log files |

## Why these three

- **Office spawning a script interpreter** is the most common first step of a phishing payload: Word or Excel
  launching PowerShell, cmd, wscript or mshta.
- **Shadow copy deletion** usually happens minutes before ransomware encrypts. Treat it as critical every time.
- **LSASS dump via comsvcs** is a favourite "living off the land" way to steal credentials without dropping Mimikatz.

## How they were tested

Each rule was run against public attack datasets (EVTX-ATTACK-SAMPLES, the Yamato Security sample collection and
related public repositories), plus a benign look-alike it must ignore (same tool, harmless arguments).
None of the three alerted on a 163-event corpus of everyday Windows, Linux and cloud admin activity.

## Quick start

### Splunk

1. Copy [`splunk/macros.conf`](splunk/macros.conf) into an app's `local/macros.conf` (or create the macros in
   Settings > Advanced search > Search macros).
2. Set `soc_fk_index` to your indexes, for example `(index=wineventlog OR index=sysmon)`.
3. Run the searches in [`queries/splunk/`](queries/splunk/). They accept Sysmon Event ID 1 **and** Windows
   Security 4688; the `soc_fk_process_creation` macro normalizes both to the same field names. Windows inputs
   need `renderXml = true`.

### Microsoft Sentinel / Defender XDR

Open the `.kql` file in [`queries/sentinel_kql/`](queries/sentinel_kql/). Each file has one query per data source
(`DeviceProcessEvents` for Defender for Endpoint, `SecurityEvent` / Sysmon for Sentinel). Use the one you collect,
then create a scheduled analytics rule.

### Any other SIEM

Convert the Sigma rules with [sigma-cli](https://github.com/SigmaHQ/sigma-cli), for example
`sigma convert -t lucene -p ecs_windows rules/`.

**Before enabling alerts,** run each query over the last 30 days and add exclusions for the approved activity
listed under `falsepositives` in each rule.

## Want the full kit?

These rules come from the **SOC Field Kit**, which includes:

- **111 tested Sigma rules** across Windows, Active Directory, Entra ID, Microsoft 365, AWS, Azure, Linux, web and DNS.
  57 of them detected real attacks in public datasets (Mimikatz, Impacket, PsExec, Kerbrute, UAC bypasses,
  Golden SAML and more)
- A **Splunk app** with 109 searches and one macro per data source
- **Sentinel / Defender XDR queries** for every rule, validated with Microsoft's Kusto parser
- **11 investigation playbooks** with client escalation templates
- A **361 use case library** mapped to MITRE ATT&CK and NCA ECC-2:2024 controls
- The full **test harness and test report**

👉 **[thamerin.gumroad.com](https://thamerin.gumroad.com)**: start with the
[free sample](https://thamerin.gumroad.com/l/soc-free-sample) or get the
[Complete Kit](https://thamerin.gumroad.com/l/soc-field-kit).

## License

Free for personal use and for use inside your own organization. Please link to this repository rather than
redistributing the files.

## Author

**Thamer Alshammari**, SOC analyst at a managed security provider.
Questions, issues and rule requests are welcome: open an issue or email Thamer.rin@gmail.com.
