## Statistics

This version of ATT&CK contains 877 Software, 170 Groups, and 50 Campaigns.

Broken out by domain:

* Enterprise: 14 Tactics, 211 Techniques, 468 Sub-Techniques, 166 Groups, 755 Software, 47 Campaigns, 44 Mitigations, 37 Data Sources, and 106 Data Components
* Mobile: 12 Tactics, 75 Techniques, 46 Sub-Techniques, 15 Groups, 118 Software, 3 Campaigns, 13 Mitigations, 6 Data Sources, and 17 Data Components
* ICS: 12 Tactics, 83 Techniques, 14 Groups, 23 Software, 7 Campaigns, 52 Mitigations, 14 Assets, 17 Data Sources, and 36 Data Components

## Key

* New objects: ATT&CK objects which are only present in the new release.
* Major version changes: ATT&CK objects that have a major version change. (e.g. 1.0 → 2.0)
* Minor version changes: ATT&CK objects that have a minor version change. (e.g. 1.0 → 1.1)
* Other version changes: ATT&CK objects that have a version change of any other kind. (e.g. 1.0 → 1.2)
* Patches: ATT&CK objects that have been patched while keeping the version the same. (e.g., 1.0 → 1.0 but something like a typo, a URL, or some metadata was fixed)
* Object revocations: ATT&CK objects which are revoked by a different object.
* Object deprecations: ATT&CK objects which are deprecated and no longer in use, and not replaced.
* Object deletions: ATT&CK objects which are no longer found in the STIX data.

## Techniques

### Enterprise

#### New Techniques

* [Cloud Application Integration](/techniques/T1671) <small style="color:#929393">(v1.0)</small>
* Command and Scripting Interpreter: [Hypervisor CLI](/techniques/T1059/012) <small style="color:#929393">(v1.0)</small>
* [ESXi Administration Command](/techniques/T1675) <small style="color:#929393">(v1.0)</small>
* [Email Bombing](/techniques/T1667) <small style="color:#929393">(v1.0)</small>
* [Email Spoofing](/techniques/T1672) <small style="color:#929393">(v1.0)</small>
* [Exclusive Control](/techniques/T1668) <small style="color:#929393">(v1.0)</small>
* Hide Artifacts: [Bind Mounts](/techniques/T1564/013) <small style="color:#929393">(v1.0)</small>
* Hide Artifacts: [Extended Attributes](/techniques/T1564/014) <small style="color:#929393">(v1.0)</small>
* [Input Injection](/techniques/T1674) <small style="color:#929393">(v1.0)</small>
* Masquerading: [Overwrite Process Arguments](/techniques/T1036/011) <small style="color:#929393">(v1.0)</small>
* Obfuscated Files or Information: [Compression](/techniques/T1027/015) <small style="color:#929393">(v1.0)</small>
* Obfuscated Files or Information: [Junk Code Insertion](/techniques/T1027/016) <small style="color:#929393">(v1.0)</small>
* Obfuscated Files or Information: [SVG Smuggling](/techniques/T1027/017) <small style="color:#929393">(v1.0)</small>
* Remote Access Tools: [IDE Tunneling](/techniques/T1219/001) <small style="color:#929393">(v1.0)</small>
* Remote Access Tools: [Remote Access Hardware](/techniques/T1219/003) <small style="color:#929393">(v1.0)</small>
* Remote Access Tools: [Remote Desktop Software](/techniques/T1219/002) <small style="color:#929393">(v1.0)</small>
* Server Software Component: [vSphere Installation Bundles](/techniques/T1505/006) <small style="color:#929393">(v1.0)</small>
* Software Extensions: [Browser Extensions](/techniques/T1176/001) <small style="color:#929393">(v1.0)</small>
* Software Extensions: [IDE Extensions](/techniques/T1176/002) <small style="color:#929393">(v1.0)</small>
* System Services: [Systemctl](/techniques/T1569/003) <small style="color:#929393">(v1.0)</small>
* Trusted Developer Utilities Proxy Execution: [JamPlus](/techniques/T1127/003) <small style="color:#929393">(v1.0)</small>
* User Execution: [Malicious Copy and Paste](/techniques/T1204/004) <small style="color:#929393">(v1.0)</small>
* [Virtual Machine Discovery](/techniques/T1673) <small style="color:#929393">(v1.0)</small>
* [Wi-Fi Networks](/techniques/T1669) <small style="color:#929393">(v1.0)</small>

#### Major Version Changes

* Hijack Execution Flow: [DLL](/techniques/T1574/001) <small style="color:#929393">(v1.3&#8594;v2.0)</small>
* Masquerading: [Match Legitimate Resource Name or Location](/techniques/T1036/005) <small style="color:#929393">(v1.2&#8594;v2.0)</small>
* Masquerading: [Rename Legitimate Utilities](/techniques/T1036/003) <small style="color:#929393">(v1.1&#8594;v2.0)</small>
* [Modify Registry](/techniques/T1112) <small style="color:#929393">(v1.4&#8594;v2.0)</small>
* [Remote Access Tools](/techniques/T1219) <small style="color:#929393">(v2.3&#8594;v3.0)</small>
* [Software Extensions](/techniques/T1176) <small style="color:#929393">(v1.3&#8594;v2.0)</small>

#### Minor Version Changes

* [Abuse Elevation Control Mechanism](/techniques/T1548) <small style="color:#929393">(v1.4&#8594;v1.5)</small>
  * [Bypass User Account Control](/techniques/T1548/002) <small style="color:#929393">(v2.1&#8594;v2.2)</small>
  * [Elevated Execution with Prompt](/techniques/T1548/004) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
  * [Setuid and Setgid](/techniques/T1548/001) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
  * [Sudo and Sudo Caching](/techniques/T1548/003) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Access Token Manipulation](/techniques/T1134) <small style="color:#929393">(v2.0&#8594;v2.1)</small>
  * [Create Process with Token](/techniques/T1134/002) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
  * [Make and Impersonate Token](/techniques/T1134/003) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
  * [Parent PID Spoofing](/techniques/T1134/004) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
  * [SID-History Injection](/techniques/T1134/005) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
  * [Token Impersonation/Theft](/techniques/T1134/001) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
* [Account Access Removal](/techniques/T1531) <small style="color:#929393">(v1.3&#8594;v1.4)</small>
* [Account Discovery](/techniques/T1087) <small style="color:#929393">(v2.5&#8594;v2.6)</small>
  * [Local Account](/techniques/T1087/001) <small style="color:#929393">(v1.4&#8594;v1.5)</small>
* [Account Manipulation](/techniques/T1098) <small style="color:#929393">(v2.7&#8594;v2.8)</small>
  * [SSH Authorized Keys](/techniques/T1098/004) <small style="color:#929393">(v1.3&#8594;v1.4)</small>
* Acquire Infrastructure: [Botnet](/techniques/T1583/005) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* Acquire Infrastructure: [Web Services](/techniques/T1583/006) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
* [Adversary-in-the-Middle](/techniques/T1557) <small style="color:#929393">(v2.4&#8594;v2.5)</small>
  * [Evil Twin](/techniques/T1557/004) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Application Layer Protocol](/techniques/T1071) <small style="color:#929393">(v2.3&#8594;v2.4)</small>
  * [DNS](/techniques/T1071/004) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
  * [File Transfer Protocols](/techniques/T1071/002) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
  * [Mail Protocols](/techniques/T1071/003) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
  * [Publish/Subscribe Protocols](/techniques/T1071/005) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
  * [Web Protocols](/techniques/T1071/001) <small style="color:#929393">(v1.3&#8594;v1.4)</small>
* [Automated Collection](/techniques/T1119) <small style="color:#929393">(v1.3&#8594;v1.4)</small>
* [Automated Exfiltration](/techniques/T1020) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
  * [Traffic Duplication](/techniques/T1020/001) <small style="color:#929393">(v1.3&#8594;v1.4)</small>
* [BITS Jobs](/techniques/T1197) <small style="color:#929393">(v1.4&#8594;v1.5)</small>
* [Boot or Logon Autostart Execution](/techniques/T1547) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
  * [Active Setup](/techniques/T1547/014) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
  * [Authentication Package](/techniques/T1547/002) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
  * [Kernel Modules and Extensions](/techniques/T1547/006) <small style="color:#929393">(v1.3&#8594;v1.4)</small>
  * [LSASS Driver](/techniques/T1547/008) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
  * [Login Items](/techniques/T1547/015) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
  * [Port Monitors](/techniques/T1547/010) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
  * [Print Processors](/techniques/T1547/012) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
  * [Re-opened Applications](/techniques/T1547/007) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
  * [Registry Run Keys / Startup Folder](/techniques/T1547/001) <small style="color:#929393">(v2.0&#8594;v2.1)</small>
  * [Security Support Provider](/techniques/T1547/005) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
  * [Shortcut Modification](/techniques/T1547/009) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
  * [Time Providers](/techniques/T1547/003) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
  * [Winlogon Helper DLL](/techniques/T1547/004) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
  * [XDG Autostart Entries](/techniques/T1547/013) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Boot or Logon Initialization Scripts](/techniques/T1037) <small style="color:#929393">(v2.3&#8594;v2.4)</small>
  * [RC Scripts](/techniques/T1037/004) <small style="color:#929393">(v2.1&#8594;v2.2)</small>
  * [Startup Items](/techniques/T1037/005) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Browser Session Hijacking](/techniques/T1185) <small style="color:#929393">(v2.0&#8594;v2.1)</small>
* [Brute Force](/techniques/T1110) <small style="color:#929393">(v2.6&#8594;v2.7)</small>
  * [Credential Stuffing](/techniques/T1110/004) <small style="color:#929393">(v1.6&#8594;v1.7)</small>
  * [Password Cracking](/techniques/T1110/002) <small style="color:#929393">(v1.3&#8594;v1.4)</small>
  * [Password Guessing](/techniques/T1110/001) <small style="color:#929393">(v1.6&#8594;v1.7)</small>
  * [Password Spraying](/techniques/T1110/003) <small style="color:#929393">(v1.6&#8594;v1.7)</small>
* [Cloud Administration Command](/techniques/T1651) <small style="color:#929393">(v2.0&#8594;v2.1)</small>
* [Cloud Service Dashboard](/techniques/T1538) <small style="color:#929393">(v1.4&#8594;v1.5)</small>
* [Command and Scripting Interpreter](/techniques/T1059) <small style="color:#929393">(v2.5&#8594;v2.6)</small>
  * [AppleScript](/techniques/T1059/002) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
  * [AutoHotKey & AutoIT](/techniques/T1059/010) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
  * [Cloud API](/techniques/T1059/009) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
  * [Lua](/techniques/T1059/011) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
  * [Network Device CLI](/techniques/T1059/008) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
  * [PowerShell](/techniques/T1059/001) <small style="color:#929393">(v1.4&#8594;v1.5)</small>
  * [Python](/techniques/T1059/006) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
  * [Unix Shell](/techniques/T1059/004) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
  * [Visual Basic](/techniques/T1059/005) <small style="color:#929393">(v1.4&#8594;v1.5)</small>
  * [Windows Command Shell](/techniques/T1059/003) <small style="color:#929393">(v1.4&#8594;v1.5)</small>
* [Compromise Host Software Binary](/techniques/T1554) <small style="color:#929393">(v2.1&#8594;v2.2)</small>
* [Compromise Infrastructure](/techniques/T1584) <small style="color:#929393">(v1.5&#8594;v1.6)</small>
* [Container Administration Command](/techniques/T1609) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
* [Create Account](/techniques/T1136) <small style="color:#929393">(v2.5&#8594;v2.6)</small>
  * [Local Account](/techniques/T1136/001) <small style="color:#929393">(v1.3&#8594;v1.4)</small>
* Create or Modify System Process: [Launch Agent](/techniques/T1543/001) <small style="color:#929393">(v1.4&#8594;v1.5)</small>
* Create or Modify System Process: [Launch Daemon](/techniques/T1543/004) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
* Create or Modify System Process: [Systemd Service](/techniques/T1543/002) <small style="color:#929393">(v1.5&#8594;v1.6)</small>
* Create or Modify System Process: [Windows Service](/techniques/T1543/003) <small style="color:#929393">(v1.5&#8594;v1.6)</small>
* [Data Destruction](/techniques/T1485) <small style="color:#929393">(v1.3&#8594;v1.4)</small>
  * [Lifecycle-Triggered Deletion](/techniques/T1485/001) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Data Encoding](/techniques/T1132) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
  * [Non-Standard Encoding](/techniques/T1132/002) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
  * [Standard Encoding](/techniques/T1132/001) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Data Encrypted for Impact](/techniques/T1486) <small style="color:#929393">(v1.4&#8594;v1.5)</small>
* [Data Obfuscation](/techniques/T1001) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
  * [Junk Data](/techniques/T1001/001) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
  * [Protocol or Service Impersonation](/techniques/T1001/003) <small style="color:#929393">(v2.0&#8594;v2.1)</small>
  * [Steganography](/techniques/T1001/002) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Data Staged](/techniques/T1074) <small style="color:#929393">(v1.4&#8594;v1.5)</small>
  * [Local Data Staging](/techniques/T1074/001) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
  * [Remote Data Staging](/techniques/T1074/002) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Data Transfer Size Limits](/techniques/T1030) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Data from Configuration Repository](/techniques/T1602) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
  * [Network Device Configuration Dump](/techniques/T1602/002) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
  * [SNMP (MIB Dump)](/techniques/T1602/001) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Data from Local System](/techniques/T1005) <small style="color:#929393">(v1.6&#8594;v1.7)</small>
* [Data from Network Shared Drive](/techniques/T1039) <small style="color:#929393">(v1.4&#8594;v1.5)</small>
* [Data from Removable Media](/techniques/T1025) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
* [Debugger Evasion](/techniques/T1622) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Defacement](/techniques/T1491) <small style="color:#929393">(v1.3&#8594;v1.4)</small>
  * [Internal Defacement](/techniques/T1491/001) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Deobfuscate/Decode Files or Information](/techniques/T1140) <small style="color:#929393">(v1.3&#8594;v1.4)</small>
* [Deploy Container](/techniques/T1610) <small style="color:#929393">(v1.3&#8594;v1.4)</small>
* [Direct Volume Access](/techniques/T1006) <small style="color:#929393">(v2.2&#8594;v2.3)</small>
* [Disk Wipe](/techniques/T1561) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
  * [Disk Content Wipe](/techniques/T1561/001) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
  * [Disk Structure Wipe](/techniques/T1561/002) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Domain or Tenant Policy Modification](/techniques/T1484) <small style="color:#929393">(v3.1&#8594;v3.2)</small>
  * [Group Policy Modification](/techniques/T1484/001) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
  * [Trust Modification](/techniques/T1484/002) <small style="color:#929393">(v2.1&#8594;v2.2)</small>
* [Drive-by Compromise](/techniques/T1189) <small style="color:#929393">(v1.6&#8594;v1.7)</small>
* [Dynamic Resolution](/techniques/T1568) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
  * [DNS Calculation](/techniques/T1568/003) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
  * [Domain Generation Algorithms](/techniques/T1568/002) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
  * [Fast Flux DNS](/techniques/T1568/001) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* Email Collection: [Local Email Collection](/techniques/T1114/001) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Encrypted Channel](/techniques/T1573) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
  * [Asymmetric Cryptography](/techniques/T1573/002) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
  * [Symmetric Cryptography](/techniques/T1573/001) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Escape to Host](/techniques/T1611) <small style="color:#929393">(v1.5&#8594;v1.6)</small>
* Event Triggered Execution: [Accessibility Features](/techniques/T1546/008) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* Event Triggered Execution: [AppCert DLLs](/techniques/T1546/009) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* Event Triggered Execution: [AppInit DLLs](/techniques/T1546/010) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* Event Triggered Execution: [Application Shimming](/techniques/T1546/011) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* Event Triggered Execution: [Change Default File Association](/techniques/T1546/001) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* Event Triggered Execution: [Component Object Model Hijacking](/techniques/T1546/015) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* Event Triggered Execution: [Emond](/techniques/T1546/014) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* Event Triggered Execution: [Image File Execution Options Injection](/techniques/T1546/012) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* Event Triggered Execution: [Installer Packages](/techniques/T1546/016) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* Event Triggered Execution: [LC_LOAD_DYLIB Addition](/techniques/T1546/006) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* Event Triggered Execution: [Netsh Helper DLL](/techniques/T1546/007) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* Event Triggered Execution: [PowerShell Profile](/techniques/T1546/013) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* Event Triggered Execution: [Screensaver](/techniques/T1546/002) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
* Event Triggered Execution: [Trap](/techniques/T1546/005) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* Event Triggered Execution: [Unix Shell Configuration Modification](/techniques/T1546/004) <small style="color:#929393">(v2.1&#8594;v2.2)</small>
* Event Triggered Execution: [Windows Management Instrumentation Event Subscription](/techniques/T1546/003) <small style="color:#929393">(v1.4&#8594;v1.5)</small>
* [Execution Guardrails](/techniques/T1480) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
  * [Environmental Keying](/techniques/T1480/001) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Exfiltration Over Alternative Protocol](/techniques/T1048) <small style="color:#929393">(v1.5&#8594;v1.6)</small>
  * [Exfiltration Over Asymmetric Encrypted Non-C2 Protocol](/techniques/T1048/002) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
  * [Exfiltration Over Symmetric Encrypted Non-C2 Protocol](/techniques/T1048/001) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
  * [Exfiltration Over Unencrypted Non-C2 Protocol](/techniques/T1048/003) <small style="color:#929393">(v2.1&#8594;v2.2)</small>
* [Exfiltration Over C2 Channel](/techniques/T1041) <small style="color:#929393">(v2.2&#8594;v2.3)</small>
* Exfiltration Over Other Network Medium: [Exfiltration Over Bluetooth](/techniques/T1011/001) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Exfiltration Over Physical Medium](/techniques/T1052) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
  * [Exfiltration over USB](/techniques/T1052/001) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Exfiltration Over Web Service](/techniques/T1567) <small style="color:#929393">(v1.4&#8594;v1.5)</small>
  * [Exfiltration Over Webhook](/techniques/T1567/004) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
  * [Exfiltration to Cloud Storage](/techniques/T1567/002) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
  * [Exfiltration to Code Repository](/techniques/T1567/001) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
  * [Exfiltration to Text Storage Sites](/techniques/T1567/003) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Exploit Public-Facing Application](/techniques/T1190) <small style="color:#929393">(v2.6&#8594;v2.7)</small>
* [Exploitation for Client Execution](/techniques/T1203) <small style="color:#929393">(v1.4&#8594;v1.5)</small>
* [Exploitation for Defense Evasion](/techniques/T1211) <small style="color:#929393">(v1.4&#8594;v1.5)</small>
* [Exploitation for Privilege Escalation](/techniques/T1068) <small style="color:#929393">(v1.5&#8594;v1.6)</small>
* [Exploitation of Remote Services](/techniques/T1210) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Fallback Channels](/techniques/T1008) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [File and Directory Discovery](/techniques/T1083) <small style="color:#929393">(v1.6&#8594;v1.7)</small>
* [File and Directory Permissions Modification](/techniques/T1222) <small style="color:#929393">(v2.2&#8594;v2.3)</small>
* [Firmware Corruption](/techniques/T1495) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
* [Hardware Additions](/techniques/T1200) <small style="color:#929393">(v1.6&#8594;v1.7)</small>
* [Hide Artifacts](/techniques/T1564) <small style="color:#929393">(v1.3&#8594;v1.4)</small>
  * [Hidden File System](/techniques/T1564/005) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
  * [Hidden Files and Directories](/techniques/T1564/001) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
  * [Hidden Window](/techniques/T1564/003) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
  * [NTFS File Attributes](/techniques/T1564/004) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
  * [Process Argument Spoofing](/techniques/T1564/010) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
  * [Resource Forking](/techniques/T1564/009) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
  * [Run Virtual Instance](/techniques/T1564/006) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
  * [VBA Stomping](/techniques/T1564/007) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Hide Infrastructure](/techniques/T1665) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Hijack Execution Flow](/techniques/T1574) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
  * [COR_PROFILER](/techniques/T1574/012) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
  * [Dylib Hijacking](/techniques/T1574/004) <small style="color:#929393">(v2.0&#8594;v2.1)</small>
  * [Dynamic Linker Hijacking](/techniques/T1574/006) <small style="color:#929393">(v2.0&#8594;v2.1)</small>
  * [Executable Installer File Permissions Weakness](/techniques/T1574/005) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
  * [Path Interception by PATH Environment Variable](/techniques/T1574/007) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
  * [Path Interception by Search Order Hijacking](/techniques/T1574/008) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
  * [Services File Permissions Weakness](/techniques/T1574/010) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
  * [Services Registry Permissions Weakness](/techniques/T1574/011) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Impair Defenses](/techniques/T1562) <small style="color:#929393">(v1.6&#8594;v1.7)</small>
  * [Disable Windows Event Logging](/techniques/T1562/002) <small style="color:#929393">(v1.3&#8594;v1.4)</small>
  * [Disable or Modify System Firewall](/techniques/T1562/004) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
  * [Disable or Modify Tools](/techniques/T1562/001) <small style="color:#929393">(v1.5&#8594;v1.6)</small>
  * [Downgrade Attack](/techniques/T1562/010) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
  * [Impair Command History Logging](/techniques/T1562/003) <small style="color:#929393">(v2.2&#8594;v2.3)</small>
  * [Indicator Blocking](/techniques/T1562/006) <small style="color:#929393">(v1.4&#8594;v1.5)</small>
  * [Safe Mode Boot](/techniques/T1562/009) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Implant Internal Image](/techniques/T1525) <small style="color:#929393">(v2.1&#8594;v2.2)</small>
* [Indicator Removal](/techniques/T1070) <small style="color:#929393">(v2.2&#8594;v2.3)</small>
  * [Clear Command History](/techniques/T1070/003) <small style="color:#929393">(v1.5&#8594;v1.6)</small>
  * [Clear Network Connection History and Configurations](/techniques/T1070/007) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
  * [Clear Persistence](/techniques/T1070/009) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
  * [Clear Windows Event Logs](/techniques/T1070/001) <small style="color:#929393">(v1.4&#8594;v1.5)</small>
  * [File Deletion](/techniques/T1070/004) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
  * [Network Share Connection Removal](/techniques/T1070/005) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
  * [Relocate Malware](/techniques/T1070/010) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
  * [Timestomp](/techniques/T1070/006) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Indirect Command Execution](/techniques/T1202) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
* [Ingress Tool Transfer](/techniques/T1105) <small style="color:#929393">(v2.4&#8594;v2.5)</small>
* [Inhibit System Recovery](/techniques/T1490) <small style="color:#929393">(v1.5&#8594;v1.6)</small>
* [Input Capture](/techniques/T1056) <small style="color:#929393">(v1.3&#8594;v1.4)</small>
  * [Credential API Hooking](/techniques/T1056/004) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
  * [Keylogging](/techniques/T1056/001) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
  * [Web Portal Capture](/techniques/T1056/003) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Inter-Process Communication](/techniques/T1559) <small style="color:#929393">(v1.3&#8594;v1.4)</small>
  * [Component Object Model](/techniques/T1559/001) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
  * [Dynamic Data Exchange](/techniques/T1559/002) <small style="color:#929393">(v1.3&#8594;v1.4)</small>
  * [XPC Services](/techniques/T1559/003) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Lateral Tool Transfer](/techniques/T1570) <small style="color:#929393">(v1.3&#8594;v1.4)</small>
* [Log Enumeration](/techniques/T1654) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Masquerading](/techniques/T1036) <small style="color:#929393">(v1.7&#8594;v1.8)</small>
  * [Masquerade File Type](/techniques/T1036/008) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
  * [Space after Filename](/techniques/T1036/006) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Modify Authentication Process](/techniques/T1556) <small style="color:#929393">(v2.5&#8594;v2.6)</small>
  * [Multi-Factor Authentication](/techniques/T1556/006) <small style="color:#929393">(v1.3&#8594;v1.4)</small>
  * [Network Device Authentication](/techniques/T1556/004) <small style="color:#929393">(v2.0&#8594;v2.1)</small>
* Modify Cloud Compute Infrastructure: [Revert Cloud Instance](/techniques/T1578/004) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Modify System Image](/techniques/T1601) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
  * [Downgrade System Image](/techniques/T1601/002) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
  * [Patch System Image](/techniques/T1601/001) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Multi-Stage Channels](/techniques/T1104) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Native API](/techniques/T1106) <small style="color:#929393">(v2.2&#8594;v2.3)</small>
* [Network Boundary Bridging](/techniques/T1599) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
  * [Network Address Translation Traversal](/techniques/T1599/001) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Network Service Discovery](/techniques/T1046) <small style="color:#929393">(v3.1&#8594;v3.2)</small>
* [Network Sniffing](/techniques/T1040) <small style="color:#929393">(v1.6&#8594;v1.7)</small>
* [Non-Application Layer Protocol](/techniques/T1095) <small style="color:#929393">(v2.3&#8594;v2.4)</small>
* [Non-Standard Port](/techniques/T1571) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* OS Credential Dumping: [/etc/passwd and /etc/shadow](/techniques/T1003/008) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* OS Credential Dumping: [NTDS](/techniques/T1003/003) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
* [Obfuscated Files or Information](/techniques/T1027) <small style="color:#929393">(v1.6&#8594;v1.7)</small>
  * [Binary Padding](/techniques/T1027/001) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
  * [Compile After Delivery](/techniques/T1027/004) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
  * [Embedded Payloads](/techniques/T1027/009) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
  * [Encrypted/Encoded File](/techniques/T1027/013) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
  * [HTML Smuggling](/techniques/T1027/006) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
  * [Indicator Removal from Tools](/techniques/T1027/005) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
  * [Polymorphic Code](/techniques/T1027/014) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
  * [Software Packing](/techniques/T1027/002) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
  * [Stripped Payloads](/techniques/T1027/008) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* Obtain Capabilities: [Artificial Intelligence](/techniques/T1588/007) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Password Policy Discovery](/techniques/T1201) <small style="color:#929393">(v1.6&#8594;v1.7)</small>
* [Peripheral Device Discovery](/techniques/T1120) <small style="color:#929393">(v1.3&#8594;v1.4)</small>
* [Phishing](/techniques/T1566) <small style="color:#929393">(v2.6&#8594;v2.7)</small>
  * [Spearphishing Voice](/techniques/T1566/004) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Phishing for Information](/techniques/T1598) <small style="color:#929393">(v1.3&#8594;v1.4)</small>
  * [Spearphishing Attachment](/techniques/T1598/002) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Power Settings](/techniques/T1653) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Pre-OS Boot](/techniques/T1542) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
  * [Bootkit](/techniques/T1542/003) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
  * [Component Firmware](/techniques/T1542/002) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
  * [ROMMONkit](/techniques/T1542/004) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
  * [System Firmware](/techniques/T1542/001) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
  * [TFTP Boot](/techniques/T1542/005) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Process Discovery](/techniques/T1057) <small style="color:#929393">(v1.5&#8594;v1.6)</small>
* [Process Injection](/techniques/T1055) <small style="color:#929393">(v1.3&#8594;v1.4)</small>
  * [Asynchronous Procedure Call](/techniques/T1055/004) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
  * [Dynamic-link Library Injection](/techniques/T1055/001) <small style="color:#929393">(v1.3&#8594;v1.4)</small>
  * [Extra Window Memory Injection](/techniques/T1055/011) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
  * [ListPlanting](/techniques/T1055/015) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
  * [Portable Executable Injection](/techniques/T1055/002) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
  * [Proc Memory](/techniques/T1055/009) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
  * [Process Doppelgänging](/techniques/T1055/013) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
  * [Process Hollowing](/techniques/T1055/012) <small style="color:#929393">(v1.3&#8594;v1.4)</small>
  * [Ptrace System Calls](/techniques/T1055/008) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
  * [Thread Execution Hijacking](/techniques/T1055/003) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
  * [Thread Local Storage](/techniques/T1055/005) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
  * [VDSO Hijacking](/techniques/T1055/014) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Protocol Tunneling](/techniques/T1572) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Proxy](/techniques/T1090) <small style="color:#929393">(v3.1&#8594;v3.2)</small>
  * [Domain Fronting](/techniques/T1090/004) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
  * [External Proxy](/techniques/T1090/002) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
  * [Internal Proxy](/techniques/T1090/001) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
  * [Multi-hop Proxy](/techniques/T1090/003) <small style="color:#929393">(v2.2&#8594;v2.3)</small>
* [Reflective Code Loading](/techniques/T1620) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
* Remote Service Session Hijacking: [SSH Hijacking](/techniques/T1563/001) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Remote Services](/techniques/T1021) <small style="color:#929393">(v1.5&#8594;v1.6)</small>
  * [Remote Desktop Protocol](/techniques/T1021/001) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
  * [SMB/Windows Admin Shares](/techniques/T1021/002) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
  * [SSH](/techniques/T1021/004) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
  * [VNC](/techniques/T1021/005) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Remote System Discovery](/techniques/T1018) <small style="color:#929393">(v3.5&#8594;v3.6)</small>
* [Replication Through Removable Media](/techniques/T1091) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
* [Rogue Domain Controller](/techniques/T1207) <small style="color:#929393">(v2.1&#8594;v2.2)</small>
* [Rootkit](/techniques/T1014) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Scheduled Task/Job](/techniques/T1053) <small style="color:#929393">(v2.3&#8594;v2.4)</small>
  * [At](/techniques/T1053/002) <small style="color:#929393">(v2.3&#8594;v2.4)</small>
  * [Container Orchestration Job](/techniques/T1053/007) <small style="color:#929393">(v1.3&#8594;v1.4)</small>
  * [Cron](/techniques/T1053/003) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
  * [Scheduled Task](/techniques/T1053/005) <small style="color:#929393">(v1.6&#8594;v1.7)</small>
  * [Systemd Timers](/techniques/T1053/006) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
* [Server Software Component](/techniques/T1505) <small style="color:#929393">(v1.4&#8594;v1.5)</small>
  * [IIS Components](/techniques/T1505/004) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
  * [Transport Agent](/techniques/T1505/002) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
  * [Web Shell](/techniques/T1505/003) <small style="color:#929393">(v1.4&#8594;v1.5)</small>
* [Serverless Execution](/techniques/T1648) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Service Stop](/techniques/T1489) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
* [Shared Modules](/techniques/T1129) <small style="color:#929393">(v2.2&#8594;v2.3)</small>
* [Software Deployment Tools](/techniques/T1072) <small style="color:#929393">(v3.1&#8594;v3.2)</small>
* [Software Discovery](/techniques/T1518) <small style="color:#929393">(v1.4&#8594;v1.5)</small>
* [Steal Application Access Token](/techniques/T1528) <small style="color:#929393">(v1.4&#8594;v1.5)</small>
* [Steal or Forge Kerberos Tickets](/techniques/T1558) <small style="color:#929393">(v1.6&#8594;v1.7)</small>
  * [AS-REP Roasting](/techniques/T1558/004) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
  * [Golden Ticket](/techniques/T1558/001) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
  * [Kerberoasting](/techniques/T1558/003) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
  * [Silver Ticket](/techniques/T1558/002) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Subvert Trust Controls](/techniques/T1553) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
  * [Code Signing](/techniques/T1553/002) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
  * [Code Signing Policy Modification](/techniques/T1553/006) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
  * [Gatekeeper Bypass](/techniques/T1553/001) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
  * [Install Root Certificate](/techniques/T1553/004) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
  * [Mark-of-the-Web Bypass](/techniques/T1553/005) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
  * [SIP and Trust Provider Hijacking](/techniques/T1553/003) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [System Binary Proxy Execution](/techniques/T1218) <small style="color:#929393">(v3.1&#8594;v3.2)</small>
  * [CMSTP](/techniques/T1218/003) <small style="color:#929393">(v2.1&#8594;v2.2)</small>
  * [Compiled HTML File](/techniques/T1218/001) <small style="color:#929393">(v2.1&#8594;v2.2)</small>
  * [Control Panel](/techniques/T1218/002) <small style="color:#929393">(v2.0&#8594;v2.1)</small>
  * [InstallUtil](/techniques/T1218/004) <small style="color:#929393">(v2.0&#8594;v2.1)</small>
  * [MMC](/techniques/T1218/014) <small style="color:#929393">(v2.0&#8594;v2.1)</small>
  * [Mshta](/techniques/T1218/005) <small style="color:#929393">(v2.0&#8594;v2.1)</small>
  * [Msiexec](/techniques/T1218/007) <small style="color:#929393">(v2.0&#8594;v2.1)</small>
  * [Odbcconf](/techniques/T1218/008) <small style="color:#929393">(v2.0&#8594;v2.1)</small>
  * [Regsvcs/Regasm](/techniques/T1218/009) <small style="color:#929393">(v2.0&#8594;v2.1)</small>
  * [Regsvr32](/techniques/T1218/010) <small style="color:#929393">(v2.1&#8594;v2.2)</small>
  * [Rundll32](/techniques/T1218/011) <small style="color:#929393">(v2.3&#8594;v2.4)</small>
  * [Verclsid](/techniques/T1218/012) <small style="color:#929393">(v2.0&#8594;v2.1)</small>
* [System Information Discovery](/techniques/T1082) <small style="color:#929393">(v2.5&#8594;v2.6)</small>
* System Location Discovery: [System Language Discovery](/techniques/T1614/001) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [System Network Configuration Discovery](/techniques/T1016) <small style="color:#929393">(v1.6&#8594;v1.7)</small>
  * [Internet Connection Discovery](/techniques/T1016/001) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [System Network Connections Discovery](/techniques/T1049) <small style="color:#929393">(v2.4&#8594;v2.5)</small>
* [System Owner/User Discovery](/techniques/T1033) <small style="color:#929393">(v1.5&#8594;v1.6)</small>
* [System Script Proxy Execution](/techniques/T1216) <small style="color:#929393">(v2.0&#8594;v2.1)</small>
  * [PubPrn](/techniques/T1216/001) <small style="color:#929393">(v2.0&#8594;v2.1)</small>
* [System Services](/techniques/T1569) <small style="color:#929393">(v1.3&#8594;v1.4)</small>
  * [Launchctl](/techniques/T1569/001) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
  * [Service Execution](/techniques/T1569/002) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
* [System Shutdown/Reboot](/techniques/T1529) <small style="color:#929393">(v1.3&#8594;v1.4)</small>
* [System Time Discovery](/techniques/T1124) <small style="color:#929393">(v1.4&#8594;v1.5)</small>
* [Taint Shared Content](/techniques/T1080) <small style="color:#929393">(v1.5&#8594;v1.6)</small>
* [Template Injection](/techniques/T1221) <small style="color:#929393">(v1.3&#8594;v1.4)</small>
* [Traffic Signaling](/techniques/T1205) <small style="color:#929393">(v2.4&#8594;v2.5)</small>
  * [Port Knocking](/techniques/T1205/001) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Trusted Developer Utilities Proxy Execution](/techniques/T1127) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
  * [ClickOnce](/techniques/T1127/002) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
  * [MSBuild](/techniques/T1127/001) <small style="color:#929393">(v1.3&#8594;v1.4)</small>
* [Unsecured Credentials](/techniques/T1552) <small style="color:#929393">(v1.4&#8594;v1.5)</small>
  * [Credentials In Files](/techniques/T1552/001) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
  * [Credentials in Registry](/techniques/T1552/002) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
  * [Private Keys](/techniques/T1552/004) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
* [Use Alternate Authentication Material](/techniques/T1550) <small style="color:#929393">(v1.4&#8594;v1.5)</small>
  * [Application Access Token](/techniques/T1550/001) <small style="color:#929393">(v1.7&#8594;v1.8)</small>
  * [Pass the Hash](/techniques/T1550/002) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
  * [Pass the Ticket](/techniques/T1550/003) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
  * [Web Session Cookie](/techniques/T1550/004) <small style="color:#929393">(v1.4&#8594;v1.5)</small>
* [User Execution](/techniques/T1204) <small style="color:#929393">(v1.7&#8594;v1.8)</small>
  * [Malicious File](/techniques/T1204/002) <small style="color:#929393">(v1.4&#8594;v1.5)</small>
  * [Malicious Image](/techniques/T1204/003) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
  * [Malicious Link](/techniques/T1204/001) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Valid Accounts](/techniques/T1078) <small style="color:#929393">(v2.7&#8594;v2.8)</small>
  * [Cloud Accounts](/techniques/T1078/004) <small style="color:#929393">(v1.8&#8594;v1.9)</small>
  * [Default Accounts](/techniques/T1078/001) <small style="color:#929393">(v1.4&#8594;v1.5)</small>
  * [Domain Accounts](/techniques/T1078/002) <small style="color:#929393">(v1.4&#8594;v1.5)</small>
  * [Local Accounts](/techniques/T1078/003) <small style="color:#929393">(v1.4&#8594;v1.5)</small>
* [Video Capture](/techniques/T1125) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Virtualization/Sandbox Evasion](/techniques/T1497) <small style="color:#929393">(v1.3&#8594;v1.4)</small>
  * [System Checks](/techniques/T1497/001) <small style="color:#929393">(v2.2&#8594;v2.3)</small>
  * [Time Based Evasion](/techniques/T1497/003) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
  * [User Activity Based Checks](/techniques/T1497/002) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Weaken Encryption](/techniques/T1600) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
  * [Disable Crypto Hardware](/techniques/T1600/002) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
  * [Reduce Key Space](/techniques/T1600/001) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Web Service](/techniques/T1102) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
  * [Bidirectional Communication](/techniques/T1102/002) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
  * [Dead Drop Resolver](/techniques/T1102/001) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
  * [One-Way Communication](/techniques/T1102/003) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Windows Management Instrumentation](/techniques/T1047) <small style="color:#929393">(v1.5&#8594;v1.6)</small>
* [XSL Script Processing](/techniques/T1220) <small style="color:#929393">(v1.2&#8594;v1.3)</small>

#### Patches

* Abuse Elevation Control Mechanism: [TCC Manipulation](/techniques/T1548/006) <small style="color:#929393">(v1.1)</small>
* Abuse Elevation Control Mechanism: [Temporary Elevated Cloud Access](/techniques/T1548/005) <small style="color:#929393">(v1.2)</small>
* Account Discovery: [Cloud Account](/techniques/T1087/004) <small style="color:#929393">(v1.3)</small>
* Account Discovery: [Domain Account](/techniques/T1087/002) <small style="color:#929393">(v1.2)</small>
* Account Discovery: [Email Account](/techniques/T1087/003) <small style="color:#929393">(v1.2)</small>
* Account Manipulation: [Additional Cloud Credentials](/techniques/T1098/001) <small style="color:#929393">(v2.8)</small>
* Account Manipulation: [Additional Cloud Roles](/techniques/T1098/003) <small style="color:#929393">(v2.5)</small>
* Account Manipulation: [Additional Container Cluster Roles](/techniques/T1098/006) <small style="color:#929393">(v1.0)</small>
* Account Manipulation: [Additional Email Delegate Permissions](/techniques/T1098/002) <small style="color:#929393">(v2.2)</small>
* Account Manipulation: [Additional Local or Domain Groups](/techniques/T1098/007) <small style="color:#929393">(v1.0)</small>
* Account Manipulation: [Device Registration](/techniques/T1098/005) <small style="color:#929393">(v1.3)</small>
* [Acquire Access](/techniques/T1650) <small style="color:#929393">(v1.0)</small>
* [Acquire Infrastructure](/techniques/T1583) <small style="color:#929393">(v1.4)</small>
  * [DNS Server](/techniques/T1583/002) <small style="color:#929393">(v1.0)</small>
  * [Domains](/techniques/T1583/001) <small style="color:#929393">(v1.4)</small>
  * [Malvertising](/techniques/T1583/008) <small style="color:#929393">(v1.0)</small>
  * [Server](/techniques/T1583/004) <small style="color:#929393">(v1.3)</small>
  * [Serverless](/techniques/T1583/007) <small style="color:#929393">(v1.1)</small>
  * [Virtual Private Server](/techniques/T1583/003) <small style="color:#929393">(v1.1)</small>
* [Active Scanning](/techniques/T1595) <small style="color:#929393">(v1.0)</small>
  * [Scanning IP Blocks](/techniques/T1595/001) <small style="color:#929393">(v1.1)</small>
  * [Vulnerability Scanning](/techniques/T1595/002) <small style="color:#929393">(v1.0)</small>
  * [Wordlist Scanning](/techniques/T1595/003) <small style="color:#929393">(v1.0)</small>
* Adversary-in-the-Middle: [ARP Cache Poisoning](/techniques/T1557/002) <small style="color:#929393">(v1.1)</small>
* Adversary-in-the-Middle: [DHCP Spoofing](/techniques/T1557/003) <small style="color:#929393">(v1.1)</small>
* Adversary-in-the-Middle: [LLMNR/NBT-NS Poisoning and SMB Relay](/techniques/T1557/001) <small style="color:#929393">(v1.4)</small>
* [Application Window Discovery](/techniques/T1010) <small style="color:#929393">(v1.3)</small>
* [Archive Collected Data](/techniques/T1560) <small style="color:#929393">(v1.0)</small>
  * [Archive via Custom Method](/techniques/T1560/003) <small style="color:#929393">(v1.0)</small>
  * [Archive via Library](/techniques/T1560/002) <small style="color:#929393">(v1.0)</small>
  * [Archive via Utility](/techniques/T1560/001) <small style="color:#929393">(v1.3)</small>
* [Audio Capture](/techniques/T1123) <small style="color:#929393">(v1.0)</small>
* Boot or Logon Initialization Scripts: [Login Hook](/techniques/T1037/002) <small style="color:#929393">(v2.0)</small>
* Boot or Logon Initialization Scripts: [Logon Script (Windows)](/techniques/T1037/001) <small style="color:#929393">(v1.0)</small>
* Boot or Logon Initialization Scripts: [Network Logon Script](/techniques/T1037/003) <small style="color:#929393">(v1.0)</small>
* [Browser Information Discovery](/techniques/T1217) <small style="color:#929393">(v2.0)</small>
* [Build Image on Host](/techniques/T1612) <small style="color:#929393">(v1.3)</small>
* [Clipboard Data](/techniques/T1115) <small style="color:#929393">(v1.2)</small>
* [Cloud Infrastructure Discovery](/techniques/T1580) <small style="color:#929393">(v1.3)</small>
* [Cloud Service Discovery](/techniques/T1526) <small style="color:#929393">(v1.4)</small>
* [Cloud Storage Object Discovery](/techniques/T1619) <small style="color:#929393">(v1.0)</small>
* Command and Scripting Interpreter: [JavaScript](/techniques/T1059/007) <small style="color:#929393">(v2.2)</small>
* [Communication Through Removable Media](/techniques/T1092) <small style="color:#929393">(v1.0)</small>
* [Compromise Accounts](/techniques/T1586) <small style="color:#929393">(v1.2)</small>
  * [Cloud Accounts](/techniques/T1586/003) <small style="color:#929393">(v1.1)</small>
  * [Email Accounts](/techniques/T1586/002) <small style="color:#929393">(v1.1)</small>
  * [Social Media Accounts](/techniques/T1586/001) <small style="color:#929393">(v1.1)</small>
* Compromise Infrastructure: [Botnet](/techniques/T1584/005) <small style="color:#929393">(v1.0)</small>
* Compromise Infrastructure: [DNS Server](/techniques/T1584/002) <small style="color:#929393">(v1.2)</small>
* Compromise Infrastructure: [Domains](/techniques/T1584/001) <small style="color:#929393">(v1.4)</small>
* Compromise Infrastructure: [Network Devices](/techniques/T1584/008) <small style="color:#929393">(v1.0)</small>
* Compromise Infrastructure: [Server](/techniques/T1584/004) <small style="color:#929393">(v1.2)</small>
* Compromise Infrastructure: [Serverless](/techniques/T1584/007) <small style="color:#929393">(v1.1)</small>
* Compromise Infrastructure: [Virtual Private Server](/techniques/T1584/003) <small style="color:#929393">(v1.1)</small>
* Compromise Infrastructure: [Web Services](/techniques/T1584/006) <small style="color:#929393">(v1.2)</small>
* [Container and Resource Discovery](/techniques/T1613) <small style="color:#929393">(v1.1)</small>
* [Content Injection](/techniques/T1659) <small style="color:#929393">(v1.0)</small>
* Create Account: [Cloud Account](/techniques/T1136/003) <small style="color:#929393">(v1.6)</small>
* Create Account: [Domain Account](/techniques/T1136/002) <small style="color:#929393">(v1.1)</small>
* [Create or Modify System Process](/techniques/T1543) <small style="color:#929393">(v1.2)</small>
  * [Container Service](/techniques/T1543/005) <small style="color:#929393">(v1.0)</small>
* [Credentials from Password Stores](/techniques/T1555) <small style="color:#929393">(v1.2)</small>
  * [Cloud Secrets Management Stores](/techniques/T1555/006) <small style="color:#929393">(v1.0)</small>
  * [Credentials from Web Browsers](/techniques/T1555/003) <small style="color:#929393">(v1.2)</small>
  * [Keychain](/techniques/T1555/001) <small style="color:#929393">(v1.1)</small>
  * [Password Managers](/techniques/T1555/005) <small style="color:#929393">(v1.1)</small>
  * [Securityd Memory](/techniques/T1555/002) <small style="color:#929393">(v1.2)</small>
  * [Windows Credential Manager](/techniques/T1555/004) <small style="color:#929393">(v1.1)</small>
* [Data Manipulation](/techniques/T1565) <small style="color:#929393">(v1.1)</small>
  * [Runtime Data Manipulation](/techniques/T1565/003) <small style="color:#929393">(v1.2)</small>
  * [Stored Data Manipulation](/techniques/T1565/001) <small style="color:#929393">(v1.1)</small>
  * [Transmitted Data Manipulation](/techniques/T1565/002) <small style="color:#929393">(v1.1)</small>
* [Data from Cloud Storage](/techniques/T1530) <small style="color:#929393">(v2.2)</small>
* [Data from Information Repositories](/techniques/T1213) <small style="color:#929393">(v3.4)</small>
  * [Code Repositories](/techniques/T1213/003) <small style="color:#929393">(v1.2)</small>
  * [Confluence](/techniques/T1213/001) <small style="color:#929393">(v1.1)</small>
  * [Customer Relationship Management Software](/techniques/T1213/004) <small style="color:#929393">(v1.0)</small>
  * [Messaging Applications](/techniques/T1213/005) <small style="color:#929393">(v1.0)</small>
  * [Sharepoint](/techniques/T1213/002) <small style="color:#929393">(v1.1)</small>
* Defacement: [External Defacement](/techniques/T1491/002) <small style="color:#929393">(v1.2)</small>
* [Develop Capabilities](/techniques/T1587) <small style="color:#929393">(v1.1)</small>
  * [Code Signing Certificates](/techniques/T1587/002) <small style="color:#929393">(v1.1)</small>
  * [Digital Certificates](/techniques/T1587/003) <small style="color:#929393">(v1.2)</small>
  * [Exploits](/techniques/T1587/004) <small style="color:#929393">(v1.0)</small>
  * [Malware](/techniques/T1587/001) <small style="color:#929393">(v1.2)</small>
* [Device Driver Discovery](/techniques/T1652) <small style="color:#929393">(v1.0)</small>
* [Domain Trust Discovery](/techniques/T1482) <small style="color:#929393">(v1.2)</small>
* [Email Collection](/techniques/T1114) <small style="color:#929393">(v2.6)</small>
  * [Email Forwarding Rule](/techniques/T1114/003) <small style="color:#929393">(v1.4)</small>
  * [Remote Email Collection](/techniques/T1114/002) <small style="color:#929393">(v1.3)</small>
* [Endpoint Denial of Service](/techniques/T1499) <small style="color:#929393">(v1.2)</small>
  * [Application Exhaustion Flood](/techniques/T1499/003) <small style="color:#929393">(v1.3)</small>
  * [Application or System Exploitation](/techniques/T1499/004) <small style="color:#929393">(v1.3)</small>
  * [OS Exhaustion Flood](/techniques/T1499/001) <small style="color:#929393">(v1.2)</small>
  * [Service Exhaustion Flood](/techniques/T1499/002) <small style="color:#929393">(v1.4)</small>
* [Establish Accounts](/techniques/T1585) <small style="color:#929393">(v1.3)</small>
  * [Cloud Accounts](/techniques/T1585/003) <small style="color:#929393">(v1.1)</small>
  * [Email Accounts](/techniques/T1585/002) <small style="color:#929393">(v1.1)</small>
  * [Social Media Accounts](/techniques/T1585/001) <small style="color:#929393">(v1.1)</small>
* [Event Triggered Execution](/techniques/T1546) <small style="color:#929393">(v1.4)</small>
  * [Udev Rules](/techniques/T1546/017) <small style="color:#929393">(v1.0)</small>
* Execution Guardrails: [Mutual Exclusion](/techniques/T1480/002) <small style="color:#929393">(v1.0)</small>
* [Exfiltration Over Other Network Medium](/techniques/T1011) <small style="color:#929393">(v1.2)</small>
* [Exploitation for Credential Access](/techniques/T1212) <small style="color:#929393">(v1.6)</small>
* [External Remote Services](/techniques/T1133) <small style="color:#929393">(v2.4)</small>
* File and Directory Permissions Modification: [Linux and Mac File and Directory Permissions Modification](/techniques/T1222/002) <small style="color:#929393">(v1.2)</small>
* File and Directory Permissions Modification: [Windows File and Directory Permissions Modification](/techniques/T1222/001) <small style="color:#929393">(v1.2)</small>
* [Financial Theft](/techniques/T1657) <small style="color:#929393">(v1.2)</small>
* [Forced Authentication](/techniques/T1187) <small style="color:#929393">(v1.3)</small>
* [Forge Web Credentials](/techniques/T1606) <small style="color:#929393">(v1.5)</small>
  * [SAML Tokens](/techniques/T1606/002) <small style="color:#929393">(v1.4)</small>
  * [Web Cookies](/techniques/T1606/001) <small style="color:#929393">(v1.1)</small>
* [Gather Victim Host Information](/techniques/T1592) <small style="color:#929393">(v1.2)</small>
  * [Client Configurations](/techniques/T1592/004) <small style="color:#929393">(v1.1)</small>
  * [Firmware](/techniques/T1592/003) <small style="color:#929393">(v1.0)</small>
  * [Hardware](/techniques/T1592/001) <small style="color:#929393">(v1.1)</small>
  * [Software](/techniques/T1592/002) <small style="color:#929393">(v1.1)</small>
* [Gather Victim Identity Information](/techniques/T1589) <small style="color:#929393">(v1.3)</small>
  * [Credentials](/techniques/T1589/001) <small style="color:#929393">(v1.2)</small>
  * [Email Addresses](/techniques/T1589/002) <small style="color:#929393">(v1.2)</small>
  * [Employee Names](/techniques/T1589/003) <small style="color:#929393">(v1.0)</small>
* [Gather Victim Network Information](/techniques/T1590) <small style="color:#929393">(v1.0)</small>
  * [DNS](/techniques/T1590/002) <small style="color:#929393">(v1.2)</small>
  * [Domain Properties](/techniques/T1590/001) <small style="color:#929393">(v1.1)</small>
  * [IP Addresses](/techniques/T1590/005) <small style="color:#929393">(v1.0)</small>
  * [Network Security Appliances](/techniques/T1590/006) <small style="color:#929393">(v1.0)</small>
  * [Network Topology](/techniques/T1590/004) <small style="color:#929393">(v1.0)</small>
  * [Network Trust Dependencies](/techniques/T1590/003) <small style="color:#929393">(v1.0)</small>
* [Gather Victim Org Information](/techniques/T1591) <small style="color:#929393">(v1.1)</small>
  * [Business Relationships](/techniques/T1591/002) <small style="color:#929393">(v1.0)</small>
  * [Determine Physical Locations](/techniques/T1591/001) <small style="color:#929393">(v1.1)</small>
  * [Identify Business Tempo](/techniques/T1591/003) <small style="color:#929393">(v1.0)</small>
  * [Identify Roles](/techniques/T1591/004) <small style="color:#929393">(v1.0)</small>
* [Group Policy Discovery](/techniques/T1615) <small style="color:#929393">(v1.1)</small>
* Hide Artifacts: [Email Hiding Rules](/techniques/T1564/008) <small style="color:#929393">(v1.4)</small>
* Hide Artifacts: [File/Path Exclusions](/techniques/T1564/012) <small style="color:#929393">(v1.0)</small>
* Hide Artifacts: [Hidden Users](/techniques/T1564/002) <small style="color:#929393">(v1.2)</small>
* Hide Artifacts: [Ignore Process Interrupts](/techniques/T1564/011) <small style="color:#929393">(v1.0)</small>
* Hijack Execution Flow: [AppDomainManager](/techniques/T1574/014) <small style="color:#929393">(v1.0)</small>
* Hijack Execution Flow: [KernelCallbackTable](/techniques/T1574/013) <small style="color:#929393">(v1.0)</small>
* Hijack Execution Flow: [Path Interception by Unquoted Path](/techniques/T1574/009) <small style="color:#929393">(v1.1)</small>
* Impair Defenses: [Disable or Modify Cloud Firewall](/techniques/T1562/007) <small style="color:#929393">(v1.3)</small>
* Impair Defenses: [Disable or Modify Cloud Logs](/techniques/T1562/008) <small style="color:#929393">(v2.1)</small>
* Impair Defenses: [Disable or Modify Linux Audit System](/techniques/T1562/012) <small style="color:#929393">(v1.0)</small>
* Impair Defenses: [Spoof Security Alerting](/techniques/T1562/011) <small style="color:#929393">(v1.0)</small>
* [Impersonation](/techniques/T1656) <small style="color:#929393">(v1.1)</small>
* Indicator Removal: [Clear Linux or Mac System Logs](/techniques/T1070/002) <small style="color:#929393">(v1.0)</small>
* Indicator Removal: [Clear Mailbox Data](/techniques/T1070/008) <small style="color:#929393">(v1.2)</small>
* Input Capture: [GUI Input Capture](/techniques/T1056/002) <small style="color:#929393">(v1.3)</small>
* [Internal Spearphishing](/techniques/T1534) <small style="color:#929393">(v1.4)</small>
* Masquerading: [Break Process Trees](/techniques/T1036/009) <small style="color:#929393">(v1.0)</small>
* Masquerading: [Double File Extension](/techniques/T1036/007) <small style="color:#929393">(v1.0)</small>
* Masquerading: [Invalid Code Signature](/techniques/T1036/001) <small style="color:#929393">(v1.0)</small>
* Masquerading: [Masquerade Account Name](/techniques/T1036/010) <small style="color:#929393">(v1.0)</small>
* Masquerading: [Masquerade Task or Service](/techniques/T1036/004) <small style="color:#929393">(v1.2)</small>
* Masquerading: [Right-to-Left Override](/techniques/T1036/002) <small style="color:#929393">(v1.1)</small>
* Modify Authentication Process: [Conditional Access Policies](/techniques/T1556/009) <small style="color:#929393">(v1.1)</small>
* Modify Authentication Process: [Domain Controller Authentication](/techniques/T1556/001) <small style="color:#929393">(v2.1)</small>
* Modify Authentication Process: [Hybrid Identity](/techniques/T1556/007) <small style="color:#929393">(v1.1)</small>
* Modify Authentication Process: [Network Provider DLL](/techniques/T1556/008) <small style="color:#929393">(v1.0)</small>
* Modify Authentication Process: [Password Filter DLL](/techniques/T1556/002) <small style="color:#929393">(v2.1)</small>
* Modify Authentication Process: [Pluggable Authentication Modules](/techniques/T1556/003) <small style="color:#929393">(v2.1)</small>
* Modify Authentication Process: [Reversible Encryption](/techniques/T1556/005) <small style="color:#929393">(v1.1)</small>
* [Modify Cloud Compute Infrastructure](/techniques/T1578) <small style="color:#929393">(v1.2)</small>
  * [Create Cloud Instance](/techniques/T1578/002) <small style="color:#929393">(v1.2)</small>
  * [Create Snapshot](/techniques/T1578/001) <small style="color:#929393">(v1.2)</small>
  * [Delete Cloud Instance](/techniques/T1578/003) <small style="color:#929393">(v1.2)</small>
  * [Modify Cloud Compute Configurations](/techniques/T1578/005) <small style="color:#929393">(v2.0)</small>
* [Modify Cloud Resource Hierarchy](/techniques/T1666) <small style="color:#929393">(v1.0)</small>
* [Multi-Factor Authentication Interception](/techniques/T1111) <small style="color:#929393">(v2.1)</small>
* [Multi-Factor Authentication Request Generation](/techniques/T1621) <small style="color:#929393">(v1.2)</small>
* [Network Denial of Service](/techniques/T1498) <small style="color:#929393">(v1.2)</small>
  * [Direct Network Flood](/techniques/T1498/001) <small style="color:#929393">(v1.4)</small>
  * [Reflection Amplification](/techniques/T1498/002) <small style="color:#929393">(v1.4)</small>
* [Network Share Discovery](/techniques/T1135) <small style="color:#929393">(v3.2)</small>
* [OS Credential Dumping](/techniques/T1003) <small style="color:#929393">(v2.2)</small>
  * [Cached Domain Credentials](/techniques/T1003/005) <small style="color:#929393">(v1.1)</small>
  * [DCSync](/techniques/T1003/006) <small style="color:#929393">(v1.1)</small>
  * [LSA Secrets](/techniques/T1003/004) <small style="color:#929393">(v1.1)</small>
  * [LSASS Memory](/techniques/T1003/001) <small style="color:#929393">(v1.5)</small>
  * [Proc Filesystem](/techniques/T1003/007) <small style="color:#929393">(v1.2)</small>
  * [Security Account Manager](/techniques/T1003/002) <small style="color:#929393">(v1.1)</small>
* Obfuscated Files or Information: [Command Obfuscation](/techniques/T1027/010) <small style="color:#929393">(v1.0)</small>
* Obfuscated Files or Information: [Dynamic API Resolution](/techniques/T1027/007) <small style="color:#929393">(v1.0)</small>
* Obfuscated Files or Information: [Fileless Storage](/techniques/T1027/011) <small style="color:#929393">(v2.0)</small>
* Obfuscated Files or Information: [LNK Icon Smuggling](/techniques/T1027/012) <small style="color:#929393">(v1.0)</small>
* Obfuscated Files or Information: [Steganography](/techniques/T1027/003) <small style="color:#929393">(v1.2)</small>
* [Obtain Capabilities](/techniques/T1588) <small style="color:#929393">(v1.1)</small>
  * [Code Signing Certificates](/techniques/T1588/003) <small style="color:#929393">(v1.1)</small>
  * [Digital Certificates](/techniques/T1588/004) <small style="color:#929393">(v1.2)</small>
  * [Exploits](/techniques/T1588/005) <small style="color:#929393">(v1.0)</small>
  * [Malware](/techniques/T1588/001) <small style="color:#929393">(v1.1)</small>
  * [Tool](/techniques/T1588/002) <small style="color:#929393">(v1.1)</small>
  * [Vulnerabilities](/techniques/T1588/006) <small style="color:#929393">(v1.0)</small>
* [Office Application Startup](/techniques/T1137) <small style="color:#929393">(v1.4)</small>
  * [Add-ins](/techniques/T1137/006) <small style="color:#929393">(v1.2)</small>
  * [Office Template Macros](/techniques/T1137/001) <small style="color:#929393">(v1.2)</small>
  * [Office Test](/techniques/T1137/002) <small style="color:#929393">(v1.3)</small>
  * [Outlook Forms](/techniques/T1137/003) <small style="color:#929393">(v1.2)</small>
  * [Outlook Home Page](/techniques/T1137/004) <small style="color:#929393">(v1.2)</small>
  * [Outlook Rules](/techniques/T1137/005) <small style="color:#929393">(v1.2)</small>
* [Permission Groups Discovery](/techniques/T1069) <small style="color:#929393">(v2.6)</small>
  * [Cloud Groups](/techniques/T1069/003) <small style="color:#929393">(v1.5)</small>
  * [Domain Groups](/techniques/T1069/002) <small style="color:#929393">(v1.2)</small>
  * [Local Groups](/techniques/T1069/001) <small style="color:#929393">(v1.2)</small>
* Phishing: [Spearphishing Attachment](/techniques/T1566/001) <small style="color:#929393">(v2.2)</small>
* Phishing: [Spearphishing Link](/techniques/T1566/002) <small style="color:#929393">(v2.7)</small>
* Phishing: [Spearphishing via Service](/techniques/T1566/003) <small style="color:#929393">(v2.0)</small>
* Phishing for Information: [Spearphishing Link](/techniques/T1598/003) <small style="color:#929393">(v1.6)</small>
* Phishing for Information: [Spearphishing Service](/techniques/T1598/001) <small style="color:#929393">(v1.0)</small>
* Phishing for Information: [Spearphishing Voice](/techniques/T1598/004) <small style="color:#929393">(v1.0)</small>
* [Plist File Modification](/techniques/T1647) <small style="color:#929393">(v1.0)</small>
* [Query Registry](/techniques/T1012) <small style="color:#929393">(v1.3)</small>
* [Remote Service Session Hijacking](/techniques/T1563) <small style="color:#929393">(v1.1)</small>
  * [RDP Hijacking](/techniques/T1563/002) <small style="color:#929393">(v1.1)</small>
* Remote Services: [Cloud Services](/techniques/T1021/007) <small style="color:#929393">(v1.1)</small>
* Remote Services: [Direct Cloud VM Connections](/techniques/T1021/008) <small style="color:#929393">(v1.0)</small>
* Remote Services: [Distributed Component Object Model](/techniques/T1021/003) <small style="color:#929393">(v1.3)</small>
* Remote Services: [Windows Remote Management](/techniques/T1021/006) <small style="color:#929393">(v1.2)</small>
* [Resource Hijacking](/techniques/T1496) <small style="color:#929393">(v2.0)</small>
  * [Bandwidth Hijacking](/techniques/T1496/002) <small style="color:#929393">(v1.0)</small>
  * [Cloud Service Hijacking](/techniques/T1496/004) <small style="color:#929393">(v1.0)</small>
  * [Compute Hijacking](/techniques/T1496/001) <small style="color:#929393">(v1.0)</small>
  * [SMS Pumping](/techniques/T1496/003) <small style="color:#929393">(v1.0)</small>
* [Scheduled Transfer](/techniques/T1029) <small style="color:#929393">(v1.1)</small>
* [Screen Capture](/techniques/T1113) <small style="color:#929393">(v1.1)</small>
* [Search Closed Sources](/techniques/T1597) <small style="color:#929393">(v1.1)</small>
  * [Purchase Technical Data](/techniques/T1597/002) <small style="color:#929393">(v1.0)</small>
  * [Threat Intel Vendors](/techniques/T1597/001) <small style="color:#929393">(v1.0)</small>
* [Search Open Technical Databases](/techniques/T1596) <small style="color:#929393">(v1.0)</small>
  * [CDNs](/techniques/T1596/004) <small style="color:#929393">(v1.0)</small>
  * [DNS/Passive DNS](/techniques/T1596/001) <small style="color:#929393">(v1.0)</small>
  * [Digital Certificates](/techniques/T1596/003) <small style="color:#929393">(v1.0)</small>
  * [Scan Databases](/techniques/T1596/005) <small style="color:#929393">(v1.0)</small>
  * [WHOIS](/techniques/T1596/002) <small style="color:#929393">(v1.0)</small>
* [Search Open Websites/Domains](/techniques/T1593) <small style="color:#929393">(v1.1)</small>
  * [Code Repositories](/techniques/T1593/003) <small style="color:#929393">(v1.0)</small>
  * [Search Engines](/techniques/T1593/002) <small style="color:#929393">(v1.0)</small>
  * [Social Media](/techniques/T1593/001) <small style="color:#929393">(v1.0)</small>
* [Search Victim-Owned Websites](/techniques/T1594) <small style="color:#929393">(v1.1)</small>
* Server Software Component: [SQL Stored Procedures](/techniques/T1505/001) <small style="color:#929393">(v1.1)</small>
* Server Software Component: [Terminal Services DLL](/techniques/T1505/005) <small style="color:#929393">(v1.0)</small>
* Software Discovery: [Security Software Discovery](/techniques/T1518/001) <small style="color:#929393">(v1.5)</small>
* [Stage Capabilities](/techniques/T1608) <small style="color:#929393">(v1.2)</small>
  * [Drive-by Target](/techniques/T1608/004) <small style="color:#929393">(v1.3)</small>
  * [Install Digital Certificate](/techniques/T1608/003) <small style="color:#929393">(v1.1)</small>
  * [Link Target](/techniques/T1608/005) <small style="color:#929393">(v1.4)</small>
  * [SEO Poisoning](/techniques/T1608/006) <small style="color:#929393">(v1.1)</small>
  * [Upload Malware](/techniques/T1608/001) <small style="color:#929393">(v1.2)</small>
  * [Upload Tool](/techniques/T1608/002) <small style="color:#929393">(v1.2)</small>
* [Steal Web Session Cookie](/techniques/T1539) <small style="color:#929393">(v1.4)</small>
* [Steal or Forge Authentication Certificates](/techniques/T1649) <small style="color:#929393">(v1.2)</small>
* Steal or Forge Kerberos Tickets: [Ccache Files](/techniques/T1558/005) <small style="color:#929393">(v1.0)</small>
* [Supply Chain Compromise](/techniques/T1195) <small style="color:#929393">(v1.6)</small>
  * [Compromise Hardware Supply Chain](/techniques/T1195/003) <small style="color:#929393">(v1.1)</small>
  * [Compromise Software Dependencies and Development Tools](/techniques/T1195/001) <small style="color:#929393">(v1.2)</small>
  * [Compromise Software Supply Chain](/techniques/T1195/002) <small style="color:#929393">(v1.1)</small>
* System Binary Proxy Execution: [Electron Applications](/techniques/T1218/015) <small style="color:#929393">(v1.0)</small>
* System Binary Proxy Execution: [Mavinject](/techniques/T1218/013) <small style="color:#929393">(v2.0)</small>
* [System Location Discovery](/techniques/T1614) <small style="color:#929393">(v1.1)</small>
* System Network Configuration Discovery: [Wi-Fi Discovery](/techniques/T1016/002) <small style="color:#929393">(v1.0)</small>
* System Script Proxy Execution: [SyncAppvPublishingServer](/techniques/T1216/002) <small style="color:#929393">(v1.0)</small>
* [System Service Discovery](/techniques/T1007) <small style="color:#929393">(v1.5)</small>
* Traffic Signaling: [Socket Filters](/techniques/T1205/002) <small style="color:#929393">(v1.0)</small>
* [Transfer Data to Cloud Account](/techniques/T1537) <small style="color:#929393">(v1.5)</small>
* [Trusted Relationship](/techniques/T1199) <small style="color:#929393">(v2.4)</small>
* Unsecured Credentials: [Bash History](/techniques/T1552/003) <small style="color:#929393">(v1.2)</small>
* Unsecured Credentials: [Chat Messages](/techniques/T1552/008) <small style="color:#929393">(v1.1)</small>
* Unsecured Credentials: [Cloud Instance Metadata API](/techniques/T1552/005) <small style="color:#929393">(v1.4)</small>
* Unsecured Credentials: [Container API](/techniques/T1552/007) <small style="color:#929393">(v1.2)</small>
* Unsecured Credentials: [Group Policy Preferences](/techniques/T1552/006) <small style="color:#929393">(v1.1)</small>
* [Unused/Unsupported Cloud Regions](/techniques/T1535) <small style="color:#929393">(v1.1)</small>

#### Revocations

* Hijack Execution Flow: DLL Side-Loading (revoked by Hijack Execution Flow: [DLL](/techniques/T1574/001)) <small style="color:#929393">(v2.1)</small>

### Mobile

#### New Techniques

* [Virtualization Solution](/techniques/T1670) <small style="color:#929393">(v1.0)</small>

#### Major Version Changes

* [SIM Card Swap](/techniques/T1451) <small style="color:#929393">(v1.2&#8594;v2.0)</small>

#### Minor Version Changes

* [Exploitation for Initial Access](/techniques/T1664) <small style="color:#929393">(v1.0&#8594;v1.1)</small>

#### Patches

* [Abuse Elevation Control Mechanism](/techniques/T1626) <small style="color:#929393">(v1.1)</small>
  * [Device Administrator Permissions](/techniques/T1626/001) <small style="color:#929393">(v1.1)</small>
* [Access Notifications](/techniques/T1517) <small style="color:#929393">(v1.2)</small>
* [Account Access Removal](/techniques/T1640) <small style="color:#929393">(v1.1)</small>
* [Application Layer Protocol](/techniques/T1437) <small style="color:#929393">(v1.2)</small>
  * [Web Protocols](/techniques/T1437/001) <small style="color:#929393">(v1.0)</small>
* [Archive Collected Data](/techniques/T1532) <small style="color:#929393">(v2.0)</small>
* [Audio Capture](/techniques/T1429) <small style="color:#929393">(v3.1)</small>
* [Boot or Logon Initialization Scripts](/techniques/T1398) <small style="color:#929393">(v2.1)</small>
* [Call Control](/techniques/T1616) <small style="color:#929393">(v1.2)</small>
* [Command and Scripting Interpreter](/techniques/T1623) <small style="color:#929393">(v1.2)</small>
  * [Unix Shell](/techniques/T1623/001) <small style="color:#929393">(v1.2)</small>
* [Compromise Application Executable](/techniques/T1577) <small style="color:#929393">(v1.0)</small>
* [Compromise Client Software Binary](/techniques/T1645) <small style="color:#929393">(v1.1)</small>
* [Credentials from Password Store](/techniques/T1634) <small style="color:#929393">(v1.1)</small>
  * [Keychain](/techniques/T1634/001) <small style="color:#929393">(v1.1)</small>
* [Data Encrypted for Impact](/techniques/T1471) <small style="color:#929393">(v3.2)</small>
* [Data Manipulation](/techniques/T1641) <small style="color:#929393">(v1.1)</small>
  * [Transmitted Data Manipulation](/techniques/T1641/001) <small style="color:#929393">(v1.1)</small>
* [Data from Local System](/techniques/T1533) <small style="color:#929393">(v1.1)</small>
* [Download New Code at Runtime](/techniques/T1407) <small style="color:#929393">(v1.5)</small>
* [Drive-By Compromise](/techniques/T1456) <small style="color:#929393">(v2.2)</small>
* [Dynamic Resolution](/techniques/T1637) <small style="color:#929393">(v1.1)</small>
  * [Domain Generation Algorithms](/techniques/T1637/001) <small style="color:#929393">(v1.1)</small>
* [Encrypted Channel](/techniques/T1521) <small style="color:#929393">(v2.0)</small>
  * [Asymmetric Cryptography](/techniques/T1521/002) <small style="color:#929393">(v1.0)</small>
  * [Symmetric Cryptography](/techniques/T1521/001) <small style="color:#929393">(v1.0)</small>
* [Endpoint Denial of Service](/techniques/T1642) <small style="color:#929393">(v1.1)</small>
* [Event Triggered Execution](/techniques/T1624) <small style="color:#929393">(v1.1)</small>
  * [Broadcast Receivers](/techniques/T1624/001) <small style="color:#929393">(v1.1)</small>
* [Execution Guardrails](/techniques/T1627) <small style="color:#929393">(v1.1)</small>
  * [Geofencing](/techniques/T1627/001) <small style="color:#929393">(v1.1)</small>
* [Exfiltration Over Alternative Protocol](/techniques/T1639) <small style="color:#929393">(v1.1)</small>
  * [Exfiltration Over Unencrypted Non-C2 Protocol](/techniques/T1639/001) <small style="color:#929393">(v1.1)</small>
* [Exfiltration Over C2 Channel](/techniques/T1646) <small style="color:#929393">(v1.1)</small>
* [Exploitation for Privilege Escalation](/techniques/T1404) <small style="color:#929393">(v2.1)</small>
* [Exploitation of Remote Services](/techniques/T1428) <small style="color:#929393">(v1.2)</small>
* [File and Directory Discovery](/techniques/T1420) <small style="color:#929393">(v1.2)</small>
* [Foreground Persistence](/techniques/T1541) <small style="color:#929393">(v2.1)</small>
* [Generate Traffic from Victim](/techniques/T1643) <small style="color:#929393">(v1.1)</small>
* [Hide Artifacts](/techniques/T1628) <small style="color:#929393">(v1.1)</small>
  * [User Evasion](/techniques/T1628/002) <small style="color:#929393">(v1.0)</small>
* [Hijack Execution Flow](/techniques/T1625) <small style="color:#929393">(v1.1)</small>
  * [System Runtime API Hijacking](/techniques/T1625/001) <small style="color:#929393">(v1.1)</small>
* [Hooking](/techniques/T1617) <small style="color:#929393">(v1.0)</small>
* [Impair Defenses](/techniques/T1629) <small style="color:#929393">(v1.1)</small>
  * [Device Lockout](/techniques/T1629/002) <small style="color:#929393">(v1.1)</small>
  * [Disable or Modify Tools](/techniques/T1629/003) <small style="color:#929393">(v1.1)</small>
* [Indicator Removal on Host](/techniques/T1630) <small style="color:#929393">(v1.1)</small>
  * [Disguise Root/Jailbreak Indicators](/techniques/T1630/003) <small style="color:#929393">(v1.1)</small>
  * [File Deletion](/techniques/T1630/002) <small style="color:#929393">(v1.1)</small>
  * [Uninstall Malicious Application](/techniques/T1630/001) <small style="color:#929393">(v1.1)</small>
* [Ingress Tool Transfer](/techniques/T1544) <small style="color:#929393">(v2.2)</small>
* [Input Capture](/techniques/T1417) <small style="color:#929393">(v2.3)</small>
  * [GUI Input Capture](/techniques/T1417/002) <small style="color:#929393">(v1.1)</small>
  * [Keylogging](/techniques/T1417/001) <small style="color:#929393">(v1.1)</small>
* [Input Injection](/techniques/T1516) <small style="color:#929393">(v1.2)</small>
* [Location Tracking](/techniques/T1430) <small style="color:#929393">(v1.2)</small>
  * [Impersonate SS7 Nodes](/techniques/T1430/002) <small style="color:#929393">(v1.1)</small>
  * [Remote Device Management Services](/techniques/T1430/001) <small style="color:#929393">(v1.1)</small>
* [Masquerading](/techniques/T1655) <small style="color:#929393">(v1.0)</small>
  * [Match Legitimate Name or Location](/techniques/T1655/001) <small style="color:#929393">(v1.0)</small>
* [Native API](/techniques/T1575) <small style="color:#929393">(v2.0)</small>
* [Network Denial of Service](/techniques/T1464) <small style="color:#929393">(v1.3)</small>
* [Network Service Scanning](/techniques/T1423) <small style="color:#929393">(v1.1)</small>
* [Non-Standard Port](/techniques/T1509) <small style="color:#929393">(v2.1)</small>
* [Obfuscated Files or Information](/techniques/T1406) <small style="color:#929393">(v3.1)</small>
  * [Software Packing](/techniques/T1406/002) <small style="color:#929393">(v1.1)</small>
  * [Steganography](/techniques/T1406/001) <small style="color:#929393">(v1.0)</small>
* [Out of Band Data](/techniques/T1644) <small style="color:#929393">(v2.1)</small>
* [Process Discovery](/techniques/T1424) <small style="color:#929393">(v2.1)</small>
* [Process Injection](/techniques/T1631) <small style="color:#929393">(v1.1)</small>
  * [Ptrace System Calls](/techniques/T1631/001) <small style="color:#929393">(v1.1)</small>
* [Protected User Data](/techniques/T1636) <small style="color:#929393">(v1.1)</small>
  * [Calendar Entries](/techniques/T1636/001) <small style="color:#929393">(v1.1)</small>
  * [Call Log](/techniques/T1636/002) <small style="color:#929393">(v1.1)</small>
  * [Contact List](/techniques/T1636/003) <small style="color:#929393">(v1.1)</small>
  * [SMS Messages](/techniques/T1636/004) <small style="color:#929393">(v1.1)</small>
* [Proxy Through Victim](/techniques/T1604) <small style="color:#929393">(v1.1)</small>
* [Remote Access Software](/techniques/T1663) <small style="color:#929393">(v1.0)</small>
* [Replication Through Removable Media](/techniques/T1458) <small style="color:#929393">(v2.1)</small>
* [SMS Control](/techniques/T1582) <small style="color:#929393">(v1.1)</small>
* [Scheduled Task/Job](/techniques/T1603) <small style="color:#929393">(v1.0)</small>
* [Screen Capture](/techniques/T1513) <small style="color:#929393">(v1.3)</small>
* [Software Discovery](/techniques/T1418) <small style="color:#929393">(v2.1)</small>
  * [Security Software Discovery](/techniques/T1418/001) <small style="color:#929393">(v1.1)</small>
* Steal Application Access Token: [URI Hijacking](/techniques/T1635/001) <small style="color:#929393">(v1.1)</small>
* [Stored Application Data](/techniques/T1409) <small style="color:#929393">(v3.1)</small>
* [Subvert Trust Controls](/techniques/T1632) <small style="color:#929393">(v1.1)</small>
  * [Code Signing Policy Modification](/techniques/T1632/001) <small style="color:#929393">(v1.1)</small>
* [Supply Chain Compromise](/techniques/T1474) <small style="color:#929393">(v2.1)</small>
  * [Compromise Hardware Supply Chain](/techniques/T1474/002) <small style="color:#929393">(v1.1)</small>
  * [Compromise Software Dependencies and Development Tools](/techniques/T1474/001) <small style="color:#929393">(v1.1)</small>
  * [Compromise Software Supply Chain](/techniques/T1474/003) <small style="color:#929393">(v1.1)</small>
* [System Information Discovery](/techniques/T1426) <small style="color:#929393">(v1.2)</small>
* [System Network Connections Discovery](/techniques/T1421) <small style="color:#929393">(v2.1)</small>
* [Video Capture](/techniques/T1512) <small style="color:#929393">(v2.1)</small>
* [Virtualization/Sandbox Evasion](/techniques/T1633) <small style="color:#929393">(v1.1)</small>
  * [System Checks](/techniques/T1633/001) <small style="color:#929393">(v1.1)</small>
* [Web Service](/techniques/T1481) <small style="color:#929393">(v1.3)</small>
  * [Bidirectional Communication](/techniques/T1481/002) <small style="color:#929393">(v1.2)</small>
  * [Dead Drop Resolver](/techniques/T1481/001) <small style="color:#929393">(v1.2)</small>
  * [One-Way Communication](/techniques/T1481/003) <small style="color:#929393">(v1.2)</small>

### ICS

#### Patches

* [Activate Firmware Update Mode](/techniques/T0800) <small style="color:#929393">(v1.0)</small>
* [Adversary-in-the-Middle](/techniques/T0830) <small style="color:#929393">(v2.0)</small>
* [Alarm Suppression](/techniques/T0878) <small style="color:#929393">(v1.2)</small>
* [Automated Collection](/techniques/T0802) <small style="color:#929393">(v1.1)</small>
* [Autorun Image](/techniques/T0895) <small style="color:#929393">(v1.0)</small>
* [Block Command Message](/techniques/T0803) <small style="color:#929393">(v1.1)</small>
* [Block Reporting Message](/techniques/T0804) <small style="color:#929393">(v1.0)</small>
* [Block Serial COM](/techniques/T0805) <small style="color:#929393">(v1.1)</small>
* [Brute Force I/O](/techniques/T0806) <small style="color:#929393">(v1.1)</small>
* [Change Credential](/techniques/T0892) <small style="color:#929393">(v1.0)</small>
* [Change Operating Mode](/techniques/T0858) <small style="color:#929393">(v1.0)</small>
* [Command-Line Interface](/techniques/T0807) <small style="color:#929393">(v1.1)</small>
* [Commonly Used Port](/techniques/T0885) <small style="color:#929393">(v1.1)</small>
* [Connection Proxy](/techniques/T0884) <small style="color:#929393">(v1.1)</small>
* [Damage to Property](/techniques/T0879) <small style="color:#929393">(v1.1)</small>
* [Data Destruction](/techniques/T0809) <small style="color:#929393">(v1.0)</small>
* [Data from Information Repositories](/techniques/T0811) <small style="color:#929393">(v1.2)</small>
* [Data from Local System](/techniques/T0893) <small style="color:#929393">(v1.0)</small>
* [Default Credentials](/techniques/T0812) <small style="color:#929393">(v1.0)</small>
* [Denial of Control](/techniques/T0813) <small style="color:#929393">(v1.1)</small>
* [Denial of Service](/techniques/T0814) <small style="color:#929393">(v1.1)</small>
* [Denial of View](/techniques/T0815) <small style="color:#929393">(v1.1)</small>
* [Detect Operating Mode](/techniques/T0868) <small style="color:#929393">(v1.0)</small>
* [Device Restart/Shutdown](/techniques/T0816) <small style="color:#929393">(v1.1)</small>
* [Drive-by Compromise](/techniques/T0817) <small style="color:#929393">(v1.0)</small>
* [Execution through API](/techniques/T0871) <small style="color:#929393">(v1.1)</small>
* [Exploit Public-Facing Application](/techniques/T0819) <small style="color:#929393">(v1.0)</small>
* [Exploitation for Evasion](/techniques/T0820) <small style="color:#929393">(v1.1)</small>
* [Exploitation for Privilege Escalation](/techniques/T0890) <small style="color:#929393">(v1.1)</small>
* [Exploitation of Remote Services](/techniques/T0866) <small style="color:#929393">(v1.0)</small>
* [External Remote Services](/techniques/T0822) <small style="color:#929393">(v1.1)</small>
* [Graphical User Interface](/techniques/T0823) <small style="color:#929393">(v1.1)</small>
* [Hardcoded Credentials](/techniques/T0891) <small style="color:#929393">(v1.0)</small>
* [Hooking](/techniques/T0874) <small style="color:#929393">(v1.2)</small>
* [I/O Image](/techniques/T0877) <small style="color:#929393">(v1.1)</small>
* [Indicator Removal on Host](/techniques/T0872) <small style="color:#929393">(v1.0)</small>
* [Internet Accessible Device](/techniques/T0883) <small style="color:#929393">(v1.0)</small>
* [Lateral Tool Transfer](/techniques/T0867) <small style="color:#929393">(v1.1)</small>
* [Loss of Availability](/techniques/T0826) <small style="color:#929393">(v1.0)</small>
* [Loss of Control](/techniques/T0827) <small style="color:#929393">(v1.0)</small>
* [Loss of Productivity and Revenue](/techniques/T0828) <small style="color:#929393">(v1.0)</small>
* [Loss of Protection](/techniques/T0837) <small style="color:#929393">(v1.0)</small>
* [Loss of Safety](/techniques/T0880) <small style="color:#929393">(v1.0)</small>
* [Loss of View](/techniques/T0829) <small style="color:#929393">(v1.0)</small>
* [Manipulate I/O Image](/techniques/T0835) <small style="color:#929393">(v1.1)</small>
* [Manipulation of Control](/techniques/T0831) <small style="color:#929393">(v1.0)</small>
* [Manipulation of View](/techniques/T0832) <small style="color:#929393">(v1.0)</small>
* [Masquerading](/techniques/T0849) <small style="color:#929393">(v1.1)</small>
* [Modify Alarm Settings](/techniques/T0838) <small style="color:#929393">(v1.2)</small>
* [Modify Controller Tasking](/techniques/T0821) <small style="color:#929393">(v1.2)</small>
* [Modify Parameter](/techniques/T0836) <small style="color:#929393">(v1.3)</small>
* [Modify Program](/techniques/T0889) <small style="color:#929393">(v1.2)</small>
* [Module Firmware](/techniques/T0839) <small style="color:#929393">(v1.1)</small>
* [Monitor Process State](/techniques/T0801) <small style="color:#929393">(v1.0)</small>
* [Native API](/techniques/T0834) <small style="color:#929393">(v1.0)</small>
* [Network Connection Enumeration](/techniques/T0840) <small style="color:#929393">(v1.2)</small>
* [Network Sniffing](/techniques/T0842) <small style="color:#929393">(v1.0)</small>
* [Point & Tag Identification](/techniques/T0861) <small style="color:#929393">(v1.1)</small>
* [Program Download](/techniques/T0843) <small style="color:#929393">(v1.1)</small>
* [Program Upload](/techniques/T0845) <small style="color:#929393">(v1.0)</small>
* [Project File Infection](/techniques/T0873) <small style="color:#929393">(v1.0)</small>
* [Remote Services](/techniques/T0886) <small style="color:#929393">(v1.1)</small>
* [Remote System Discovery](/techniques/T0846) <small style="color:#929393">(v1.1)</small>
* [Remote System Information Discovery](/techniques/T0888) <small style="color:#929393">(v1.1)</small>
* [Replication Through Removable Media](/techniques/T0847) <small style="color:#929393">(v1.0)</small>
* [Rogue Master](/techniques/T0848) <small style="color:#929393">(v1.2)</small>
* [Rootkit](/techniques/T0851) <small style="color:#929393">(v1.1)</small>
* [Screen Capture](/techniques/T0852) <small style="color:#929393">(v1.0)</small>
* [Scripting](/techniques/T0853) <small style="color:#929393">(v1.0)</small>
* [Service Stop](/techniques/T0881) <small style="color:#929393">(v1.1)</small>
* [Spearphishing Attachment](/techniques/T0865) <small style="color:#929393">(v1.1)</small>
* [Spoof Reporting Message](/techniques/T0856) <small style="color:#929393">(v1.2)</small>
* [Standard Application Layer Protocol](/techniques/T0869) <small style="color:#929393">(v1.0)</small>
* [Supply Chain Compromise](/techniques/T0862) <small style="color:#929393">(v1.1)</small>
* [System Binary Proxy Execution](/techniques/T0894) <small style="color:#929393">(v1.0)</small>
* [System Firmware](/techniques/T0857) <small style="color:#929393">(v1.1)</small>
* [Theft of Operational Information](/techniques/T0882) <small style="color:#929393">(v1.0)</small>
* [Transient Cyber Asset](/techniques/T0864) <small style="color:#929393">(v1.2)</small>
* [Unauthorized Command Message](/techniques/T0855) <small style="color:#929393">(v1.2)</small>
* [User Execution](/techniques/T0863) <small style="color:#929393">(v1.1)</small>
* [Valid Accounts](/techniques/T0859) <small style="color:#929393">(v1.1)</small>
* [Wireless Compromise](/techniques/T0860) <small style="color:#929393">(v1.2)</small>
* [Wireless Sniffing](/techniques/T0887) <small style="color:#929393">(v1.1)</small>

## Software

### Enterprise

#### New Software

* [AcidPour](/software/S1167) <small style="color:#929393">(v1.0)</small>
* [Akira _v2](/software/S1194) <small style="color:#929393">(v1.0)</small>
* [BOLDMOVE](/software/S1184) <small style="color:#929393">(v1.0)</small>
* [BlackByte 2.0 Ransomware](/software/S1181) <small style="color:#929393">(v1.0)</small>
* [BlackByte Ransomware](/software/S1180) <small style="color:#929393">(v1.0)</small>
* [Exbyte](/software/S1179) <small style="color:#929393">(v1.0)</small>
* [GoBear](/software/S1197) <small style="color:#929393">(v1.0)</small>
* [Gomir](/software/S1198) <small style="color:#929393">(v1.0)</small>
* [Hannotog](/software/S1211) <small style="color:#929393">(v1.0)</small>
* [J-magic](/software/S1203) <small style="color:#929393">(v1.0)</small>
* [JumbledPath](/software/S1206) <small style="color:#929393">(v1.0)</small>
* [Kapeka](/software/S1190) <small style="color:#929393">(v1.0)</small>
* [LightSpy](/software/S1185) <small style="color:#929393">(v1.0)</small>
* [Line Dancer](/software/S1186) <small style="color:#929393">(v1.0)</small>
* [Line Runner](/software/S1188) <small style="color:#929393">(v1.0)</small>
* [LockBit 2.0](/software/S1199) <small style="color:#929393">(v1.0)</small>
* [LockBit 3.0](/software/S1202) <small style="color:#929393">(v1.0)</small>
* [Lumma Stealer](/software/S1213) <small style="color:#929393">(v1.0)</small>
* [MagicRAT](/software/S1182) <small style="color:#929393">(v1.0)</small>
* [Mango](/software/S1169) <small style="color:#929393">(v1.0)</small>
* [Megazord](/software/S1191) <small style="color:#929393">(v1.0)</small>
* [NICECURL](/software/S1192) <small style="color:#929393">(v1.0)</small>
* [Neo-reGeorg](/software/S1189) <small style="color:#929393">(v1.0)</small>
* [ODAgent](/software/S1170) <small style="color:#929393">(v1.0)</small>
* [OilBooster](/software/S1172) <small style="color:#929393">(v1.0)</small>
* [OilCheck](/software/S1171) <small style="color:#929393">(v1.0)</small>
* [PowerExchange](/software/S1173) <small style="color:#929393">(v1.0)</small>
* [Quick Assist](/software/S1209) <small style="color:#929393">(v1.0)</small>
* [RansomHub](/software/S1212) <small style="color:#929393">(v1.0)</small>
* [Sagerunex](/software/S1210) <small style="color:#929393">(v1.0)</small>
* [SampleCheck5000](/software/S1168) <small style="color:#929393">(v1.0)</small>
* [ShrinkLocker](/software/S1178) <small style="color:#929393">(v1.0)</small>
* [SnappyTCP](/software/S1163) <small style="color:#929393">(v1.0)</small>
* [Solar](/software/S1166) <small style="color:#929393">(v1.0)</small>
* [StealBit](/software/S1200) <small style="color:#929393">(v1.0)</small>
* [StrelaStealer](/software/S1183) <small style="color:#929393">(v1.0)</small>
* [TAMECAT](/software/S1193) <small style="color:#929393">(v1.0)</small>
* [TRANSLATEXT](/software/S1201) <small style="color:#929393">(v1.0)</small>
* [Troll Stealer](/software/S1196) <small style="color:#929393">(v1.0)</small>
* [UPSTYLE](/software/S1164) <small style="color:#929393">(v1.0)</small>
* [XLoader](/software/S1207) <small style="color:#929393">(v1.0)</small>
* [attrib](/software/S1176) <small style="color:#929393">(v1.0)</small>
* [cd00r](/software/S1204) <small style="color:#929393">(v1.0)</small>
* [cipher.exe](/software/S1205) <small style="color:#929393">(v1.0)</small>
* [reGeorg](/software/S1187) <small style="color:#929393">(v1.0)</small>

#### Major Version Changes

* [Akira](/software/S1129) <small style="color:#929393">(v1.0&#8594;v2.0)</small>
* [Sliver](/software/S0633) <small style="color:#929393">(v1.2&#8594;v2.0)</small>

#### Minor Version Changes

* [AcidRain](/software/S1125) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [BPFDoor](/software/S1161) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [BUSHWALK](/software/S1118) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Bad Rabbit](/software/S0606) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Black Basta](/software/S1070) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [BloodHound](/software/S0521) <small style="color:#929393">(v1.6&#8594;v1.7)</small>
* [COATHANGER](/software/S1105) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Cheerscrypt](/software/S1096) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Cyclops Blink](/software/S0687) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Emotet](/software/S0367) <small style="color:#929393">(v1.6&#8594;v1.7)</small>
* [FRAMESTING](/software/S1120) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [GLASSTOKEN](/software/S1117) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Impacket](/software/S0357) <small style="color:#929393">(v1.7&#8594;v1.8)</small>
* [LIGHTWIRE](/software/S1119) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [LITTLELAMB.WOOLTEA](/software/S1121) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [MegaCortex](/software/S0576) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Mimikatz](/software/S0002) <small style="color:#929393">(v1.9&#8594;v1.10)</small>
* [Net](/software/S0039) <small style="color:#929393">(v2.6&#8594;v2.7)</small>
* [PACEMAKER](/software/S1109) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [PITSTOP](/software/S1123) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [PULSECHECK](/software/S1108) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [PlugX](/software/S0013) <small style="color:#929393">(v3.1&#8594;v3.2)</small>
* [QUIETEXIT](/software/S1084) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [RAPIDPULSE](/software/S1113) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Royal](/software/S1073) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [SLIGHTPULSE](/software/S1110) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [SLOWPULSE](/software/S1104) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [STEADYPULSE](/software/S1112) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [SYNful Knock](/software/S0519) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Tor](/software/S0183) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
* [VPNFilter](/software/S1010) <small style="color:#929393">(v2.0&#8594;v2.1)</small>
* [VersaMem](/software/S1154) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [WARPWIRE](/software/S1116) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [WIREFIRE](/software/S1115) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [XCSSET](/software/S0658) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
* [ZIPLINE](/software/S1114) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [certutil](/software/S0160) <small style="color:#929393">(v1.4&#8594;v1.5)</small>
* [netsh](/software/S0108) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
* [netstat](/software/S0104) <small style="color:#929393">(v1.3&#8594;v1.4)</small>
* [ngrok](/software/S0508) <small style="color:#929393">(v1.2&#8594;v1.3)</small>

#### Patches

* [3PARA RAT](/software/S0066) <small style="color:#929393">(v1.1)</small>
* [4H RAT](/software/S0065) <small style="color:#929393">(v1.1)</small>
* [AADInternals](/software/S0677) <small style="color:#929393">(v1.2)</small>
* [ABK](/software/S0469) <small style="color:#929393">(v1.0)</small>
* [ADVSTORESHELL](/software/S0045) <small style="color:#929393">(v1.1)</small>
* [Action RAT](/software/S1028) <small style="color:#929393">(v1.0)</small>
* [Agent Tesla](/software/S0331) <small style="color:#929393">(v1.3)</small>
* [Agent.btz](/software/S0092) <small style="color:#929393">(v1.1)</small>
* [AppleJeus](/software/S0584) <small style="color:#929393">(v1.1)</small>
* [AppleSeed](/software/S0622) <small style="color:#929393">(v1.1)</small>
* [Arp](/software/S0099) <small style="color:#929393">(v1.2)</small>
* [AuTo Stealer](/software/S1029) <small style="color:#929393">(v1.0)</small>
* [AutoIt backdoor](/software/S0129) <small style="color:#929393">(v1.1)</small>
* [Avaddon](/software/S0640) <small style="color:#929393">(v1.0)</small>
* [AvosLocker](/software/S1053) <small style="color:#929393">(v1.0)</small>
* [Azorult](/software/S0344) <small style="color:#929393">(v1.3)</small>
* [BACKSPACE](/software/S0031) <small style="color:#929393">(v1.1)</small>
* [BADCALL](/software/S0245) <small style="color:#929393">(v1.1)</small>
* [BADFLICK](/software/S0642) <small style="color:#929393">(v1.0)</small>
* [BADNEWS](/software/S0128) <small style="color:#929393">(v1.2)</small>
* [BBK](/software/S0470) <small style="color:#929393">(v1.0)</small>
* [BBSRAT](/software/S0127) <small style="color:#929393">(v1.2)</small>
* [BITSAdmin](/software/S0190) <small style="color:#929393">(v1.4)</small>
* [BLACKCOFFEE](/software/S0069) <small style="color:#929393">(v1.1)</small>
* [BONDUPDATER](/software/S0360) <small style="color:#929393">(v1.2)</small>
* [BOOTRASH](/software/S0114) <small style="color:#929393">(v1.1)</small>
* [BS2005](/software/S0014) <small style="color:#929393">(v1.1)</small>
* [BUBBLEWRAP](/software/S0043) <small style="color:#929393">(v1.1)</small>
* [Babuk](/software/S0638) <small style="color:#929393">(v1.0)</small>
* [BackConfig](/software/S0475) <small style="color:#929393">(v1.1)</small>
* [Backdoor.Oldrea](/software/S0093) <small style="color:#929393">(v2.0)</small>
* [BadPatch](/software/S0337) <small style="color:#929393">(v1.1)</small>
* [Bandook](/software/S0234) <small style="color:#929393">(v2.0)</small>
* [Bankshot](/software/S0239) <small style="color:#929393">(v1.1)</small>
* [BlackCat](/software/S1068) <small style="color:#929393">(v1.0)</small>
* [BlackMould](/software/S0564) <small style="color:#929393">(v1.0)</small>
* [Bonadan](/software/S0486) <small style="color:#929393">(v1.0)</small>
* [BoomBox](/software/S0635) <small style="color:#929393">(v1.0)</small>
* [BoxCaon](/software/S0651) <small style="color:#929393">(v1.0)</small>
* [Brave Prince](/software/S0252) <small style="color:#929393">(v1.2)</small>
* [Briba](/software/S0204) <small style="color:#929393">(v1.0)</small>
* [Bundlore](/software/S0482) <small style="color:#929393">(v1.1)</small>
* [CALENDAR](/software/S0025) <small style="color:#929393">(v1.2)</small>
* [CARROTBALL](/software/S0465) <small style="color:#929393">(v1.0)</small>
* [CCBkdr](/software/S0222) <small style="color:#929393">(v1.2)</small>
* [CHOPSTICK](/software/S0023) <small style="color:#929393">(v2.3)</small>
* [CORALDECK](/software/S0212) <small style="color:#929393">(v1.1)</small>
* [CORESHELL](/software/S0137) <small style="color:#929393">(v2.1)</small>
* [CSPY Downloader](/software/S0527) <small style="color:#929393">(v1.0)</small>
* [Cachedump](/software/S0119) <small style="color:#929393">(v1.1)</small>
* [Cadelspy](/software/S0454) <small style="color:#929393">(v1.0)</small>
* [Calisto](/software/S0274) <small style="color:#929393">(v1.1)</small>
* [CallMe](/software/S0077) <small style="color:#929393">(v1.1)</small>
* [Cannon](/software/S0351) <small style="color:#929393">(v1.1)</small>
* [Carbanak](/software/S0030) <small style="color:#929393">(v1.1)</small>
* [Carbon](/software/S0335) <small style="color:#929393">(v1.2)</small>
* [Catchamas](/software/S0261) <small style="color:#929393">(v1.1)</small>
* [Caterpillar WebShell](/software/S0572) <small style="color:#929393">(v1.0)</small>
* [ChChes](/software/S0144) <small style="color:#929393">(v1.1)</small>
* [Chaes](/software/S0631) <small style="color:#929393">(v1.1)</small>
* [Chaos](/software/S0220) <small style="color:#929393">(v1.1)</small>
* [CharmPower](/software/S0674) <small style="color:#929393">(v1.0)</small>
* [Cherry Picker](/software/S0107) <small style="color:#929393">(v1.1)</small>
* [Clambling](/software/S0660) <small style="color:#929393">(v1.0)</small>
* [Clop](/software/S0611) <small style="color:#929393">(v1.0)</small>
* [CloudDuke](/software/S0054) <small style="color:#929393">(v1.1)</small>
* [Cobian RAT](/software/S0338) <small style="color:#929393">(v1.1)</small>
* [CoinTicker](/software/S0369) <small style="color:#929393">(v1.1)</small>
* [ComRAT](/software/S0126) <small style="color:#929393">(v1.4)</small>
* [Comnie](/software/S0244) <small style="color:#929393">(v1.1)</small>
* [Conficker](/software/S0608) <small style="color:#929393">(v1.0)</small>
* [ConnectWise](/software/S0591) <small style="color:#929393">(v1.0)</small>
* [Conti](/software/S0575) <small style="color:#929393">(v2.2)</small>
* [CookieMiner](/software/S0492) <small style="color:#929393">(v1.1)</small>
* [CosmicDuke](/software/S0050) <small style="color:#929393">(v1.1)</small>
* [CostaBricks](/software/S0614) <small style="color:#929393">(v1.1)</small>
* [CreepyDrive](/software/S1023) <small style="color:#929393">(v1.0)</small>
* [CreepySnail](/software/S1024) <small style="color:#929393">(v1.0)</small>
* [Crimson](/software/S0115) <small style="color:#929393">(v1.3)</small>
* [Crutch](/software/S0538) <small style="color:#929393">(v1.0)</small>
* [Cryptoistic](/software/S0498) <small style="color:#929393">(v1.0)</small>
* [Cuba](/software/S0625) <small style="color:#929393">(v1.0)</small>
* [DEATHRANSOM](/software/S0616) <small style="color:#929393">(v1.0)</small>
* [DOGCALL](/software/S0213) <small style="color:#929393">(v1.3)</small>
* [DRATzarus](/software/S0694) <small style="color:#929393">(v1.1)</small>
* [DarkComet](/software/S0334) <small style="color:#929393">(v1.1)</small>
* [DarkTortilla](/software/S1066) <small style="color:#929393">(v1.0)</small>
* [Daserf](/software/S0187) <small style="color:#929393">(v1.1)</small>
* [DealersChoice](/software/S0243) <small style="color:#929393">(v1.1)</small>
* [Denis](/software/S0354) <small style="color:#929393">(v1.2)</small>
* [Derusbi](/software/S0021) <small style="color:#929393">(v1.2)</small>
* [Diavol](/software/S0659) <small style="color:#929393">(v2.0)</small>
* [Dipsind](/software/S0200) <small style="color:#929393">(v1.1)</small>
* [DnsSystem](/software/S1021) <small style="color:#929393">(v1.0)</small>
* [Dok](/software/S0281) <small style="color:#929393">(v2.0)</small>
* [Doki](/software/S0600) <small style="color:#929393">(v1.0)</small>
* [Donut](/software/S0695) <small style="color:#929393">(v1.0)</small>
* [DownPaper](/software/S0186) <small style="color:#929393">(v1.1)</small>
* [Downdelph](/software/S0134) <small style="color:#929393">(v1.2)</small>
* [Dridex](/software/S0384) <small style="color:#929393">(v2.1)</small>
* [DropBook](/software/S0547) <small style="color:#929393">(v1.1)</small>
* [Drovorub](/software/S0502) <small style="color:#929393">(v1.0)</small>
* [Dtrack](/software/S0567) <small style="color:#929393">(v1.1)</small>
* [Duqu](/software/S0038) <small style="color:#929393">(v1.2)</small>
* [DustySky](/software/S0062) <small style="color:#929393">(v1.1)</small>
* [Dyre](/software/S0024) <small style="color:#929393">(v1.2)</small>
* [ECCENTRICBANDWAGON](/software/S0593) <small style="color:#929393">(v1.0)</small>
* [EKANS](/software/S0605) <small style="color:#929393">(v2.0)</small>
* [ELMER](/software/S0064) <small style="color:#929393">(v1.1)</small>
* [EVILNUM](/software/S0568) <small style="color:#929393">(v1.0)</small>
* [Ecipekac](/software/S0624) <small style="color:#929393">(v1.0)</small>
* [Egregor](/software/S0554) <small style="color:#929393">(v1.0)</small>
* [Elise](/software/S0081) <small style="color:#929393">(v1.3)</small>
* [Emissary](/software/S0082) <small style="color:#929393">(v1.3)</small>
* [Epic](/software/S0091) <small style="color:#929393">(v1.3)</small>
* [EvilGrab](/software/S0152) <small style="color:#929393">(v1.1)</small>
* [Exaramel for Windows](/software/S0343) <small style="color:#929393">(v2.2)</small>
* [Expand](/software/S0361) <small style="color:#929393">(v1.1)</small>
* [Explosive](/software/S0569) <small style="color:#929393">(v1.0)</small>
* [FALLCHILL](/software/S0181) <small style="color:#929393">(v1.2)</small>
* [FELIXROOT](/software/S0267) <small style="color:#929393">(v2.2)</small>
* [FLASHFLOOD](/software/S0036) <small style="color:#929393">(v1.1)</small>
* [FLIPSIDE](/software/S0173) <small style="color:#929393">(v1.1)</small>
* [FYAnti](/software/S0628) <small style="color:#929393">(v1.0)</small>
* [FakeM](/software/S0076) <small style="color:#929393">(v1.1)</small>
* [FatDuke](/software/S0512) <small style="color:#929393">(v1.1)</small>
* [Felismus](/software/S0171) <small style="color:#929393">(v1.1)</small>
* [Ferocious](/software/S0679) <small style="color:#929393">(v1.0)</small>
* [Fgdump](/software/S0120) <small style="color:#929393">(v1.1)</small>
* [Final1stspy](/software/S0355) <small style="color:#929393">(v1.1)</small>
* [Flame](/software/S0143) <small style="color:#929393">(v1.1)</small>
* [FlawedAmmyy](/software/S0381) <small style="color:#929393">(v1.2)</small>
* [Forfiles](/software/S0193) <small style="color:#929393">(v1.0)</small>
* [FrameworkPOS](/software/S0503) <small style="color:#929393">(v1.0)</small>
* [FruitFly](/software/S0277) <small style="color:#929393">(v1.2)</small>
* [GRIFFON](/software/S0417) <small style="color:#929393">(v1.1)</small>
* [GeminiDuke](/software/S0049) <small style="color:#929393">(v1.1)</small>
* [Get2](/software/S0460) <small style="color:#929393">(v1.0)</small>
* [GoldFinder](/software/S0597) <small style="color:#929393">(v1.1)</small>
* [Goopy](/software/S0477) <small style="color:#929393">(v1.1)</small>
* [Green Lambert](/software/S0690) <small style="color:#929393">(v1.0)</small>
* [GuLoader](/software/S0561) <small style="color:#929393">(v2.0)</small>
* [H1N1](/software/S0132) <small style="color:#929393">(v1.2)</small>
* [HALFBAKED](/software/S0151) <small style="color:#929393">(v1.0)</small>
* [HAMMERTOSS](/software/S0037) <small style="color:#929393">(v1.2)</small>
* [HAPPYWORK](/software/S0214) <small style="color:#929393">(v1.0)</small>
* [HARDRAIN](/software/S0246) <small style="color:#929393">(v1.1)</small>
* [HDoor](/software/S0061) <small style="color:#929393">(v1.0)</small>
* [HELLOKITTY](/software/S0617) <small style="color:#929393">(v1.0)</small>
* [HIDEDRV](/software/S0135) <small style="color:#929393">(v1.1)</small>
* [HTRAN](/software/S0040) <small style="color:#929393">(v1.2)</small>
* [HTTPBrowser](/software/S0070) <small style="color:#929393">(v1.1)</small>
* [Hacking Team UEFI Rootkit](/software/S0047) <small style="color:#929393">(v1.1)</small>
* [Hancitor](/software/S0499) <small style="color:#929393">(v1.0)</small>
* [Havij](/software/S0224) <small style="color:#929393">(v1.0)</small>
* [Hikit](/software/S0009) <small style="color:#929393">(v1.3)</small>
* [Hydraq](/software/S0203) <small style="color:#929393">(v2.0)</small>
* [HyperStack](/software/S0537) <small style="color:#929393">(v1.0)</small>
* [ISMInjector](/software/S0189) <small style="color:#929393">(v1.1)</small>
* [IceApple](/software/S1022) <small style="color:#929393">(v1.1)</small>
* [Industroyer2](/software/S1072) <small style="color:#929393">(v1.0)</small>
* [InnaputRAT](/software/S0259) <small style="color:#929393">(v1.1)</small>
* [InvisiMole](/software/S0260) <small style="color:#929393">(v2.1)</small>
* [Invoke-PSImage](/software/S0231) <small style="color:#929393">(v1.1)</small>
* [Ixeshe](/software/S0015) <small style="color:#929393">(v1.2)</small>
* [JCry](/software/S0389) <small style="color:#929393">(v1.1)</small>
* [JHUHUGIT](/software/S0044) <small style="color:#929393">(v2.2)</small>
* [JPIN](/software/S0201) <small style="color:#929393">(v1.1)</small>
* [JSS Loader](/software/S0648) <small style="color:#929393">(v1.0)</small>
* [Javali](/software/S0528) <small style="color:#929393">(v1.0)</small>
* [KARAE](/software/S0215) <small style="color:#929393">(v1.1)</small>
* [KEYMARBLE](/software/S0271) <small style="color:#929393">(v1.1)</small>
* [KOCTOPUS](/software/S0669) <small style="color:#929393">(v1.2)</small>
* [KOMPROGO](/software/S0156) <small style="color:#929393">(v1.1)</small>
* [KOPILUWAK](/software/S1075) <small style="color:#929393">(v1.0)</small>
* [Kasidet](/software/S0088) <small style="color:#929393">(v1.1)</small>
* [Kazuar](/software/S0265) <small style="color:#929393">(v1.3)</small>
* [Kerrdown](/software/S0585) <small style="color:#929393">(v2.0)</small>
* [Kinsing](/software/S0599) <small style="color:#929393">(v1.1)</small>
* [Kivars](/software/S0437) <small style="color:#929393">(v1.0)</small>
* [Koadic](/software/S0250) <small style="color:#929393">(v2.0)</small>
* [Kobalos](/software/S0641) <small style="color:#929393">(v1.0)</small>
* [Komplex](/software/S0162) <small style="color:#929393">(v1.1)</small>
* [LOWBALL](/software/S0042) <small style="color:#929393">(v1.1)</small>
* [Linfo](/software/S0211) <small style="color:#929393">(v1.1)</small>
* [Linux Rabbit](/software/S0362) <small style="color:#929393">(v1.2)</small>
* [LiteDuke](/software/S0513) <small style="color:#929393">(v1.0)</small>
* [LitePower](/software/S0680) <small style="color:#929393">(v1.0)</small>
* [Lizar](/software/S0681) <small style="color:#929393">(v1.0)</small>
* [LoJax](/software/S0397) <small style="color:#929393">(v1.1)</small>
* [Lokibot](/software/S0447) <small style="color:#929393">(v2.0)</small>
* [LookBack](/software/S0582) <small style="color:#929393">(v1.0)</small>
* [Lslsass](/software/S0121) <small style="color:#929393">(v1.1)</small>
* [Lucifer](/software/S0532) <small style="color:#929393">(v1.1)</small>
* [Lurid](/software/S0010) <small style="color:#929393">(v1.1)</small>
* [MCMD](/software/S0500) <small style="color:#929393">(v1.1)</small>
* [MESSAGETAP](/software/S0443) <small style="color:#929393">(v1.0)</small>
* [MURKYTOP](/software/S0233) <small style="color:#929393">(v1.1)</small>
* [MacSpy](/software/S0282) <small style="color:#929393">(v1.1)</small>
* [Machete](/software/S0409) <small style="color:#929393">(v2.1)</small>
* [MarkiRAT](/software/S0652) <small style="color:#929393">(v1.0)</small>
* [Matryoshka](/software/S0167) <small style="color:#929393">(v2.0)</small>
* [Maze](/software/S0449) <small style="color:#929393">(v1.2)</small>
* [MechaFlounder](/software/S0459) <small style="color:#929393">(v1.0)</small>
* [Meteor](/software/S0688) <small style="color:#929393">(v1.0)</small>
* [MimiPenguin](/software/S0179) <small style="color:#929393">(v1.2)</small>
* [MiniDuke](/software/S0051) <small style="color:#929393">(v1.3)</small>
* [MirageFox](/software/S0280) <small style="color:#929393">(v1.1)</small>
* [Mis-Type](/software/S0084) <small style="color:#929393">(v1.2)</small>
* [Misdat](/software/S0083) <small style="color:#929393">(v1.2)</small>
* [Mivast](/software/S0080) <small style="color:#929393">(v1.1)</small>
* [MobileOrder](/software/S0079) <small style="color:#929393">(v1.0)</small>
* [MoleNet](/software/S0553) <small style="color:#929393">(v1.0)</small>
* [Mongall](/software/S1026) <small style="color:#929393">(v1.0)</small>
* [MoonWind](/software/S0149) <small style="color:#929393">(v1.1)</small>
* [Mori](/software/S1047) <small style="color:#929393">(v1.0)</small>
* [Mythic](/software/S0699) <small style="color:#929393">(v1.0)</small>
* [NBTscan](/software/S0590) <small style="color:#929393">(v1.0)</small>
* [NDiskMonitor](/software/S0272) <small style="color:#929393">(v1.1)</small>
* [NETEAGLE](/software/S0034) <small style="color:#929393">(v1.1)</small>
* [NETWIRE](/software/S0198) <small style="color:#929393">(v1.6)</small>
* [NOKKI](/software/S0353) <small style="color:#929393">(v1.1)</small>
* [Naid](/software/S0205) <small style="color:#929393">(v1.0)</small>
* [NativeZone](/software/S0637) <small style="color:#929393">(v1.0)</small>
* [NavRAT](/software/S0247) <small style="color:#929393">(v1.1)</small>
* [Nebulae](/software/S0630) <small style="color:#929393">(v1.0)</small>
* [Neoichor](/software/S0691) <small style="color:#929393">(v1.0)</small>
* [Nerex](/software/S0210) <small style="color:#929393">(v1.0)</small>
* [Net Crawler](/software/S0056) <small style="color:#929393">(v1.1)</small>
* [NetTraveler](/software/S0033) <small style="color:#929393">(v1.1)</small>
* [Netwalker](/software/S0457) <small style="color:#929393">(v1.1)</small>
* [Nidiran](/software/S0118) <small style="color:#929393">(v1.1)</small>
* [NotPetya](/software/S0368) <small style="color:#929393">(v2.0)</small>
* [OLDBAIT](/software/S0138) <small style="color:#929393">(v1.1)</small>
* [OSInfo](/software/S0165) <small style="color:#929393">(v1.1)</small>
* [OSX/Shlayer](/software/S0402) <small style="color:#929393">(v1.4)</small>
* [ObliqueRAT](/software/S0644) <small style="color:#929393">(v1.0)</small>
* [OceanSalt](/software/S0346) <small style="color:#929393">(v1.1)</small>
* [Octopus](/software/S0340) <small style="color:#929393">(v2.0)</small>
* [Okrum](/software/S0439) <small style="color:#929393">(v1.0)</small>
* [Olympic Destroyer](/software/S0365) <small style="color:#929393">(v2.0)</small>
* [OnionDuke](/software/S0052) <small style="color:#929393">(v1.2)</small>
* [OopsIE](/software/S0264) <small style="color:#929393">(v1.2)</small>
* [Orz](/software/S0229) <small style="color:#929393">(v2.2)</small>
* [Out1](/software/S0594) <small style="color:#929393">(v1.0)</small>
* [OwaAuth](/software/S0072) <small style="color:#929393">(v1.2)</small>
* [P.A.S. Webshell](/software/S0598) <small style="color:#929393">(v1.0)</small>
* [P8RAT](/software/S0626) <small style="color:#929393">(v1.0)</small>
* [PHOREAL](/software/S0158) <small style="color:#929393">(v1.1)</small>
* [PLAINTEE](/software/S0254) <small style="color:#929393">(v1.1)</small>
* [PLEAD](/software/S0435) <small style="color:#929393">(v2.0)</small>
* [POORAIM](/software/S0216) <small style="color:#929393">(v1.1)</small>
* [POSHSPY](/software/S0150) <small style="color:#929393">(v1.2)</small>
* [POWERSOURCE](/software/S0145) <small style="color:#929393">(v1.1)</small>
* [POWERSTATS](/software/S0223) <small style="color:#929393">(v2.3)</small>
* [POWERTON](/software/S0371) <small style="color:#929393">(v1.1)</small>
* [POWRUNER](/software/S0184) <small style="color:#929393">(v1.1)</small>
* [PUNCHBUGGY](/software/S0196) <small style="color:#929393">(v2.1)</small>
* [PUNCHTRACK](/software/S0197) <small style="color:#929393">(v1.1)</small>
* [Pandora](/software/S0664) <small style="color:#929393">(v1.0)</small>
* [Pasam](/software/S0208) <small style="color:#929393">(v1.1)</small>
* [Pass-The-Hash Toolkit](/software/S0122) <small style="color:#929393">(v1.0)</small>
* [Pay2Key](/software/S0556) <small style="color:#929393">(v1.0)</small>
* [Peirates](/software/S0683) <small style="color:#929393">(v1.0)</small>
* [Peppy](/software/S0643) <small style="color:#929393">(v1.0)</small>
* [Pillowmint](/software/S0517) <small style="color:#929393">(v1.2)</small>
* [PinchDuke](/software/S0048) <small style="color:#929393">(v1.1)</small>
* [Ping](/software/S0097) <small style="color:#929393">(v1.4)</small>
* [PingPull](/software/S1031) <small style="color:#929393">(v1.0)</small>
* [Pisloader](/software/S0124) <small style="color:#929393">(v1.1)</small>
* [PoisonIvy](/software/S0012) <small style="color:#929393">(v2.2)</small>
* [PolyglotDuke](/software/S0518) <small style="color:#929393">(v1.1)</small>
* [Pony](/software/S0453) <small style="color:#929393">(v1.0)</small>
* [PoshC2](/software/S0378) <small style="color:#929393">(v1.3)</small>
* [PowGoop](/software/S1046) <small style="color:#929393">(v1.0)</small>
* [Power Loader](/software/S0177) <small style="color:#929393">(v1.0)</small>
* [PowerDuke](/software/S0139) <small style="color:#929393">(v1.2)</small>
* [PowerLess](/software/S1012) <small style="color:#929393">(v1.1)</small>
* [PowerPunch](/software/S0685) <small style="color:#929393">(v1.1)</small>
* [PowerShower](/software/S0441) <small style="color:#929393">(v1.0)</small>
* [PowerSploit](/software/S0194) <small style="color:#929393">(v1.6)</small>
* [PowerStallion](/software/S0393) <small style="color:#929393">(v1.1)</small>
* [Prestige](/software/S1058) <small style="color:#929393">(v1.0)</small>
* [ProLock](/software/S0654) <small style="color:#929393">(v1.0)</small>
* [Proton](/software/S0279) <small style="color:#929393">(v1.2)</small>
* [Proxysvc](/software/S0238) <small style="color:#929393">(v1.2)</small>
* [Psylo](/software/S0078) <small style="color:#929393">(v1.1)</small>
* [Pteranodon](/software/S0147) <small style="color:#929393">(v2.1)</small>
* [Pysa](/software/S0583) <small style="color:#929393">(v1.0)</small>
* [QUADAGENT](/software/S0269) <small style="color:#929393">(v1.2)</small>
* [QUIETCANARY](/software/S1076) <small style="color:#929393">(v1.0)</small>
* [QakBot](/software/S0650) <small style="color:#929393">(v1.3)</small>
* [QuietSieve](/software/S0686) <small style="color:#929393">(v1.0)</small>
* [RARSTONE](/software/S0055) <small style="color:#929393">(v1.1)</small>
* [RATANKBA](/software/S0241) <small style="color:#929393">(v1.1)</small>
* [RDAT](/software/S0495) <small style="color:#929393">(v1.0)</small>
* [RDFSNIFFER](/software/S0416) <small style="color:#929393">(v1.0)</small>
* [REvil](/software/S0496) <small style="color:#929393">(v2.2)</small>
* [RGDoor](/software/S0258) <small style="color:#929393">(v1.2)</small>
* [RIPTIDE](/software/S0003) <small style="color:#929393">(v1.1)</small>
* [ROCKBOOT](/software/S0112) <small style="color:#929393">(v1.1)</small>
* [ROKRAT](/software/S0240) <small style="color:#929393">(v2.3)</small>
* [RTM](/software/S0148) <small style="color:#929393">(v1.2)</small>
* [Ragnar Locker](/software/S0481) <small style="color:#929393">(v1.2)</small>
* [Ramsay](/software/S0458) <small style="color:#929393">(v1.1)</small>
* [RawDisk](/software/S0364) <small style="color:#929393">(v1.1)</small>
* [RawPOS](/software/S0169) <small style="color:#929393">(v1.1)</small>
* [Reg](/software/S0075) <small style="color:#929393">(v1.1)</small>
* [RegDuke](/software/S0511) <small style="color:#929393">(v1.1)</small>
* [Remcos](/software/S0332) <small style="color:#929393">(v1.3)</small>
* [RemoteCMD](/software/S0166) <small style="color:#929393">(v1.1)</small>
* [RemoteUtilities](/software/S0592) <small style="color:#929393">(v1.0)</small>
* [Responder](/software/S0174) <small style="color:#929393">(v1.2)</small>
* [Revenge RAT](/software/S0379) <small style="color:#929393">(v1.2)</small>
* [RobbinHood](/software/S0400) <small style="color:#929393">(v1.1)</small>
* [RogueRobin](/software/S0270) <small style="color:#929393">(v2.2)</small>
* [Rover](/software/S0090) <small style="color:#929393">(v1.1)</small>
* [Rubeus](/software/S1071) <small style="color:#929393">(v1.1)</small>
* [Ruler](/software/S0358) <small style="color:#929393">(v1.1)</small>
* [RunningRAT](/software/S0253) <small style="color:#929393">(v1.1)</small>
* [Ryuk](/software/S0446) <small style="color:#929393">(v1.4)</small>
* [S-Type](/software/S0085) <small style="color:#929393">(v1.3)</small>
* [SDBbot](/software/S0461) <small style="color:#929393">(v2.1)</small>
* [SDelete](/software/S0195) <small style="color:#929393">(v1.2)</small>
* [SEASHARPEE](/software/S0185) <small style="color:#929393">(v2.0)</small>
* [SHARPSTATS](/software/S0450) <small style="color:#929393">(v1.1)</small>
* [SHIPSHAPE](/software/S0028) <small style="color:#929393">(v1.0)</small>
* [SHOTPUT](/software/S0063) <small style="color:#929393">(v1.1)</small>
* [SHUTTERSPEED](/software/S0217) <small style="color:#929393">(v1.0)</small>
* [SLOWDRIFT](/software/S0218) <small style="color:#929393">(v1.1)</small>
* [SMOKEDHAM](/software/S0649) <small style="color:#929393">(v1.2)</small>
* [SNUGRIDE](/software/S0159) <small style="color:#929393">(v1.1)</small>
* [SOUNDBITE](/software/S0157) <small style="color:#929393">(v1.1)</small>
* [SPACESHIP](/software/S0035) <small style="color:#929393">(v1.1)</small>
* [SQLRat](/software/S0390) <small style="color:#929393">(v1.2)</small>
* [SUGARDUMP](/software/S1042) <small style="color:#929393">(v1.0)</small>
* [SUGARUSH](/software/S1049) <small style="color:#929393">(v1.0)</small>
* [SUNSPOT](/software/S0562) <small style="color:#929393">(v1.2)</small>
* [SVCReady](/software/S1064) <small style="color:#929393">(v1.0)</small>
* [SYSCON](/software/S0464) <small style="color:#929393">(v1.1)</small>
* [SeaDuke](/software/S0053) <small style="color:#929393">(v1.1)</small>
* [ServHelper](/software/S0382) <small style="color:#929393">(v1.2)</small>
* [Seth-Locker](/software/S0639) <small style="color:#929393">(v1.0)</small>
* [ShadowPad](/software/S0596) <small style="color:#929393">(v1.2)</small>
* [Shamoon](/software/S0140) <small style="color:#929393">(v2.2)</small>
* [SharpDisco](/software/S1089) <small style="color:#929393">(v1.0)</small>
* [SharpStage](/software/S0546) <small style="color:#929393">(v1.1)</small>
* [ShimRat](/software/S0444) <small style="color:#929393">(v1.0)</small>
* [ShimRatReporter](/software/S0445) <small style="color:#929393">(v1.0)</small>
* [Sibot](/software/S0589) <small style="color:#929393">(v1.1)</small>
* [SideTwist](/software/S0610) <small style="color:#929393">(v1.0)</small>
* [Siloscape](/software/S0623) <small style="color:#929393">(v1.0)</small>
* [Small Sieve](/software/S1035) <small style="color:#929393">(v1.0)</small>
* [Socksbot](/software/S0273) <small style="color:#929393">(v1.1)</small>
* [SodaMaster](/software/S0627) <small style="color:#929393">(v1.0)</small>
* [SombRAT](/software/S0615) <small style="color:#929393">(v1.2)</small>
* [SoreFang](/software/S0516) <small style="color:#929393">(v1.0)</small>
* [Spark](/software/S0543) <small style="color:#929393">(v1.1)</small>
* [SpicyOmelette](/software/S0646) <small style="color:#929393">(v1.0)</small>
* [SslMM](/software/S0058) <small style="color:#929393">(v1.1)</small>
* [Starloader](/software/S0188) <small style="color:#929393">(v1.1)</small>
* [StreamEx](/software/S0142) <small style="color:#929393">(v1.1)</small>
* [StrifeWater](/software/S1034) <small style="color:#929393">(v1.0)</small>
* [Stuxnet](/software/S0603) <small style="color:#929393">(v1.4)</small>
* [Sykipot](/software/S0018) <small style="color:#929393">(v1.1)</small>
* [SynAck](/software/S0242) <small style="color:#929393">(v1.3)</small>
* [Sys10](/software/S0060) <small style="color:#929393">(v1.1)</small>
* [Systeminfo](/software/S0096) <small style="color:#929393">(v1.2)</small>
* [T9000](/software/S0098) <small style="color:#929393">(v1.1)</small>
* [TAINTEDSCRIBE](/software/S0586) <small style="color:#929393">(v1.0)</small>
* [TDTESS](/software/S0164) <small style="color:#929393">(v1.1)</small>
* [TEARDROP](/software/S0560) <small style="color:#929393">(v1.2)</small>
* [TEXTMATE](/software/S0146) <small style="color:#929393">(v1.1)</small>
* [TSCookie](/software/S0436) <small style="color:#929393">(v1.0)</small>
* [TURNEDUP](/software/S0199) <small style="color:#929393">(v1.1)</small>
* [TajMahal](/software/S0467) <small style="color:#929393">(v1.0)</small>
* [Tarrask](/software/S1011) <small style="color:#929393">(v1.0)</small>
* [ThiefQuest](/software/S0595) <small style="color:#929393">(v1.2)</small>
* [TinyTurla](/software/S0668) <small style="color:#929393">(v1.1)</small>
* [TinyZBot](/software/S0004) <small style="color:#929393">(v1.1)</small>
* [Tomiris](/software/S0671) <small style="color:#929393">(v1.0)</small>
* [TrailBlazer](/software/S0682) <small style="color:#929393">(v1.1)</small>
* [Trojan.Karagany](/software/S0094) <small style="color:#929393">(v3.0)</small>
* [Trojan.Mebromi](/software/S0001) <small style="color:#929393">(v1.1)</small>
* [Truvasys](/software/S0178) <small style="color:#929393">(v1.1)</small>
* [Turian](/software/S0647) <small style="color:#929393">(v1.0)</small>
* [UACMe](/software/S0116) <small style="color:#929393">(v1.0)</small>
* [UPPERCUT](/software/S0275) <small style="color:#929393">(v1.1)</small>
* [USBferry](/software/S0452) <small style="color:#929393">(v1.0)</small>
* [Umbreon](/software/S0221) <small style="color:#929393">(v1.1)</small>
* [Unknown Logger](/software/S0130) <small style="color:#929393">(v1.1)</small>
* [VBShower](/software/S0442) <small style="color:#929393">(v1.0)</small>
* [Valak](/software/S0476) <small style="color:#929393">(v1.3)</small>
* [VaporRage](/software/S0636) <small style="color:#929393">(v1.0)</small>
* [Vasport](/software/S0207) <small style="color:#929393">(v1.1)</small>
* [WINDSHIELD](/software/S0155) <small style="color:#929393">(v1.0)</small>
* [WINERACK](/software/S0219) <small style="color:#929393">(v1.0)</small>
* [WannaCry](/software/S0366) <small style="color:#929393">(v1.1)</small>
* [WellMail](/software/S0515) <small style="color:#929393">(v1.0)</small>
* [WellMess](/software/S0514) <small style="color:#929393">(v1.0)</small>
* [Wiarp](/software/S0206) <small style="color:#929393">(v1.1)</small>
* [WinMM](/software/S0059) <small style="color:#929393">(v1.1)</small>
* [WindTail](/software/S0466) <small style="color:#929393">(v1.1)</small>
* [Wingbird](/software/S0176) <small style="color:#929393">(v1.1)</small>
* [Wiper](/software/S0041) <small style="color:#929393">(v1.0)</small>
* [XAgentOSX](/software/S0161) <small style="color:#929393">(v1.3)</small>
* [XTunnel](/software/S0117) <small style="color:#929393">(v2.1)</small>
* [Xbash](/software/S0341) <small style="color:#929393">(v1.2)</small>
* [ZLib](/software/S0086) <small style="color:#929393">(v1.2)</small>
* [Zebrocy](/software/S0251) <small style="color:#929393">(v3.0)</small>
* [Zeroaccess](/software/S0027) <small style="color:#929393">(v1.0)</small>
* [ZxShell](/software/S0412) <small style="color:#929393">(v1.2)</small>
* [adbupd](/software/S0202) <small style="color:#929393">(v1.1)</small>
* [at](/software/S0110) <small style="color:#929393">(v1.3)</small>
* [build_downer](/software/S0471) <small style="color:#929393">(v1.0)</small>
* [ccf32](/software/S1043) <small style="color:#929393">(v1.0)</small>
* [cmd](/software/S0106) <small style="color:#929393">(v1.2)</small>
* [down_new](/software/S0472) <small style="color:#929393">(v1.0)</small>
* [dsquery](/software/S0105) <small style="color:#929393">(v1.4)</small>
* [gsecdump](/software/S0008) <small style="color:#929393">(v1.2)</small>
* [hcdLoader](/software/S0071) <small style="color:#929393">(v1.1)</small>
* [httpclient](/software/S0068) <small style="color:#929393">(v1.1)</small>
* [iKitten](/software/S0278) <small style="color:#929393">(v1.1)</small>
* [ifconfig](/software/S0101) <small style="color:#929393">(v1.0)</small>
* [ipconfig](/software/S0100) <small style="color:#929393">(v1.1)</small>
* [macOS.OSAMiner](/software/S1048) <small style="color:#929393">(v1.0)</small>
* [meek](/software/S0175) <small style="color:#929393">(v1.0)</small>
* [nbtstat](/software/S0102) <small style="color:#929393">(v1.0)</small>
* [njRAT](/software/S0385) <small style="color:#929393">(v1.6)</small>
* [pngdowner](/software/S0067) <small style="color:#929393">(v1.1)</small>
* [pwdump](/software/S0006) <small style="color:#929393">(v1.1)</small>
* [route](/software/S0103) <small style="color:#929393">(v1.1)</small>
* [schtasks](/software/S0111) <small style="color:#929393">(v1.2)</small>
* [spwebmember](/software/S0227) <small style="color:#929393">(v1.1)</small>
* [sqlmap](/software/S0225) <small style="color:#929393">(v1.0)</small>
* [xCaon](/software/S0653) <small style="color:#929393">(v1.0)</small>
* [xCmd](/software/S0123) <small style="color:#929393">(v1.0)</small>
* [yty](/software/S0248) <small style="color:#929393">(v1.2)</small>
* [zwShell](/software/S0350) <small style="color:#929393">(v2.0)</small>

### Mobile

#### New Software

* [Android/SpyAgent](/software/S1214) <small style="color:#929393">(v1.0)</small>
* [Binary Validator](/software/S1215) <small style="color:#929393">(v1.0)</small>
* [FjordPhantom](/software/S1208) <small style="color:#929393">(v1.0)</small>
* [LightSpy](/software/S1185) <small style="color:#929393">(v1.0)</small>
* [SpyC23](/software/S1195) <small style="color:#929393">(v1.0)</small>
* [TriangleDB](/software/S1216) <small style="color:#929393">(v1.0)</small>

#### Minor Version Changes

* [Desert Scorpion](/software/S0505) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [FluBot](/software/S1067) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [FrozenCell](/software/S0577) <small style="color:#929393">(v1.0&#8594;v1.1)</small>

#### Patches

* [ANDROIDOS_ANSERVER.A](/software/S0310) <small style="color:#929393">(v1.3)</small>
* [AbstractEmu](/software/S1061) <small style="color:#929393">(v1.0)</small>
* [Adups](/software/S0309) <small style="color:#929393">(v1.0)</small>
* [Agent Smith](/software/S0440) <small style="color:#929393">(v1.0)</small>
* [AhRat](/software/S1095) <small style="color:#929393">(v1.0)</small>
* [Allwinner](/software/S0319) <small style="color:#929393">(v1.0)</small>
* [AndroRAT](/software/S0292) <small style="color:#929393">(v1.1)</small>
* [Android/AdDisplay.Ashas](/software/S0525) <small style="color:#929393">(v1.0)</small>
* [Android/Chuli.A](/software/S0304) <small style="color:#929393">(v1.2)</small>
* [AndroidOS/MalLocker.B](/software/S0524) <small style="color:#929393">(v1.0)</small>
* [Asacub](/software/S0540) <small style="color:#929393">(v1.0)</small>
* [BrainTest](/software/S0293) <small style="color:#929393">(v1.0)</small>
* [Bread](/software/S0432) <small style="color:#929393">(v1.2)</small>
* [BusyGasper](/software/S0655) <small style="color:#929393">(v1.0)</small>
* [CHEMISTGAMES](/software/S0555) <small style="color:#929393">(v1.0)</small>
* [CarbonSteal](/software/S0529) <small style="color:#929393">(v1.1)</small>
* [Cerberus](/software/S0480) <small style="color:#929393">(v1.1)</small>
* [Chameleon](/software/S1083) <small style="color:#929393">(v1.0)</small>
* [Charger](/software/S0323) <small style="color:#929393">(v1.1)</small>
* [Circles](/software/S0602) <small style="color:#929393">(v1.0)</small>
* [Concipit1248](/software/S0426) <small style="color:#929393">(v1.0)</small>
* [Corona Updates](/software/S0425) <small style="color:#929393">(v1.1)</small>
* [DEFENSOR ID](/software/S0479) <small style="color:#929393">(v1.0)</small>
* [Dendroid](/software/S0301) <small style="color:#929393">(v2.0)</small>
* [DoubleAgent](/software/S0550) <small style="color:#929393">(v1.0)</small>
* [DressCode](/software/S0300) <small style="color:#929393">(v1.0)</small>
* [Drinik](/software/S1054) <small style="color:#929393">(v1.0)</small>
* [DroidJack](/software/S0320) <small style="color:#929393">(v1.2)</small>
* [DualToy](/software/S0315) <small style="color:#929393">(v1.0)</small>
* [Dvmap](/software/S0420) <small style="color:#929393">(v1.0)</small>
* [EventBot](/software/S0478) <small style="color:#929393">(v1.0)</small>
* [Exodus](/software/S0405) <small style="color:#929393">(v1.0)</small>
* [FakeSpy](/software/S0509) <small style="color:#929393">(v1.0)</small>
* [FlexiSpy](/software/S0408) <small style="color:#929393">(v1.0)</small>
* [GPlayed](/software/S0536) <small style="color:#929393">(v1.0)</small>
* [Ginp](/software/S0423) <small style="color:#929393">(v1.1)</small>
* [Golden Cup](/software/S0535) <small style="color:#929393">(v1.0)</small>
* [GoldenEagle](/software/S0551) <small style="color:#929393">(v1.0)</small>
* [GolfSpy](/software/S0421) <small style="color:#929393">(v1.0)</small>
* [Gooligan](/software/S0290) <small style="color:#929393">(v1.2)</small>
* [Gustuff](/software/S0406) <small style="color:#929393">(v1.0)</small>
* [HenBox](/software/S0544) <small style="color:#929393">(v1.0)</small>
* [HummingBad](/software/S0322) <small style="color:#929393">(v1.1)</small>
* [HummingWhale](/software/S0321) <small style="color:#929393">(v1.0)</small>
* [INSOMNIA](/software/S0463) <small style="color:#929393">(v1.0)</small>
* [Judy](/software/S0325) <small style="color:#929393">(v1.0)</small>
* [KeyRaider](/software/S0288) <small style="color:#929393">(v1.0)</small>
* [Mandrake](/software/S0485) <small style="color:#929393">(v1.0)</small>
* [MazarBOT](/software/S0303) <small style="color:#929393">(v1.0)</small>
* [Monokle](/software/S0407) <small style="color:#929393">(v1.2)</small>
* [NotCompatible](/software/S0299) <small style="color:#929393">(v1.0)</small>
* [OBAD](/software/S0286) <small style="color:#929393">(v1.0)</small>
* [OldBoot](/software/S0285) <small style="color:#929393">(v1.0)</small>
* [PJApps](/software/S0291) <small style="color:#929393">(v1.0)</small>
* [Pallas](/software/S0399) <small style="color:#929393">(v1.1)</small>
* [Pegasus for Android](/software/S0316) <small style="color:#929393">(v1.2)</small>
* [Phenakite](/software/S1126) <small style="color:#929393">(v1.0)</small>
* [RCSAndroid](/software/S0295) <small style="color:#929393">(v1.2)</small>
* [Red Alert 2.0](/software/S0539) <small style="color:#929393">(v1.0)</small>
* [RedDrop](/software/S0326) <small style="color:#929393">(v1.2)</small>
* [Riltok](/software/S0403) <small style="color:#929393">(v1.0)</small>
* [Rotexy](/software/S0411) <small style="color:#929393">(v1.1)</small>
* [RuMMS](/software/S0313) <small style="color:#929393">(v1.0)</small>
* [S.O.V.A.](/software/S1062) <small style="color:#929393">(v1.0)</small>
* [SharkBot](/software/S1055) <small style="color:#929393">(v1.0)</small>
* [ShiftyBug](/software/S0294) <small style="color:#929393">(v1.0)</small>
* [SilkBean](/software/S0549) <small style="color:#929393">(v1.0)</small>
* [SimBad](/software/S0419) <small style="color:#929393">(v1.0)</small>
* [Skygofree](/software/S0327) <small style="color:#929393">(v1.2)</small>
* [SpyDealer](/software/S0324) <small style="color:#929393">(v1.2)</small>
* [SpyNote RAT](/software/S0305) <small style="color:#929393">(v1.2)</small>
* [Stealth Mango](/software/S0328) <small style="color:#929393">(v1.3)</small>
* [TERRACOTTA](/software/S0545) <small style="color:#929393">(v1.0)</small>
* [Tangelo](/software/S0329) <small style="color:#929393">(v1.2)</small>
* [TangleBot](/software/S1069) <small style="color:#929393">(v1.0)</small>
* [TianySpy](/software/S1056) <small style="color:#929393">(v1.0)</small>
* [Tiktok Pro](/software/S0558) <small style="color:#929393">(v1.0)</small>
* [Triada](/software/S0424) <small style="color:#929393">(v1.0)</small>
* [TrickMo](/software/S0427) <small style="color:#929393">(v1.1)</small>
* [Trojan-SMS.AndroidOS.Agent.ao](/software/S0307) <small style="color:#929393">(v1.0)</small>
* [Trojan-SMS.AndroidOS.FakeInst.a](/software/S0306) <small style="color:#929393">(v1.0)</small>
* [Trojan-SMS.AndroidOS.OpFake.a](/software/S0308) <small style="color:#929393">(v1.0)</small>
* [Twitoor](/software/S0302) <small style="color:#929393">(v2.0)</small>
* [ViceLeaker](/software/S0418) <small style="color:#929393">(v1.0)</small>
* [ViperRAT](/software/S0506) <small style="color:#929393">(v1.0)</small>
* [WireLurker](/software/S0312) <small style="color:#929393">(v1.0)</small>
* [WolfRAT](/software/S0489) <small style="color:#929393">(v1.0)</small>
* [X-Agent for Android](/software/S0314) <small style="color:#929393">(v1.0)</small>
* [XLoader for Android](/software/S0318) <small style="color:#929393">(v2.0)</small>
* [XLoader for iOS](/software/S0490) <small style="color:#929393">(v1.1)</small>
* [Xbot](/software/S0298) <small style="color:#929393">(v1.0)</small>
* [XcodeGhost](/software/S0297) <small style="color:#929393">(v1.0)</small>
* [YiSpecter](/software/S0311) <small style="color:#929393">(v2.0)</small>
* [Zen](/software/S0494) <small style="color:#929393">(v1.0)</small>
* [ZergHelper](/software/S0287) <small style="color:#929393">(v1.0)</small>

### ICS

#### New Software

* [FrostyGoop](/software/S1165) <small style="color:#929393">(v1.0)</small>

#### Minor Version Changes

* [Bad Rabbit](/software/S0606) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [VPNFilter](/software/S1010) <small style="color:#929393">(v2.0&#8594;v2.1)</small>

#### Patches

* [ACAD/Medre.A](/software/S1000) <small style="color:#929393">(v1.0)</small>
* [Backdoor.Oldrea](/software/S0093) <small style="color:#929393">(v2.0)</small>
* [Conficker](/software/S0608) <small style="color:#929393">(v1.0)</small>
* [Duqu](/software/S0038) <small style="color:#929393">(v1.2)</small>
* [EKANS](/software/S0605) <small style="color:#929393">(v2.0)</small>
* [Flame](/software/S0143) <small style="color:#929393">(v1.1)</small>
* [INCONTROLLER](/software/S1045) <small style="color:#929393">(v1.0)</small>
* [Industroyer2](/software/S1072) <small style="color:#929393">(v1.0)</small>
* [NotPetya](/software/S0368) <small style="color:#929393">(v2.0)</small>
* [PLC-Blaster](/software/S1006) <small style="color:#929393">(v1.0)</small>
* [REvil](/software/S0496) <small style="color:#929393">(v2.2)</small>
* [Ryuk](/software/S0446) <small style="color:#929393">(v1.4)</small>
* [Stuxnet](/software/S0603) <small style="color:#929393">(v1.4)</small>
* [WannaCry](/software/S0366) <small style="color:#929393">(v1.1)</small>

## Groups

### Enterprise

#### New Groups

* [APT42](/groups/G1044) <small style="color:#929393">(v1.0)</small>
* [BlackByte](/groups/G1043) <small style="color:#929393">(v1.0)</small>
* [RedEcho](/groups/G1042) <small style="color:#929393">(v1.0)</small>
* [Salt Typhoon](/groups/G1045) <small style="color:#929393">(v1.0)</small>
* [Sea Turtle](/groups/G1041) <small style="color:#929393">(v1.0)</small>
* [Storm-1811](/groups/G1046) <small style="color:#929393">(v1.0)</small>
* [Velvet Ant](/groups/G1047) <small style="color:#929393">(v1.0)</small>

#### Major Version Changes

* [Akira](/groups/G1024) <small style="color:#929393">(v1.0&#8594;v2.0)</small>
* [HAFNIUM](/groups/G0125) <small style="color:#929393">(v2.0&#8594;v3.0)</small>
* [Lotus Blossom](/groups/G0030) <small style="color:#929393">(v3.0&#8594;v4.0)</small>
* [OilRig](/groups/G0049) <small style="color:#929393">(v4.1&#8594;v5.0)</small>

#### Minor Version Changes

* [APT28](/groups/G0007) <small style="color:#929393">(v5.1&#8594;v5.2)</small>
* [APT29](/groups/G0016) <small style="color:#929393">(v6.1&#8594;v6.2)</small>
* [APT38](/groups/G0082) <small style="color:#929393">(v3.0&#8594;v3.1)</small>
* [APT5](/groups/G1023) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Ember Bear](/groups/G1003) <small style="color:#929393">(v2.0&#8594;v2.1)</small>
* [Ke3chang](/groups/G0004) <small style="color:#929393">(v3.0&#8594;v3.1)</small>
* [Kimsuky](/groups/G0094) <small style="color:#929393">(v5.0&#8594;v5.1)</small>
* [LAPSUS$](/groups/G1004) <small style="color:#929393">(v2.0&#8594;v2.1)</small>
* [Lazarus Group](/groups/G0032) <small style="color:#929393">(v4.0&#8594;v4.1)</small>
* [Leviathan](/groups/G0065) <small style="color:#929393">(v4.0&#8594;v4.1)</small>
* [Sandworm Team](/groups/G0034) <small style="color:#929393">(v4.1&#8594;v4.2)</small>
* [ZIRCONIUM](/groups/G0128) <small style="color:#929393">(v2.1&#8594;v2.2)</small>

#### Patches

* [APT-C-23](/groups/G1028) <small style="color:#929393">(v1.0)</small>
* [APT-C-36](/groups/G0099) <small style="color:#929393">(v1.1)</small>
* [APT1](/groups/G0006) <small style="color:#929393">(v1.4)</small>
* [APT12](/groups/G0005) <small style="color:#929393">(v2.1)</small>
* [APT16](/groups/G0023) <small style="color:#929393">(v1.1)</small>
* [APT17](/groups/G0025) <small style="color:#929393">(v1.1)</small>
* [APT30](/groups/G0013) <small style="color:#929393">(v1.1)</small>
* [APT37](/groups/G0067) <small style="color:#929393">(v2.0)</small>
* [Aoqin Dragon](/groups/G1007) <small style="color:#929393">(v1.0)</small>
* [Axiom](/groups/G0001) <small style="color:#929393">(v2.0)</small>
* [BRONZE BUTLER](/groups/G0060) <small style="color:#929393">(v1.3)</small>
* [BackdoorDiplomacy](/groups/G0135) <small style="color:#929393">(v1.0)</small>
* [BlackOasis](/groups/G0063) <small style="color:#929393">(v1.0)</small>
* [BlackTech](/groups/G0098) <small style="color:#929393">(v2.0)</small>
* [Carbanak](/groups/G0008) <small style="color:#929393">(v2.0)</small>
* [Cleaver](/groups/G0003) <small style="color:#929393">(v1.3)</small>
* [Cobalt Group](/groups/G0080) <small style="color:#929393">(v2.1)</small>
* [Confucius](/groups/G0142) <small style="color:#929393">(v1.1)</small>
* [CopyKittens](/groups/G0052) <small style="color:#929393">(v1.6)</small>
* [DarkHydrus](/groups/G0079) <small style="color:#929393">(v1.3)</small>
* [DarkVishnya](/groups/G0105) <small style="color:#929393">(v1.1)</small>
* [Deep Panda](/groups/G0009) <small style="color:#929393">(v1.2)</small>
* [DragonOK](/groups/G0017) <small style="color:#929393">(v1.0)</small>
* [EXOTIC LILY](/groups/G1011) <small style="color:#929393">(v1.0)</small>
* [Elderwood](/groups/G0066) <small style="color:#929393">(v1.3)</small>
* [Equation](/groups/G0020) <small style="color:#929393">(v1.2)</small>
* [Evilnum](/groups/G0120) <small style="color:#929393">(v1.0)</small>
* [FIN10](/groups/G0051) <small style="color:#929393">(v1.3)</small>
* [FIN4](/groups/G0085) <small style="color:#929393">(v1.2)</small>
* [FIN5](/groups/G0053) <small style="color:#929393">(v1.2)</small>
* [FIN6](/groups/G0037) <small style="color:#929393">(v4.0)</small>
* [FIN8](/groups/G0061) <small style="color:#929393">(v2.0)</small>
* [Ferocious Kitten](/groups/G0137) <small style="color:#929393">(v1.0)</small>
* [GCMAN](/groups/G0036) <small style="color:#929393">(v1.1)</small>
* [GOLD SOUTHFIELD](/groups/G0115) <small style="color:#929393">(v2.0)</small>
* [Gallmaker](/groups/G0084) <small style="color:#929393">(v1.1)</small>
* [Gorgon Group](/groups/G0078) <small style="color:#929393">(v1.5)</small>
* [IndigoZebra](/groups/G0136) <small style="color:#929393">(v1.0)</small>
* [LazyScripter](/groups/G0140) <small style="color:#929393">(v1.1)</small>
* [Leafminer](/groups/G0077) <small style="color:#929393">(v2.4)</small>
* [LuminousMoth](/groups/G1014) <small style="color:#929393">(v1.0)</small>
* [Machete](/groups/G0095) <small style="color:#929393">(v2.0)</small>
* [Magic Hound](/groups/G0059) <small style="color:#929393">(v6.1)</small>
* [Moafee](/groups/G0002) <small style="color:#929393">(v1.1)</small>
* [Molerats](/groups/G0021) <small style="color:#929393">(v2.1)</small>
* [MoustachedBouncer](/groups/G1019) <small style="color:#929393">(v1.0)</small>
* [Mustang Panda](/groups/G0129) <small style="color:#929393">(v2.1)</small>
* [NEODYMIUM](/groups/G0055) <small style="color:#929393">(v1.0)</small>
* [Naikon](/groups/G0019) <small style="color:#929393">(v2.0)</small>
* [Nomadic Octopus](/groups/G0133) <small style="color:#929393">(v1.0)</small>
* [PLATINUM](/groups/G0068) <small style="color:#929393">(v1.3)</small>
* [Patchwork](/groups/G0040) <small style="color:#929393">(v1.5)</small>
* [PittyTiger](/groups/G0011) <small style="color:#929393">(v1.2)</small>
* [Poseidon Group](/groups/G0033) <small style="color:#929393">(v1.1)</small>
* [Putter Panda](/groups/G0024) <small style="color:#929393">(v1.2)</small>
* [RTM](/groups/G0048) <small style="color:#929393">(v1.1)</small>
* [Rocke](/groups/G0106) <small style="color:#929393">(v1.0)</small>
* [Scarlet Mimic](/groups/G0029) <small style="color:#929393">(v1.2)</small>
* [SideCopy](/groups/G1008) <small style="color:#929393">(v1.0)</small>
* [Silence](/groups/G0091) <small style="color:#929393">(v2.2)</small>
* [Silent Librarian](/groups/G0122) <small style="color:#929393">(v1.0)</small>
* [Sowbug](/groups/G0054) <small style="color:#929393">(v1.1)</small>
* [Stealth Falcon](/groups/G0038) <small style="color:#929393">(v1.2)</small>
* [Strider](/groups/G0041) <small style="color:#929393">(v1.1)</small>
* [Suckfly](/groups/G0039) <small style="color:#929393">(v1.1)</small>
* [TA459](/groups/G0062) <small style="color:#929393">(v1.1)</small>
* [TA551](/groups/G0127) <small style="color:#929393">(v1.2)</small>
* [The White Company](/groups/G0089) <small style="color:#929393">(v1.1)</small>
* [Threat Group-1314](/groups/G0028) <small style="color:#929393">(v1.1)</small>
* [Thrip](/groups/G0076) <small style="color:#929393">(v1.2)</small>
* [Tonto Team](/groups/G0131) <small style="color:#929393">(v1.1)</small>
* [Volatile Cedar](/groups/G0123) <small style="color:#929393">(v1.1)</small>
* [WIRTE](/groups/G0090) <small style="color:#929393">(v2.0)</small>
* [Windigo](/groups/G0124) <small style="color:#929393">(v1.0)</small>
* [Windshift](/groups/G0112) <small style="color:#929393">(v1.1)</small>
* [Winnti Group](/groups/G0044) <small style="color:#929393">(v1.2)</small>
* [Wizard Spider](/groups/G0102) <small style="color:#929393">(v4.0)</small>
* [admin@338](/groups/G0018) <small style="color:#929393">(v1.2)</small>
* [menuPass](/groups/G0045) <small style="color:#929393">(v3.0)</small>

### Mobile

#### New Groups

* [APT41](/groups/G0096) <small style="color:#eb6635">(v4.1)</small>
* [LAPSUS$](/groups/G1004) <small style="color:#eb6635">(v2.1)</small>

#### Minor Version Changes

* [APT28](/groups/G0007) <small style="color:#929393">(v5.1&#8594;v5.2)</small>
* [Sandworm Team](/groups/G0034) <small style="color:#929393">(v4.1&#8594;v4.2)</small>

#### Patches

* [APT-C-23](/groups/G1028) <small style="color:#929393">(v1.0)</small>
* [Bouncing Golf](/groups/G0097) <small style="color:#929393">(v1.0)</small>
* [Confucius](/groups/G0142) <small style="color:#929393">(v1.1)</small>
* [MoustachedBouncer](/groups/G1019) <small style="color:#929393">(v1.0)</small>
* [Windshift](/groups/G0112) <small style="color:#929393">(v1.1)</small>

### ICS

#### Major Version Changes

* [OilRig](/groups/G0049) <small style="color:#929393">(v4.1&#8594;v5.0)</small>

#### Minor Version Changes

* [APT38](/groups/G0082) <small style="color:#929393">(v3.0&#8594;v3.1)</small>
* [Lazarus Group](/groups/G0032) <small style="color:#929393">(v4.0&#8594;v4.1)</small>
* [Sandworm Team](/groups/G0034) <small style="color:#929393">(v4.1&#8594;v4.2)</small>

#### Patches

* [ALLANITE](/groups/G1000) <small style="color:#929393">(v1.0)</small>
* [FIN6](/groups/G0037) <small style="color:#929393">(v4.0)</small>
* [GOLD SOUTHFIELD](/groups/G0115) <small style="color:#929393">(v2.0)</small>
* [Wizard Spider](/groups/G0102) <small style="color:#929393">(v4.0)</small>

## Campaigns

### Enterprise

#### New Campaigns

* [APT28 Nearest Neighbor Campaign](/campaigns/C0051) <small style="color:#929393">(v1.0)</small>
* [ArcaneDoor](/campaigns/C0046) <small style="color:#929393">(v1.0)</small>
* [FLORAHOX Activity](/campaigns/C0053) <small style="color:#929393">(v1.0)</small>
* [FrostyGoop Incident](/campaigns/C0041) <small style="color:#929393">(v1.0)</small>
* [Indian Critical Infrastructure Intrusions](/campaigns/C0043) <small style="color:#929393">(v1.0)</small>
* [J-magic Campaign](/campaigns/C0050) <small style="color:#929393">(v1.0)</small>
* [Juicy Mix](/campaigns/C0044) <small style="color:#929393">(v1.0)</small>
* [Leviathan Australian Intrusions](/campaigns/C0049) <small style="color:#929393">(v1.0)</small>
* [Operation MidnightEclipse](/campaigns/C0048) <small style="color:#929393">(v1.0)</small>
* [Outer Space](/campaigns/C0042) <small style="color:#929393">(v1.0)</small>
* [RedDelta Modified PlugX Infection Chain Operations](/campaigns/C0047) <small style="color:#929393">(v1.0)</small>
* [SPACEHOP Activity](/campaigns/C0052) <small style="color:#929393">(v1.0)</small>
* [ShadowRay](/campaigns/C0045) <small style="color:#929393">(v1.0)</small>

#### Patches

* [2015 Ukraine Electric Power Attack](/campaigns/C0028) <small style="color:#929393">(v1.0)</small>
* [2016 Ukraine Electric Power Attack](/campaigns/C0025) <small style="color:#929393">(v1.0)</small>
* [C0010](/campaigns/C0010) <small style="color:#929393">(v1.0)</small>
* [C0011](/campaigns/C0011) <small style="color:#929393">(v1.0)</small>
* [C0015](/campaigns/C0015) <small style="color:#929393">(v1.0)</small>
* [C0017](/campaigns/C0017) <small style="color:#929393">(v1.0)</small>
* [C0018](/campaigns/C0018) <small style="color:#929393">(v1.0)</small>
* [C0021](/campaigns/C0021) <small style="color:#929393">(v1.0)</small>
* [C0027](/campaigns/C0027) <small style="color:#929393">(v1.0)</small>
* [CostaRicto](/campaigns/C0004) <small style="color:#929393">(v1.0)</small>
* [Frankenstein](/campaigns/C0001) <small style="color:#929393">(v1.1)</small>
* [FunnyDream](/campaigns/C0007) <small style="color:#929393">(v1.0)</small>
* [Operation CuckooBees](/campaigns/C0012) <small style="color:#929393">(v1.1)</small>
* [Operation Ghost](/campaigns/C0023) <small style="color:#929393">(v1.0)</small>
* [Operation Sharpshooter](/campaigns/C0013) <small style="color:#929393">(v1.0)</small>
* [Operation Wocao](/campaigns/C0014) <small style="color:#929393">(v1.1)</small>
* [Triton Safety Instrumented System Attack](/campaigns/C0030) <small style="color:#929393">(v1.0)</small>

### Mobile

#### New Campaigns

* [Operation Triangulation](/campaigns/C0054) <small style="color:#929393">(v1.0)</small>

### ICS

#### New Campaigns

* [FrostyGoop Incident](/campaigns/C0041) <small style="color:#929393">(v1.0)</small>

#### Patches

* [2015 Ukraine Electric Power Attack](/campaigns/C0028) <small style="color:#929393">(v1.0)</small>
* [2016 Ukraine Electric Power Attack](/campaigns/C0025) <small style="color:#929393">(v1.0)</small>
* [Maroochy Water Breach](/campaigns/C0020) <small style="color:#929393">(v1.0)</small>
* [Triton Safety Instrumented System Attack](/campaigns/C0030) <small style="color:#929393">(v1.0)</small>

## Mitigations

### Enterprise

#### Minor Version Changes

* [Account Use Policies](/mitigations/M1036) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Antivirus/Antimalware](/mitigations/M1049) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Application Developer Guidance](/mitigations/M1013) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Application Isolation and Sandboxing](/mitigations/M1048) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Audit](/mitigations/M1047) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
* [Behavior Prevention on Endpoint](/mitigations/M1040) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Boot Integrity](/mitigations/M1046) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Code Signing](/mitigations/M1045) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Credential Access Protection](/mitigations/M1043) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Data Backup](/mitigations/M1053) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Data Loss Prevention](/mitigations/M1057) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Disable or Remove Feature or Program](/mitigations/M1042) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Do Not Mitigate](/mitigations/M1055) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Encrypt Sensitive Information](/mitigations/M1041) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Environment Variable Permissions](/mitigations/M1039) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Execution Prevention](/mitigations/M1038) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
* [Exploit Protection](/mitigations/M1050) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Filter Network Traffic](/mitigations/M1037) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Limit Access to Resource Over Network](/mitigations/M1035) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Limit Hardware Installation](/mitigations/M1034) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Limit Software Installation](/mitigations/M1033) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Multi-factor Authentication](/mitigations/M1032) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Network Segmentation](/mitigations/M1030) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Operating System Configuration](/mitigations/M1028) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
* [Password Policies](/mitigations/M1027) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Pre-compromise](/mitigations/M1056) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Privileged Account Management](/mitigations/M1026) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Privileged Process Integrity](/mitigations/M1025) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Remote Data Storage](/mitigations/M1029) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Restrict File and Directory Permissions](/mitigations/M1022) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Restrict Library Loading](/mitigations/M1044) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Restrict Registry Permissions](/mitigations/M1024) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Restrict Web-Based Content](/mitigations/M1021) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [SSL/TLS Inspection](/mitigations/M1020) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Software Configuration](/mitigations/M1054) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
* [Threat Intelligence Program](/mitigations/M1019) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Update Software](/mitigations/M1051) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [User Account Control](/mitigations/M1052) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [User Account Management](/mitigations/M1018) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [User Training](/mitigations/M1017) <small style="color:#929393">(v1.2&#8594;v1.3)</small>
* [Vulnerability Scanning](/mitigations/M1016) <small style="color:#929393">(v1.1&#8594;v1.2)</small>

#### Patches

* [Active Directory Configuration](/mitigations/M1015) <small style="color:#929393">(v1.2)</small>

### Mobile

#### Minor Version Changes

* [Application Developer Guidance](/mitigations/M1013) <small style="color:#929393">(v1.1&#8594;v1.2)</small>

#### Patches

* [Antivirus/Antimalware](/mitigations/M1058) <small style="color:#929393">(v1.0)</small>
* [Attestation](/mitigations/M1002) <small style="color:#929393">(v1.0)</small>
* [Deploy Compromised Device Detection Method](/mitigations/M1010) <small style="color:#929393">(v1.0)</small>
* [Encrypt Network Traffic](/mitigations/M1009) <small style="color:#929393">(v1.0)</small>
* [Enterprise Policy](/mitigations/M1012) <small style="color:#929393">(v1.0)</small>
* [Interconnection Filtering](/mitigations/M1014) <small style="color:#929393">(v1.0)</small>
* [Lock Bootloader](/mitigations/M1003) <small style="color:#929393">(v1.0)</small>
* [Security Updates](/mitigations/M1001) <small style="color:#929393">(v1.0)</small>
* [System Partition Integrity](/mitigations/M1004) <small style="color:#929393">(v1.0)</small>
* [Use Recent OS Version](/mitigations/M1006) <small style="color:#929393">(v1.0)</small>
* [User Guidance](/mitigations/M1011) <small style="color:#929393">(v1.0)</small>

### ICS

#### Patches

* [Access Management](/mitigations/M0801) <small style="color:#929393">(v1.0)</small>
* [Account Use Policies](/mitigations/M0936) <small style="color:#929393">(v1.0)</small>
* [Active Directory Configuration](/mitigations/M0915) <small style="color:#929393">(v1.0)</small>
* [Antivirus/Antimalware](/mitigations/M0949) <small style="color:#929393">(v1.0)</small>
* [Application Developer Guidance](/mitigations/M0913) <small style="color:#929393">(v1.0)</small>
* [Application Isolation and Sandboxing](/mitigations/M0948) <small style="color:#929393">(v1.0)</small>
* [Audit](/mitigations/M0947) <small style="color:#929393">(v1.0)</small>
* [Boot Integrity](/mitigations/M0946) <small style="color:#929393">(v1.0)</small>
* [Code Signing](/mitigations/M0945) <small style="color:#929393">(v1.0)</small>
* [Communication Authenticity](/mitigations/M0802) <small style="color:#929393">(v1.0)</small>
* [Data Backup](/mitigations/M0953) <small style="color:#929393">(v1.0)</small>
* [Data Loss Prevention](/mitigations/M0803) <small style="color:#929393">(v1.0)</small>
* [Disable or Remove Feature or Program](/mitigations/M0942) <small style="color:#929393">(v1.0)</small>
* [Encrypt Network Traffic](/mitigations/M0808) <small style="color:#929393">(v1.0)</small>
* [Encrypt Sensitive Information](/mitigations/M0941) <small style="color:#929393">(v1.0)</small>
* [Execution Prevention](/mitigations/M0938) <small style="color:#929393">(v1.0)</small>
* [Exploit Protection](/mitigations/M0950) <small style="color:#929393">(v1.0)</small>
* [Filter Network Traffic](/mitigations/M0937) <small style="color:#929393">(v1.0)</small>
* [Limit Access to Resource Over Network](/mitigations/M0935) <small style="color:#929393">(v1.0)</small>
* [Limit Hardware Installation](/mitigations/M0934) <small style="color:#929393">(v1.0)</small>
* [Mechanical Protection Layers](/mitigations/M0805) <small style="color:#929393">(v1.0)</small>
* [Minimize Wireless Signal Propagation](/mitigations/M0806) <small style="color:#929393">(v1.0)</small>
* [Mitigation Limited or Not Effective](/mitigations/M0816) <small style="color:#929393">(v1.0)</small>
* [Multi-factor Authentication](/mitigations/M0932) <small style="color:#929393">(v1.0)</small>
* [Network Allowlists](/mitigations/M0807) <small style="color:#929393">(v1.0)</small>
* [Network Intrusion Prevention](/mitigations/M0931) <small style="color:#929393">(v1.0)</small>
* [Network Segmentation](/mitigations/M0930) <small style="color:#929393">(v1.0)</small>
* [Operating System Configuration](/mitigations/M0928) <small style="color:#929393">(v1.0)</small>
* [Operational Information Confidentiality](/mitigations/M0809) <small style="color:#929393">(v1.0)</small>
* [Out-of-Band Communications Channel](/mitigations/M0810) <small style="color:#929393">(v1.0)</small>
* [Password Policies](/mitigations/M0927) <small style="color:#929393">(v1.0)</small>
* [Privileged Account Management](/mitigations/M0926) <small style="color:#929393">(v1.0)</small>
* [Redundancy of Service](/mitigations/M0811) <small style="color:#929393">(v1.0)</small>
* [Restrict File and Directory Permissions](/mitigations/M0922) <small style="color:#929393">(v1.0)</small>
* [Restrict Library Loading](/mitigations/M0944) <small style="color:#929393">(v1.0)</small>
* [Restrict Registry Permissions](/mitigations/M0924) <small style="color:#929393">(v1.0)</small>
* [Restrict Web-Based Content](/mitigations/M0921) <small style="color:#929393">(v1.0)</small>
* [SSL/TLS Inspection](/mitigations/M0920) <small style="color:#929393">(v1.0)</small>
* [Safety Instrumented Systems](/mitigations/M0812) <small style="color:#929393">(v1.0)</small>
* [Software Configuration](/mitigations/M0954) <small style="color:#929393">(v1.0)</small>
* [Static Network Configuration](/mitigations/M0814) <small style="color:#929393">(v1.1)</small>
* [Supply Chain Management](/mitigations/M0817) <small style="color:#929393">(v1.0)</small>
* [Threat Intelligence Program](/mitigations/M0919) <small style="color:#929393">(v1.0)</small>
* [Update Software](/mitigations/M0951) <small style="color:#929393">(v1.0)</small>
* [User Account Management](/mitigations/M0918) <small style="color:#929393">(v1.0)</small>
* [User Training](/mitigations/M0917) <small style="color:#929393">(v1.0)</small>
* [Validate Program Inputs](/mitigations/M0818) <small style="color:#929393">(v1.0)</small>
* [Vulnerability Scanning](/mitigations/M0916) <small style="color:#929393">(v1.0)</small>
* [Watchdog Timers](/mitigations/M0815) <small style="color:#929393">(v1.0)</small>

## Data Sources

### Enterprise

#### Minor Version Changes

* [Application Log](/datasources/DS0015) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Command](/datasources/DS0017) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [File](/datasources/DS0022) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Firewall](/datasources/DS0018) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Logon Session](/datasources/DS0028) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Network Traffic](/datasources/DS0029) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Process](/datasources/DS0009) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Scheduled Job](/datasources/DS0003) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Script](/datasources/DS0012) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Service](/datasources/DS0019) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [User Account](/datasources/DS0002) <small style="color:#929393">(v1.1&#8594;v1.2)</small>

#### Patches

* [Active Directory](/datasources/DS0026) <small style="color:#929393">(v1.0)</small>
* [Certificate](/datasources/DS0037) <small style="color:#929393">(v1.0)</small>
* [Cloud Service](/datasources/DS0025) <small style="color:#929393">(v1.0)</small>
* [Cloud Storage](/datasources/DS0010) <small style="color:#929393">(v1.0)</small>
* [Container](/datasources/DS0032) <small style="color:#929393">(v1.0)</small>
* [Domain Name](/datasources/DS0038) <small style="color:#929393">(v1.0)</small>
* [Drive](/datasources/DS0016) <small style="color:#929393">(v1.0)</small>
* [Driver](/datasources/DS0027) <small style="color:#929393">(v1.0)</small>
* [Firmware](/datasources/DS0001) <small style="color:#929393">(v1.0)</small>
* [Group](/datasources/DS0036) <small style="color:#929393">(v1.0)</small>
* [Image](/datasources/DS0007) <small style="color:#929393">(v1.0)</small>
* [Instance](/datasources/DS0030) <small style="color:#929393">(v1.0)</small>
* [Internet Scan](/datasources/DS0035) <small style="color:#929393">(v1.0)</small>
* [Kernel](/datasources/DS0008) <small style="color:#929393">(v1.0)</small>
* [Malware Repository](/datasources/DS0004) <small style="color:#929393">(v1.1)</small>
* [Module](/datasources/DS0011) <small style="color:#929393">(v1.0)</small>
* [Named Pipe](/datasources/DS0023) <small style="color:#929393">(v1.0)</small>
* [Network Share](/datasources/DS0033) <small style="color:#929393">(v1.0)</small>
* [Persona](/datasources/DS0021) <small style="color:#929393">(v1.0)</small>
* [Pod](/datasources/DS0014) <small style="color:#929393">(v1.0)</small>
* [Sensor Health](/datasources/DS0013) <small style="color:#929393">(v1.1)</small>
* [Snapshot](/datasources/DS0020) <small style="color:#929393">(v1.0)</small>
* [Volume](/datasources/DS0034) <small style="color:#929393">(v1.0)</small>
* [WMI](/datasources/DS0005) <small style="color:#929393">(v1.0)</small>
* [Web Credential](/datasources/DS0006) <small style="color:#929393">(v1.0)</small>
* [Windows Registry](/datasources/DS0024) <small style="color:#929393">(v1.0)</small>

### Mobile

#### Minor Version Changes

* [Command](/datasources/DS0017) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Network Traffic](/datasources/DS0029) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Process](/datasources/DS0009) <small style="color:#929393">(v1.1&#8594;v1.2)</small>

#### Patches

* [Application Vetting](/datasources/DS0041) <small style="color:#929393">(v1.0)</small>
* [Sensor Health](/datasources/DS0013) <small style="color:#929393">(v1.1)</small>
* [User Interface](/datasources/DS0042) <small style="color:#929393">(v1.0)</small>

### ICS

#### Minor Version Changes

* [Application Log](/datasources/DS0015) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Command](/datasources/DS0017) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [File](/datasources/DS0022) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Logon Session](/datasources/DS0028) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Network Traffic](/datasources/DS0029) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Process](/datasources/DS0009) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Scheduled Job](/datasources/DS0003) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Script](/datasources/DS0012) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Service](/datasources/DS0019) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [User Account](/datasources/DS0002) <small style="color:#929393">(v1.1&#8594;v1.2)</small>

#### Patches

* [Asset](/datasources/DS0039) <small style="color:#929393">(v1.0)</small>
* [Drive](/datasources/DS0016) <small style="color:#929393">(v1.0)</small>
* [Firmware](/datasources/DS0001) <small style="color:#929393">(v1.0)</small>
* [Module](/datasources/DS0011) <small style="color:#929393">(v1.0)</small>
* [Network Share](/datasources/DS0033) <small style="color:#929393">(v1.0)</small>
* [Operational Databases](/datasources/DS0040) <small style="color:#929393">(v1.0)</small>
* [Windows Registry](/datasources/DS0024) <small style="color:#929393">(v1.0)</small>

## Data Components

### Enterprise

#### Minor Version Changes

* [Active DNS](/datasources/DS0038/#Active%20DNS) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Active Directory Credential Request](/datasources/DS0026/#Active%20Directory%20Credential%20Request) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Active Directory Object Access](/datasources/DS0026/#Active%20Directory%20Object%20Access) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Active Directory Object Creation](/datasources/DS0026/#Active%20Directory%20Object%20Creation) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Active Directory Object Deletion](/datasources/DS0026/#Active%20Directory%20Object%20Deletion) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Active Directory Object Modification](/datasources/DS0026/#Active%20Directory%20Object%20Modification) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Application Log Content](/datasources/DS0015/#Application%20Log%20Content) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Certificate Registration](/datasources/DS0037/#Certificate%20Registration) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Cloud Service Disable](/datasources/DS0025/#Cloud%20Service%20Disable) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Cloud Service Enumeration](/datasources/DS0025/#Cloud%20Service%20Enumeration) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Cloud Service Metadata](/datasources/DS0025/#Cloud%20Service%20Metadata) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Cloud Service Modification](/datasources/DS0025/#Cloud%20Service%20Modification) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Cloud Storage Access](/datasources/DS0010/#Cloud%20Storage%20Access) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Cloud Storage Creation](/datasources/DS0010/#Cloud%20Storage%20Creation) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Cloud Storage Deletion](/datasources/DS0010/#Cloud%20Storage%20Deletion) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Cloud Storage Enumeration](/datasources/DS0010/#Cloud%20Storage%20Enumeration) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Cloud Storage Metadata](/datasources/DS0010/#Cloud%20Storage%20Metadata) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Cloud Storage Modification](/datasources/DS0010/#Cloud%20Storage%20Modification) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Command Execution](/datasources/DS0017/#Command%20Execution) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Container Creation](/datasources/DS0032/#Container%20Creation) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Container Enumeration](/datasources/DS0032/#Container%20Enumeration) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Container Start](/datasources/DS0032/#Container%20Start) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Domain Registration](/datasources/DS0038/#Domain%20Registration) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Drive Access](/datasources/DS0016/#Drive%20Access) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Drive Creation](/datasources/DS0016/#Drive%20Creation) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Drive Modification](/datasources/DS0016/#Drive%20Modification) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Driver Load](/datasources/DS0027/#Driver%20Load) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Driver Metadata](/datasources/DS0027/#Driver%20Metadata) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [File Access](/datasources/DS0022/#File%20Access) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [File Creation](/datasources/DS0022/#File%20Creation) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [File Deletion](/datasources/DS0022/#File%20Deletion) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [File Metadata](/datasources/DS0022/#File%20Metadata) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [File Modification](/datasources/DS0022/#File%20Modification) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Firewall Disable](/datasources/DS0018/#Firewall%20Disable) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Firewall Enumeration](/datasources/DS0018/#Firewall%20Enumeration) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Firewall Metadata](/datasources/DS0018/#Firewall%20Metadata) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Firewall Rule Modification](/datasources/DS0018/#Firewall%20Rule%20Modification) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Firmware Modification](/datasources/DS0001/#Firmware%20Modification) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Group Enumeration](/datasources/DS0036/#Group%20Enumeration) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Group Metadata](/datasources/DS0036/#Group%20Metadata) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Group Modification](/datasources/DS0036/#Group%20Modification) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Image Creation](/datasources/DS0007/#Image%20Creation) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Image Deletion](/datasources/DS0007/#Image%20Deletion) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Image Metadata](/datasources/DS0007/#Image%20Metadata) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Instance Creation](/datasources/DS0030/#Instance%20Creation) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Instance Deletion](/datasources/DS0030/#Instance%20Deletion) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Instance Enumeration](/datasources/DS0030/#Instance%20Enumeration) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Instance Modification](/datasources/DS0030/#Instance%20Modification) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Instance Start](/datasources/DS0030/#Instance%20Start) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Instance Stop](/datasources/DS0030/#Instance%20Stop) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Kernel Module Load](/datasources/DS0008/#Kernel%20Module%20Load) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Logon Session Creation](/datasources/DS0028/#Logon%20Session%20Creation) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Malware Content](/datasources/DS0004/#Malware%20Content) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Module Load](/datasources/DS0011/#Module%20Load) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Named Pipe Metadata](/datasources/DS0023/#Named%20Pipe%20Metadata) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Network Connection Creation](/datasources/DS0029/#Network%20Connection%20Creation) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Network Share Access](/datasources/DS0033/#Network%20Share%20Access) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Network Traffic Content](/datasources/DS0029/#Network%20Traffic%20Content) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Network Traffic Flow](/datasources/DS0029/#Network%20Traffic%20Flow) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [OS API Execution](/datasources/DS0009/#OS%20API%20Execution) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Passive DNS](/datasources/DS0038/#Passive%20DNS) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Pod Creation](/datasources/DS0014/#Pod%20Creation) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Pod Enumeration](/datasources/DS0014/#Pod%20Enumeration) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Pod Modification](/datasources/DS0014/#Pod%20Modification) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Process Access](/datasources/DS0009/#Process%20Access) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Process Creation](/datasources/DS0009/#Process%20Creation) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Process Modification](/datasources/DS0009/#Process%20Modification) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Process Termination](/datasources/DS0009/#Process%20Termination) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Response Content](/datasources/DS0035/#Response%20Content) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Response Metadata](/datasources/DS0035/#Response%20Metadata) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Scheduled Job Creation](/datasources/DS0003/#Scheduled%20Job%20Creation) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Script Execution](/datasources/DS0012/#Script%20Execution) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Service Creation](/datasources/DS0019/#Service%20Creation) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Service Modification](/datasources/DS0019/#Service%20Modification) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Snapshot Creation](/datasources/DS0020/#Snapshot%20Creation) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Snapshot Deletion](/datasources/DS0020/#Snapshot%20Deletion) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Snapshot Enumeration](/datasources/DS0020/#Snapshot%20Enumeration) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Snapshot Modification](/datasources/DS0020/#Snapshot%20Modification) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Social Media](/datasources/DS0021/#Social%20Media) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [User Account Authentication](/datasources/DS0002/#User%20Account%20Authentication) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [User Account Creation](/datasources/DS0002/#User%20Account%20Creation) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [User Account Deletion](/datasources/DS0002/#User%20Account%20Deletion) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [User Account Modification](/datasources/DS0002/#User%20Account%20Modification) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Volume Creation](/datasources/DS0034/#Volume%20Creation) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Volume Deletion](/datasources/DS0034/#Volume%20Deletion) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [WMI Creation](/datasources/DS0005/#WMI%20Creation) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Windows Registry Key Access](/datasources/DS0024/#Windows%20Registry%20Key%20Access) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Windows Registry Key Creation](/datasources/DS0024/#Windows%20Registry%20Key%20Creation) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Windows Registry Key Deletion](/datasources/DS0024/#Windows%20Registry%20Key%20Deletion) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Windows Registry Key Modification](/datasources/DS0024/#Windows%20Registry%20Key%20Modification) <small style="color:#929393">(v1.0&#8594;v1.1)</small>

#### Patches

* [Host Status](/datasources/DS0013/#Host%20Status) <small style="color:#929393">(v1.1)</small>
* [Image Modification](/datasources/DS0007/#Image%20Modification) <small style="color:#929393">(v1.0)</small>
* [Instance Metadata](/datasources/DS0030/#Instance%20Metadata) <small style="color:#929393">(v1.0)</small>
* [Logon Session Metadata](/datasources/DS0028/#Logon%20Session%20Metadata) <small style="color:#929393">(v1.0)</small>
* [Malware Metadata](/datasources/DS0004/#Malware%20Metadata) <small style="color:#929393">(v1.1)</small>
* [Process Metadata](/datasources/DS0009/#Process%20Metadata) <small style="color:#929393">(v1.0)</small>
* [Scheduled Job Metadata](/datasources/DS0003/#Scheduled%20Job%20Metadata) <small style="color:#929393">(v1.0)</small>
* [Scheduled Job Modification](/datasources/DS0003/#Scheduled%20Job%20Modification) <small style="color:#929393">(v1.0)</small>
* [Service Metadata](/datasources/DS0019/#Service%20Metadata) <small style="color:#929393">(v1.0)</small>
* [Snapshot Metadata](/datasources/DS0020/#Snapshot%20Metadata) <small style="color:#929393">(v1.0)</small>
* [User Account Metadata](/datasources/DS0002/#User%20Account%20Metadata) <small style="color:#929393">(v1.0)</small>
* [Volume Enumeration](/datasources/DS0034/#Volume%20Enumeration) <small style="color:#929393">(v1.0)</small>
* [Volume Metadata](/datasources/DS0034/#Volume%20Metadata) <small style="color:#929393">(v1.0)</small>
* [Volume Modification](/datasources/DS0034/#Volume%20Modification) <small style="color:#929393">(v1.0)</small>
* [Web Credential Creation](/datasources/DS0006/#Web%20Credential%20Creation) <small style="color:#929393">(v1.0)</small>
* [Web Credential Usage](/datasources/DS0006/#Web%20Credential%20Usage) <small style="color:#929393">(v1.0)</small>

### Mobile

#### New Data Components

* [OS API Execution](/datasources/DS0009/#OS%20API%20Execution) <small style="color:#eb6635">(v1.1)</small>

#### Minor Version Changes

* [Command Execution](/datasources/DS0017/#Command%20Execution) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Network Connection Creation](/datasources/DS0029/#Network%20Connection%20Creation) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Network Traffic Content](/datasources/DS0029/#Network%20Traffic%20Content) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Network Traffic Flow](/datasources/DS0029/#Network%20Traffic%20Flow) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Process Creation](/datasources/DS0009/#Process%20Creation) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Process Termination](/datasources/DS0009/#Process%20Termination) <small style="color:#929393">(v1.0&#8594;v1.1)</small>

#### Patches

* [API Calls](/datasources/DS0041/#API%20Calls) <small style="color:#929393">(v1.0)</small>
* [Host Status](/datasources/DS0013/#Host%20Status) <small style="color:#929393">(v1.1)</small>
* [Network Communication](/datasources/DS0041/#Network%20Communication) <small style="color:#929393">(v1.0)</small>
* [Permissions Request](/datasources/DS0042/#Permissions%20Request) <small style="color:#929393">(v1.0)</small>
* [Permissions Requests](/datasources/DS0041/#Permissions%20Requests) <small style="color:#929393">(v1.0)</small>
* [Process Metadata](/datasources/DS0009/#Process%20Metadata) <small style="color:#929393">(v1.0)</small>
* [Protected Configuration](/datasources/DS0041/#Protected%20Configuration) <small style="color:#929393">(v1.0)</small>
* [System Notifications](/datasources/DS0042/#System%20Notifications) <small style="color:#929393">(v1.0)</small>
* [System Settings](/datasources/DS0042/#System%20Settings) <small style="color:#929393">(v1.0)</small>

### ICS

#### Minor Version Changes

* [Application Log Content](/datasources/DS0015/#Application%20Log%20Content) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Command Execution](/datasources/DS0017/#Command%20Execution) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Drive Creation](/datasources/DS0016/#Drive%20Creation) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Drive Modification](/datasources/DS0016/#Drive%20Modification) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [File Access](/datasources/DS0022/#File%20Access) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [File Creation](/datasources/DS0022/#File%20Creation) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [File Deletion](/datasources/DS0022/#File%20Deletion) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [File Metadata](/datasources/DS0022/#File%20Metadata) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [File Modification](/datasources/DS0022/#File%20Modification) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Firmware Modification](/datasources/DS0001/#Firmware%20Modification) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Logon Session Creation](/datasources/DS0028/#Logon%20Session%20Creation) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Module Load](/datasources/DS0011/#Module%20Load) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Network Connection Creation](/datasources/DS0029/#Network%20Connection%20Creation) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Network Share Access](/datasources/DS0033/#Network%20Share%20Access) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Network Traffic Content](/datasources/DS0029/#Network%20Traffic%20Content) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Network Traffic Flow](/datasources/DS0029/#Network%20Traffic%20Flow) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [OS API Execution](/datasources/DS0009/#OS%20API%20Execution) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Process Creation](/datasources/DS0009/#Process%20Creation) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Process Termination](/datasources/DS0009/#Process%20Termination) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Scheduled Job Creation](/datasources/DS0003/#Scheduled%20Job%20Creation) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Script Execution](/datasources/DS0012/#Script%20Execution) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Service Creation](/datasources/DS0019/#Service%20Creation) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Service Modification](/datasources/DS0019/#Service%20Modification) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [User Account Authentication](/datasources/DS0002/#User%20Account%20Authentication) <small style="color:#929393">(v1.1&#8594;v1.2)</small>
* [Windows Registry Key Deletion](/datasources/DS0024/#Windows%20Registry%20Key%20Deletion) <small style="color:#929393">(v1.0&#8594;v1.1)</small>
* [Windows Registry Key Modification](/datasources/DS0024/#Windows%20Registry%20Key%20Modification) <small style="color:#929393">(v1.0&#8594;v1.1)</small>

#### Patches

* [Asset Inventory](/datasources/DS0039/#Asset%20Inventory) <small style="color:#929393">(v1.0)</small>
* [Device Alarm](/datasources/DS0040/#Device%20Alarm) <small style="color:#929393">(v1.0)</small>
* [Logon Session Metadata](/datasources/DS0028/#Logon%20Session%20Metadata) <small style="color:#929393">(v1.0)</small>
* [Process History/Live Data](/datasources/DS0040/#Process%20History/Live%20Data) <small style="color:#929393">(v1.0)</small>
* [Process Metadata](/datasources/DS0009/#Process%20Metadata) <small style="color:#929393">(v1.0)</small>
* [Process/Event Alarm](/datasources/DS0040/#Process/Event%20Alarm) <small style="color:#929393">(v1.0)</small>
* [Scheduled Job Metadata](/datasources/DS0003/#Scheduled%20Job%20Metadata) <small style="color:#929393">(v1.0)</small>
* [Scheduled Job Modification](/datasources/DS0003/#Scheduled%20Job%20Modification) <small style="color:#929393">(v1.0)</small>
* [Service Metadata](/datasources/DS0019/#Service%20Metadata) <small style="color:#929393">(v1.0)</small>
* [Software](/datasources/DS0039/#Software) <small style="color:#929393">(v1.0)</small>

## Contributors to this release

* Aaron Sullivan aka ZerkerEOD
* Adam Lichters
* Alden Schmidt
* Ale Houspanossian
* Alexey Kleymenov
* Alon Klayman, Hunters Security
* Amnon Kushnir, Sygnia
* Ben Smith, @cyberg3cko
* Caio Silva
* Cian Heasley
* Cristian Souza - Kaspersky GERT
* Cristóbal Martínez Martín
* David Hughes, BT Security
* Dhiraj Mishra (@RandomDhiraj)
* Dmitry Bestuzhev
* Dvir Sasson, Reco
* Eliraz Levi, Hunters Security
* Fabian Kammel
* Fernando Bacchin
* Flavio Costa, Cisco
* Frank Angiolelli
* Gabriel Currie
* Gerardo Santos
* Harikrishnan Muthu, Cyble
* Hiroki Nagahama, NEC Corporation
* Inna Danilevich, U.S. Bank
* Jaesang Oh, KC7 Foundation
* Janantha Marasinghe
* Jennifer Kim Roman
* Jiraput Thamsongkrah
* Joas Antonio dos Santos, @C0d3Cr4zy
* Joe Gumke, U.S. Bank
* Jun Hirata, NEC Corporation
* Kaung Zaw Hein
* Kevin Ward
* Kori Yoshihiro, NEC Corporation
* Kyaw Pyiyt Htet, @KyawPyiytHtet
* Liran Ravich, CardinalOps
* Lê Phương Nam, Group-IB
* Manikantan Srinivasan, NEC Corporation India
* Matt Anderson, @‌nosecurething, Huntress
* Matt Brenton, Zurich Global Information Security
* Matt Brenton, Zurich Insurance Group
* Menachem Goldstein
* Michael Davis @ ServiceNow Threat Intelligence
* MyungUk Han, ASEC
* Natthawut Saexu
* Nikita Rostovcev, Group-IB
* Oren Biderman, Sygnia
* Peter Oakes
* Pooja Natarajan, NEC Corporation India
* Raghvendra Mishra
* ReliaQuest
* RoseSecurity
* Rouven Bissinger (SySS GmbH)
* Ruben Groenewoud (@RFGroenewoud)
* Ryan Perez
* Sareena Karapoola, NEC Corporation India
* seungyoul.yoo@ahnlab.com
* Sharmine Low, Group-IB
* Shun Miyazaki, NEC Corporation
* Shwetank Murarka
* Sittikorn Sangrattanapitak
* Suraj Khetani (@r00treaver)
* Vicky Ray, RayvenX
* Vijay Lalwani
* Wietze Beukema @Wietze
* Yoshihiro Kori, NEC Corporation
