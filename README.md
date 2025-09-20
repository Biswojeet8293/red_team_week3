# red_team_week3
📖 Overview
This project documents a controlled Red Team engagement designed to test and evaluate an organization's defensive capabilities. The simulation follows the MITRE ATT&CK framework, covering all stages of the cyber kill chain, including OSINT, phishing, vulnerability exploitation, lateral movement, and exfiltration. The engagement concludes with a detailed report and analysis of detection points.

🛠️ Tools Used
Phase	Tools
Reconnaissance	Maltego, Recon-ng, Shodan
Initial Access	Gophish, Evilginx2
Vulnerability Analysis	Nmap, OWASP ZAP
Exploitation	Metasploit
Post-Exploitation	Covenant, Impacket, Mimikatz
Lateral Movement	Impacket's psexec.py
Exfiltration	dnscat2
Reporting	Google Docs, Draw.io

🔎 Engagement Phases
1. OSINT and Reconnaissance
Enumerated subdomains of example.com using Recon-ng (bing_domain_web module).

Discovered exposed Apache servers in the US using Shodan queries, identifying outdated versions vulnerable to known exploits.

2. Phishing Simulation
Cloned a legitimate login portal using Evilginx2.

Deployed a credential harvesting campaign via Gophish.

Successfully captured user credentials, including a privileged service account.

3. Vulnerability Exploitation
Scanned the target network with Nmap, identifying a host running a vulnerable Apache Struts service.

Exploited the Struts Remote Code Execution (RCE) vulnerability (CVE-2017-5638) using Metasploit to gain an initial foothold.

4. Lateral Movement & Persistence
Used Mimikatz to dump credential hashes from the compromised host.

Performed lateral movement to a critical file server using Impacket's psexec.py.

Established persistence by creating a scheduled task to execute a payload daily.

5. Social Engineering
Gathered target information (phone number, carrier, social media links) using PhoneInfoga and Maltego.

Executed a successful vishing (voice phishing) call using a crafted pretexting script.

6. Post-Exploitation & Exfiltration
Extracted additional credentials from memory using Mimikatz.

Exfiltrated simulated sensitive data from the network using DNS tunneling (dnscat2), bypassing traditional network monitoring.

7. Blue Team Analysis & Evasion
Wazuh SIEM alerts were generated for suspicious logins and persistence mechanisms.

Successfully evaded static antivirus (AV) detection by obfuscating the payload with Donut and ConfuserEx.

📊 Key Findings & Recommendations
Executive Summary
The Red Team achieved full domain compromise and exfiltrated data. The primary attack vectors were a successful phishing campaign and exploitation of an unpatched, public-facing web application. Lateral movement was facilitated by weak credential hygiene and a lack of network segmentation.

Critical Findings:
Missing Multi-Factor Authentication (MFA): Critical services lacked MFA, allowing stolen credentials to be used effectively.

Delayed Patching: External systems were not patched in a timely manner, leading to the exploitation of a known critical vulnerability (CVE-2017-5638).

Insufficient Detection Capabilities: EDR and SIEM rules did not effectively correlate events into high-fidelity incidents, allowing attackers to operate undetected for a significant period.

Top Recommendations:
Implement MFA for all remote access and privileged accounts.

Enforce a strict 30-day patch cycle for all external-facing systems.

Enhance EDR and SIEM alerting to detect common lateral movement tools (e.g., Impacket, Mimikatz) and correlate related events.

Implement network segmentation to restrict lateral movement and protect critical assets.
