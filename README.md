# Linux Privilege Escalation and Data Exfiltration

**Incident Response Report**
**Case Title:** Linux Privilege Escalation and Data Exfiltration
**Date:** October 4, 2025
**Analyst:** Emran Hossain
**System Under Investigation:** linux-lab
**Framework Used:** NIST SP 800-61 (Computer Security Incident Handling Guide)

---

## 1. Executive Summary

Company A detected suspicious activities on a Linux server containing Personally Identifiable Information (PII) such as employee addresses, email addresses, and phone numbers. This server was intended to be accessible only to root or sudo users. Following a report of unauthorized system access, a detailed investigation was launched.

The investigation revealed the creation and execution of a malicious script (`super_secret_script.sh`) that escalated privileges, created a backdoor user, and exfiltrated sensitive data to Azure Blob Storage.

---

## 2. Incident Description

### 2.1 Initial Observation

An employee reported unusual activity on the company’s Linux workstation (`linux-lab`). The system logs indicated possible unauthorized privilege escalation and subsequent data transfer activities.

### 2.2 Scope and Impact

* **Assets Involved:** Linux server containing hidden PII files.
* **Type of Compromise:** Privilege Escalation & Data Exfiltration.
* **Potential Data Exfiltrated:** Employee PII (address, email, phone).
* **Attack Vector:** Execution of a malicious shell script by a compromised or rogue user.

---

## 3. Investigation Steps

### 3.1 Privilege Escalation Analysis

**Query executed:**

```kusto
let timeThreshold = ago(3d);
let sensitivegroup = dynamic(["sudo"]);
DeviceProcessEvents
| where DeviceName == "linux-lab"
| where Timestamp > timeThreshold
| where InitiatingProcessCommandLine contains "usermod -aG"
| where InitiatingProcessCommandLine has_any(sensitivegroup)
```

**Findings:**

* Unauthorized execution of the `usermod -aG sudo` command was detected.
* This command granted sudo privileges to a non-administrative account, later identified as `badactor`.
* This confirms privilege escalation and creation of a backdoor user.

### 3.2 Malicious Script Discovery

**Query executed:**

```kusto
DeviceFileEvents
| where DeviceName =="linux-lab"
| where ActionType =="FileCreated"
| order by Timestamp desc
```

**Findings:**

* A suspicious file named `super_secret_script.sh` was created on `2025-10-04T01:48:40.811161Z`.
* Commands used included:

  * `touch super_secret_script.sh` → File creation.
  * `nano super_secret_script.sh` → File modification and insertion of malicious code.
* The file likely contained commands to grant sudo access and initiate data exfiltration.

### 3.3 Process Execution Analysis

**Query executed:**

```kusto
DeviceProcessEvents
| where DeviceName =="linux-lab"
| where Timestamp >= datetime(2025-10-04T01:48:40.811161Z)
| project Timestamp,DeviceName,ActionType,InitiatingProcessCommandLine
| order by Timestamp desc
```

**Findings:**

* Execution logs confirmed that the script was run with elevated privileges.
* Associated process commands showed user creation (`useradd badactor`) and privilege modification (`usermod -aG sudo badactor`).

### 3.4 Data Exfiltration Analysis

**Query executed:**

```kusto
let timeThreshold = ago(3d);
DeviceNetworkEvents
| where DeviceName == "linux-lab"
| where Timestamp > timeThreshold
| where InitiatingProcessCommandLine contains "storage blob upload"
```

**Findings:**

* Logs indicate outbound connections to Microsoft Azure Blob Storage.
* This suggests data exfiltration of sensitive PII via cloud storage.
* The attacker likely leveraged command-line tools (e.g., `az storage blob upload`) to transmit the stolen data.

---

## 4. Root Cause

* **Cause:** Compromised credentials or physical access allowed the attacker to log in and execute commands with root privileges.
* **Impact:** Unauthorized user creation, privilege escalation, and potential PII leakage.
* **Key Artifact:** `super_secret_script.sh`.

---

## 5. Mitigation and Remediation

| Action                 | Description                                                                                                           |
| ---------------------- | --------------------------------------------------------------------------------------------------------------------- |
| **User Audit**         | Immediately disable and remove unauthorized account `badactor`.                                                       |
| **File Removal**       | Delete `super_secret_script.sh` and related malicious files.                                                          |
| **Access Review**      | Reset all root and sudo user passwords.                                                                               |
| **System Hardening**   | Restrict sudo access and implement multifactor authentication (MFA).                                                  |
| **Logging and Alerts** | Configure Microsoft Defender for Endpoint (MDE) to trigger alerts for `usermod`, `useradd`, and blob upload commands. |
| **Security Awareness** | Conduct employee training to prevent physical and phishing-related access compromises.                                |

---

## 6. Lessons Learned

* Insider or physical threats must be mitigated through strict access control policies.
* Regular log monitoring and proactive detection rules (like those created in this investigation) can prevent extended compromise.
* Cloud upload commands (`az storage blob upload`) should be tightly monitored and restricted to trusted service accounts only.

---

## 7. Conclusion

This investigation confirmed that a malicious actor gained unauthorized sudo privileges on a Linux system and exfiltrated sensitive data to external cloud storage. The root cause was the misuse of elevated access privileges, possibly due to weak or shared credentials. Mitigation measures and enhanced monitoring have been implemented to prevent recurrence.

---

## 8. Appendix

**Detected Artifacts:**

* `super_secret_script.sh` — Malicious shell script.
* `usermod -aG sudo badactor` — Privilege escalation command.
* `az storage blob upload` — Data exfiltration command.

**Key Timestamps:**

* **File Creation:** `2025-10-04T01:48:40.811161Z`.
* **Data Exfiltration Event:** Shortly after script execution.

---

*End of report.*
