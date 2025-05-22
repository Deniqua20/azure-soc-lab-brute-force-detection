## 📌 Notes
> This lab builds on an existing SOC lab setup. The honeypot VM and Log Analytics workspace were already configured before starting the detection work. The focus of this session was on detection rule creation, alert validation, and incident investigation.

# 🧪 Brute Force Detection Using Microsoft Sentinel – Hands-On Lab

> This short lab documents my hands-on setup of a brute force detection use case using Microsoft Sentinel and a pre-configured honeypot VM.

---

## ✅ What I Did

### 1. Confirmed VM & Log Analytics Connection
- My honeypot VM was already connected to a Log Analytics workspace
- Verified the connection in **Microsoft Sentinel > Logs** using:

```kql
Heartbeat
| where TimeGenerated > ago(5m)
```

✅ The query returned results, confirming that the VM was actively sending heartbeat logs.

---

### 2. Simulated Brute Force Login Attempts
- Opened RDP session to the honeypot VM
- Entered **incorrect passwords** multiple times (5–10 attempts)
- Waited a few minutes for logs to flow into Sentinel

---

### 3. Verified Failed Logins in Sentinel
- Opened **Sentinel > Logs**
- Queried for failed login attempts using Event ID `4625`:

```kql
SecurityEvent
| where EventID == 4625
| sort by TimeGenerated desc
```

✅ The query returned failed login events, confirming that the honeypot was generating the appropriate logs.

---

### 4. Created a Custom Detection Rule in Sentinel
- Went to **Microsoft Sentinel > Analytics > + Create > Scheduled query rule**
- Entered the following details:

**Rule Name:** Brute Force Logon Detection – Honeypot  
**Tactic:** Credential Access  
**Severity:** Medium  
**Run Frequency:** Every 5 minutes  
**Lookup Period:** 10 minutes

**KQL Query Used:**

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by IPAddress = RemoteIpAddress, bin(TimeGenerated, 5m)
| where FailedAttempts > 5
```

- Saved the rule and enabled it

---

### 5. Validated the Detection
- Triggered another round of failed login attempts
- Returned to **Sentinel > Incidents**
- ✅ Verified that the rule successfully fired and created an **Incident** titled: `Brute Force Login`

---

## 🧠 Skills Practiced

- Writing KQL queries in Microsoft Sentinel
- Analyzing Windows Security Logs (Event ID 4625)
- Creating custom detection rules based on log patterns
- Simulating brute force attacks for detection testing
- Using Microsoft Sentinel’s analytics and incident features

---

