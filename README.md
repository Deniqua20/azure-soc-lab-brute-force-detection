## 📌 Notes
> This lab builds on an existing SOC lab setup. The honeypot VM and Log Analytics workspace were already configured before starting the detection work. The focus of this session was on detection rule creation, alert validation, and incident investigation.
# 🧪 Brute Force Detection Using Microsoft Sentinel – Hands-On Lab

> This lab documents how I set up a brute force detection scenario using Microsoft Sentinel and a honeypot VM in Azure.

---

## ⚙️ Lab Objectives

- Deploy a vulnerable honeypot VM
- Simulate brute force RDP login attempts
- Collect logs and analyze Event ID 4625 in Microsoft Sentinel
- Write a KQL query to detect excessive failed logins
- Create an analytic rule to trigger incidents
- Validate alerts and view incidents in Sentinel

---

## 🛠️ Lab Setup

- **SIEM**: Microsoft Sentinel  
- **VM**: Azure Windows Server honeypot  
- **Protocol simulated**: RDP (Remote Desktop Protocol)  
- **Logs**: Windows Security Logs (Event ID 4625)  
- **Rule trigger**: Failed logins from same IP/account over short time span

---

## 🔍 Simulation Process

1. **Honeypot Deployment**  
   Deployed a Windows Server VM in Azure with RDP open to the internet.

2. **Failed Login Simulation**  
   Repeatedly attempted login with invalid credentials to generate Event ID 4625 logs.

3. **Log Verification**  
   Viewed logs in Sentinel:

   ![KQL Query](images/sentinel-query.png)

   ```kql
   SecurityEvent
   | where EventID == 4625
   | sort by TimeGenerated desc
   ```

4. **Event Log Results**

   ![Failed Login Logs](images/failed-logons.png)

5. **Incident Generation**  
   Created a scheduled analytics rule to detect brute force behavior using this KQL:

   ```kql
   SecurityEvent
   | where EventID == 4625
   | summarize FailedAttempts = count() by Account, bin(TimeGenerated, 5m)
   | where FailedAttempts > 5
   ```

6. **Confirmed Triggered Incidents**

   ![Sentinel Incidents](images/sentinel-incidents.png)

   Microsoft Sentinel automatically created incidents titled **"Brute Force Logon Detection"** with a medium severity.

---

## ✅ Outcome

This project demonstrates hands-on SOC experience detecting brute force login attempts in Microsoft Sentinel using real logs, KQL, and analytic rule configuration.

---

