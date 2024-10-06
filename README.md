<h1>Automatic Alert Import</h1>

- <b>This tutorial outlines the configuration of Microsoft Sentinel incidents and importing custom rule queries</b>

<h2>Environments and Technologies Used</h2>

- <b>Microsoft Azure</b> 
- <b>Microsoft Sentinel</b>
- <b>Log Analytics Workspace</b>

<h2>Operating Systems</h2>

- <b>Windows 10</b>

<h2>Configuration Steps</h2>

- <b>Download Sentinel Analytics rules from this link: https://github.com/joshmadakor1/Cyber-Course-V2/tree/main/Sentinel-Analytics-Rules</b>

![image](https://github.com/user-attachments/assets/7bb22b56-dd6a-4b65-a488-30223c905039)
- <b>Navigate to Microsoft Sentinel and click analytics</b>
- Click import and select the Sentinel Alaytics rules json file</b>

![image](https://github.com/user-attachments/assets/47d533ee-bbc5-4c14-a062-fb525c8cc99f)
- <b>Select CUSTOM: Brute Force Success - Windows and click edit</b>
- <b>Click set rule logic and copy the query:</b>
```
// Brute Force Success Windows
let FailedLogons = SecurityEvent
| where EventID == 4625 and LogonType == 3
| where TimeGenerated > ago(1h)
| summarize FailureCount = count() by AttackerIP = IpAddress, EventID, Activity, LogonType, DestinationHostName = Computer
| where FailureCount >= 5;
let SuccessfulLogons = SecurityEvent
| where EventID == 4624 and LogonType == 3
| where TimeGenerated > ago(1h)
| summarize SuccessfulCount = count() by AttackerIP = IpAddress, LogonType, DestinationHostName = Computer, AuthenticationSuccessTime = TimeGenerated;
SuccessfulLogons
| join kind = inner FailedLogons on DestinationHostName, AttackerIP, LogonType
| project AuthenticationSuccessTime, AttackerIP, DestinationHostName, FailureCount, SuccessfulCount
```

![image](https://github.com/user-attachments/assets/ef93dc88-8de2-4a38-b7f8-e9efcf019933)
- <b>Navigate to Log Analytics Workspace and observe the failed login attempts on our windows-vm</b>

![image](https://github.com/user-attachments/assets/4e961996-22c4-47c1-b792-5ab5eee1c3e2)
- <b>Microsoft Sentinel Brute Force Success - Windows incident creation</b>
