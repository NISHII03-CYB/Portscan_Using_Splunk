# Portscan_Using_Splunk

DETECTION OF PORT SCANNING (Using SPLUNK)


Name : Dehiwattage Kavindu Nishitha Fernando

Role : SOC Analyst (Lab Project)

Date : 16/02/2026


This project demonstrates detection engineering of network reconnaissance activity using Splunk SIEM. Port scanning traffic was generated using Nmap, and Windows Security logs (Event ID 5156) were collected and analyzed. A time-window correlation rule was developed to detect abnormal connection attempts across multiple ports. The project replicates a Tier 1 SOC monitoring workflow.

________________________________________

Project Objective


The objective of this project was to:

•	Enable network connection auditing in Windows

•	Generate port scanning activity in a lab environment

•	Ingest logs into Splunk SIEM

•	Develop correlation-based detection logic

•	Configure automated alerting

________________________________________

Environment Setup

Component	Description

SIEM Platform	Splunk Enterprise

Operating System	Windows

Log Source	Windows Security Logs (Event ID 5156)

Scanning Tool	Nmap

Index	windows_security

________________________________________

Log Configuration

Network connection auditing was enabled using:

auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable

This ensured Windows generated Event ID 5156 logs for allowed connections.

________________________________________

Attack Simulation

Executed:

nmap -p 1-300 127.X.X.X

This generated high-volume TCP connection attempts across multiple ports.

________________________________________

Detection Engineering

*Detection Logic

/// index=windows_security EventID=5156

| bin _time span=1m

| stats dc(dest_port) as unique_ports by _time src_ip

| where unique_ports > 50 ///

*Detection Methodology

•	Grouped events into 1-minute intervals

•	Counted distinct destination ports accessed

•	Triggered detection when unique port count exceeded 50

This approach simulates reconnaissance detection in a SOC environment.

________________________________________

Findings

•	Source IP: 127.0.0.1

•	Unique Ports Contacted: 303

•	Activity significantly exceeded threshold

The behavior clearly matched port scanning activity.

________________________________________

MITRE ATT&CK Mapping

Tactic	Technique	ID

Discovery	Network Service Discovery	T1046

________________________________________

Alert Configuration

Detection was converted into a scheduled alert:

•	Run every 5 minutes

•	Time range: Last 5 minutes

•	Trigger condition: Results > 0

•	No expiration


This simulates continuous SOC monitoring operations.

________________________________________

Conclusion

This project successfully demonstrated:

•	Windows auditing configuration

•	SIEM log ingestion

•	Correlation-based detection engineering

•	Time-window aggregation analysis

•	Real-time alert implementation

The lab replicates SOC Tier 1 workflows for detecting reconnaissance behavior.

