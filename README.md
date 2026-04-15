# Splunk-Failed-Logon-Detection
Built and validated a Splunk detection for repeated Windows failed logons using Event ID 4625, 2-minute time bucketing, and alerting.


# Objective:
Detect repeated failed Windows Authentication attempts within a short time window using Splunk.

This project simulates and identifies potential brute-force or unauthorized access attempts using Windows Security Event Logs.


# Tools Used:
- Splunk Enterprise
- Windows Event Logs (.evtx)
- Windows OS (log generation)


# Data Source:
- Log Type:  Windows Security Logs
- Event ID:  4625 (Failed Logon)
- Logon Process:  User32


# Detection Logic:
This detection identifies multiple failed logon attempts occurring on the same system within a 2-minute window.

Repeated authentication failures indicate:
- Brute-force attempts
- Credential misuse
- Unauthorized access attempts


# SPL Query:
- index="detectionlab_1" EventCode="4625" Logon_Process="User32"
  | bin _time span=2m
  | stats count by ComputerName _time
  | where count >= 4


# Detection Development process:
  1. Raw event Analysis:
     - Initial investigation of Windows Event ID 4625 logs to understand structure and relevant fields.

  2. Initial Aggregation (Before Time Bucketing):
     - Events grouped only by ComputerName, resulting in a single aggregated count:
          index="detectionlab_1" EventCode="4625" Logon_Process="User32"
          | stats count by ComputerName _time q
          | where count >= 4

  3. Improved Detection (Time Bucketing Applied):
     - Events grouped into 2-minute time windows to properly detect bursts of failed logon activity.

    
# Alert Configuration:
- Name:  Multiple Failed Logons Detection
- Type:  Scheduled
- Frequency:  Hourly (lab limitation)
- Trigger Condition:  Number of results > 0
- Severity:  Medium


# Limitations:
- Windows security controls limited the number of consecutive failed login attempts during testing
- Detection uses ComputerName due to missing/empty target account field in logs
- Threshold (>= 4) is tuned for lab conditions


# Future Improvements:
- Simulate attacks using Atomic Red Team
- Expand detection to include source IP and user correlation
- Implement Sigma rule equivalent
- Tune threshold based on real-world equivalent
- Correlate with successful logon events (Event ID 4624)


# Key Takeaways:
- Developed and validated a detection using real Windows Security logs
- Implemented time-based event aggregation using Splunk
- Tuned detection thresholds based on environmental constraints
- Created a functional alert for repeated failed authentication attempts


# Final Note:
- This project is an example of designing, validating, and operationalizing a detection using Splunk and Windows event data.
