# Alert configuration

Each query was saved as a scheduled alert (Save As > Alert). Settings as configured:

| Alert | Cron schedule | Time range | Trigger condition | Throttle | Action | Severity |
|---|---|---|---|---|---|---|
| Query 1: Detect Brute Force Login | `*/5 * * * *` | Last 15 minutes | Number of results > 0 | 60 min | Send email + Add to Triggered Alerts | Medium |
| Query 2: Detect Account Compromise | `*/10 * * * *` | All time | Number of results > 0 | 60 min | Add to Triggered Alerts | High |
| Query 3: Detect Privilege Escalation | `*/15 * * * *` | All time | Number of results > 0 | 60 min | Add to Triggered Alerts | High |
| Query 4: Detect Data Exfiltration | `0 * * * *` | All time | Number of results > 0 | 60 min | Add to Triggered Alerts | High |
| Query 5: Detect New User Account Created | `*/15 * * * *` | All time | Number of results > 0 | 60 min | Add to Triggered Alerts | Low |
| Query 6: Detect Ransomware Behaviour | `*/2 * * * *` | All time | Number of results > 0 | 60 min | Add to Triggered Alerts | Critical |
| Query 7: Detect Threat Intelligence Match | `*/10 * * * *` | All time | Number of results > 0 | 60 min | Add to Triggered Alerts | High |

All alerts expire after 24 hours. Screenshots of each configuration are in [`../screenshots`](../screenshots) (files 12 to 18).
