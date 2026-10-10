# TWP Global SOC Dashboard

Classic Splunk dashboard with a time range picker.

| Panel | Type | Value |
|---|---|---|
| Total Security Events | Single value | 1,028 |
| Total Network Events | Single value | 274 |
| Failed Logins | Single value | 69 |
| Privilege Escalations | Single value | 4 |
| Unique Attacking IPs | Single value | 6 |
| New Accounts | Single value | 3 |
| Security Event Timeline | Line chart | Event types over time |
| Outbound Traffic Trend | Area chart | outbound_mb over time |
| Top Attackers | Bar chart | Failed logins by source IP |
| Geographic Office Breakdown | Pie chart | Failed logins by office |
| Query 1 to Query 7 | Tables | One table per detection |

Screenshots: [`19_dashboard_overview.png`](../screenshots/19_dashboard_overview.png), [`20_dashboard_detection_tables.png`](../screenshots/20_dashboard_detection_tables.png), [`21_dashboard_threat_intel_table.png`](../screenshots/21_dashboard_threat_intel_table.png).

<!-- To add the dashboard source: in Splunk open the dashboard, click Edit > Source, copy everything, and save it in this folder as twp_global_soc_dashboard.xml -->
