# Data

| File | Uploaded to | Contents |
|---|---|---|
| `security_events.csv` | index `security`, sourcetype `csv` | Windows Security events (4624, 4625, 4663, 4720, 4728, 4732, 4756) |
| `network_traffic.csv` | index `network`, sourcetype `csv` | src_ip, dest_ip, dest_port, bytes_out, direction, action |
| `threat_intel_ips.csv` | Lookup table file, lookup definition `threat_intel_ips` (file-based) | ip, threat_type, severity, source |

Uploaded through Settings > Add Data > Upload (events) and Settings > Lookups (threat intel). The CSV files are not included in this repository.
