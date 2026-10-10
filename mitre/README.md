# MITRE ATT&CK mapping

| Detection | Tactic | Techniques |
|---|---|---|
| Query 1: Brute Force Login | Credential Access | T1110.001 Password Guessing<br>T1110.003 Password Spraying |
| Query 2: Account Compromise | Initial Access, Persistence | T1078 Valid Accounts<br>T1078.002 Domain Accounts |
| Query 3: Privilege Escalation | Persistence, Privilege Escalation | T1098 Account Manipulation<br>T1098.007 Additional Local or Domain Groups |
| Query 4: Data Exfiltration | Exfiltration | T1041 Exfiltration Over C2 Channel<br>T1048 Exfiltration Over Alternative Protocol |
| Query 5: New User Account | Persistence | T1136.002 Create Account: Domain Account<br>T1136.001 Local Account |
| Query 6: Ransomware Behaviour | Impact | T1486 Data Encrypted for Impact |
| Query 7: Threat Intelligence Match | Command and Control | T1071.001 Web Protocols<br>T1090.003 Multi-hop Proxy (TOR)<br>T1571 Non-Standard Port |

## Viewing the layer

1. Open the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/).
2. Choose **Open Existing Layer > Upload from local**.
3. Select `twp_attack_layer.json`.

The covered techniques are highlighted in green on the Enterprise matrix.
