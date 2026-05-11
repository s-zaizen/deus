# vuln-add-verify-with-codex

Research a CVE, extract vulnerable code, queue it, and verify it end to end.

## Usage

```text
vuln-add-verify-with-codex
vuln-add-verify-with-codex CVE-2024-XXXXX
```

If no CVE is specified, choose one that:

- has a public PoC or disclosed vulnerable code,
- has a clear taint flow from source to sink,
- is not already in the verify queue.

## Procedure

1. Check the verify queue first:

```http
GET http://localhost:7373/api/verify/queue
```

2. Research the CVE. Prefer official NVD or vendor advisory metadata plus public code from commit diffs, advisories, or reputable PoC repositories.

3. Only proceed if the code:
   - is at least 10 lines of real source,
   - shows the vulnerability in context,
   - has a clear taint source and dangerous sink.

If no suitable code is found after two search attempts, report the failure and stop.

4. Extract a self-contained snippet, preferably 20-80 lines. Keep enough context to show the vulnerable flow and remove unrelated code. Add one comment on the vulnerable line:

```text
# CVE-YYYY-NNNNN: <vulnerability type>
```

5. Run the `vuln-add` procedure on the snippet, setting `cve_id` to the CVE ID when queueing.

6. Run the `vuln-verify` procedure on the returned `case_no`.

7. Report:

```text
CVE: CVE-YYYY-NNNNN
Title: <short description>
Language: <lang>
Severity: <CVSS / HIGH / CRITICAL>
CWE: <CWE-N>
Source: <URL where code was found>

case_no: #N
findings: X tp, Y fp
retrain: triggered

Vulnerability summary:
<2-3 sentences explaining the taint flow and why the findings are TP>
```

## Constraints

- Never fabricate vulnerable code. Use only code found in public sources.
- Stop if the CVE language is not supported by makina.
- If the scanner returns zero findings, still queue and submit it as a valid training signal, then report `no scanner findings - submitted as negative example`.
