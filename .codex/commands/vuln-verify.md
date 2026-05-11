# vuln-verify

Label and submit a pending case in the makina verify queue.

## Usage

```text
vuln-verify {case_id}
```

`{case_id}` is the integer `case_no` returned by `vuln-add` or visible in the Verify tab.

## Procedure

1. Fetch the pending queue and locate `case_no == {case_id}`:

```http
GET http://localhost:7373/api/verify/queue
```

If not found, report `case #{case_id} not found in pending queue` and stop.

2. Review `findings_json` for the case. For each finding:
   - assess whether it is a true positive or false positive based on the code and reported CWE/rule,
   - default to true positive for obvious vulnerability patterns,
   - mark false positive only when the scanner clearly misfired.

3. Submit labels and case in one call:

```http
POST http://localhost:7373/api/knowledge
{
  "case_no": {case_id},
  "labels": {
    "<finding_id_1>": "tp",
    "<finding_id_2>": "fp"
  }
}
```

4. Report:
   - submitted `case_no`,
   - per-finding label summary,
   - confirmation that retrain was triggered.

## Output Shape

```text
Submitted case #42
findings: 3 tp, 0 fp
retrain: triggered
```
