# vuln-add

Add a vulnerable code snippet to the makina verify queue.

## Usage

```text
vuln-add {code}
```

`{code}` is a block of vulnerable source code in a language supported by makina.

## Procedure

1. Detect language from syntax and keywords: python, javascript, typescript, java, go, ruby, c, cpp, or rust. Default to `python` only if ambiguous.
2. Validate the snippet. Reject and explain if it:
   - has fewer than 5 lines,
   - contains no recognizable vulnerability pattern,
   - has no taint source, dangerous sink, or obvious CWE,
   - is configuration-only or placeholder code.
3. Scan through the backend:

```http
POST http://localhost:7373/api/scan
{"code": "<snippet>", "language": "<lang>"}
```

4. Queue the scan result:

```http
POST http://localhost:7373/api/verify/queue
{"cve_id": null, "code": "<snippet>", "language": "<lang>", "findings": [...]}
```

5. Report:
   - assigned `case_no`,
   - detected language,
   - number of findings,
   - primary CWE or rule id.

## Output Shape

```text
Queued as case #42
language: python
findings: 3 (CWE-89 SQL Injection, CWE-78 OS Command Injection)
```
