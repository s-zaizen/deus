# Makina Vulnerable Code Samples

This folder contains intentionally vulnerable code for local scanner testing.

Do not deploy or reuse these files in any real service. They are designed to be
dropped into the Makina UI as a folder and scanned with Scan All.

Suggested flow:

1. Open Makina locally.
2. Drop this `samples/vulnerable-code` folder into the editor.
3. Run `Scan All` or select one file and run `Scan`.
4. Send findings to Audit for LLM report generation.

Expected issue classes include SQL injection, command injection, unsafe
deserialization, code injection, path traversal, XSS, weak hashing, and SSRF.
