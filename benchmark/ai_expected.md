# Logic flaws in samples/vuln-app/admin.py (AI review only)

These have no syntactic signature, so the rule and AST scanners are not
expected to find them. They are kept out of the source file so the LLM is not
handed the answer.

| Function | Flaw | CWE |
|---|---|---|
| `get_invoice` | Any logged-in user can read any invoice; no ownership check (IDOR) | CWE-639 |
| `delete_user` | Admin role is taken from the request body, so any caller can claim it | CWE-285 |
| `reset_password` | Reset token is the username reversed, so it is predictable | CWE-640 |
