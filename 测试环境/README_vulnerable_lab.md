# Northstar Books local lab

This is a local-only Node.js 24 bookstore used to exercise the Camellia
scanner. It binds to `127.0.0.1`, uses the built-in `node:sqlite` module, and
has no third-party npm dependencies.

From the project root, start it:

```powershell
cd 测试环境
node server.js
```

From the project root, run the end-to-end verification:

```powershell
python -B .\测试环境\verify_vulnerable_lab.py
```

The site contains an unsafe legacy SQL filter, unescaped search output,
unconfined document paths, a legacy diagnostic command builder, and a default
administrator password. File access is mapped beneath
`测试环境/lab_web/virtual_host`; the diagnostic builder only supports its small
command set. No payload-match branches, uploads, reverse shells, or arbitrary
operating-system commands are implemented.

Useful routes:

- `/catalog?genre=fiction`: SQL-backed catalog filter
- `/search?q=books`: customer search
- `/download?file=guide.txt`: document download
- `/status/host?host=127.0.0.1`: maintenance host check
- `/login`: staff login
- `/about`: safe false-positive control page

The vulnerabilities exist as ordinary application logic. The server does not
inspect scanner signatures or return canned results for known payloads.
