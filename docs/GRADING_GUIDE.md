# TERMINUS evaluation guide

Start with the [installation manual](INSTALLATION.md). The standard evaluation starts a clean loopback instance and uses the prebuilt console. It needs no live security connector or model credential.

1. Open the health endpoint and confirm the service responds.
2. Sign in to the console with the local evaluation account listed in the manual.
3. Review Overview, Incidents, Agents and Workflows. The [QA walkthroughs](QA_LOCAL_EXPLORATION.md) explain how to exercise synthetic intake and inspect recorded activity when those controls are available.
4. Use the [SDD-to-code map](IMPLEMENTATION_MAP.md) to locate the implementation and identify acceptance checks that remain open.

## Verification

Run the regression suite from the extracted source directory. The following command uses a separate SQLite database.

```powershell
uv run --frozen python -c "import pathlib,tempfile,pytest; from terminus.storage.db import Database; tmp=tempfile.TemporaryDirectory(prefix='terminus-tests-', ignore_cleanup_errors=True); Database.reset_instance(str(pathlib.Path(tmp.name)/'tests.db')); raise SystemExit(pytest.main(['-q']))"
```

See the [testing record](TESTING_STATUS.md) and [response evidence](RESPONSE_DECISIONS.md) for the scope and counts of previously recorded runs. The approved and autonomous Wazuh responses used the isolated team lab. Browser-driven SSH acceptance remains a separate test. The interactive presentation launcher resets demo records and generates simulated traffic. Use a disposable demo workspace if you run it.
