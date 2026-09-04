# Terminus Opposer - Independent Red Team Demo Suite

This repository directory is a standalone, isolated Red Team Opposer tool.
It is designed to run independently from the core product codebase and acts as an external adversary testing harness.

## Running the Opposer Dashboard

To launch the standalone Opposer server:

```bash
python main.py
```

By default, the dashboard will start at:
`http://localhost:8080`

You can configure the target endpoint (e.g. an ngrok tunnel `https://xxxx.ngrok-free.app/wazuh`, local service `http://localhost:8000/wazuh`, or VPS listener), input tenant header credentials, and launch security validation scenarios.
