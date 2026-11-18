import asyncio
import os
import httpx2


async def main():
    async with httpx2.AsyncClient(base_url="https://wazuh.manager:55000", verify=False, timeout=10) as client:
        auth = await client.post("/security/user/authenticate", auth=(os.environ["TERMINUS_RESPONSE_API_USER"], os.environ["TERMINUS_RESPONSE_API_PASSWORD"]))
        token = auth.json()["data"]["token"]
        response = await client.put("/active-response", params={"agents_list": "002"}, headers={"Authorization": f"Bearer {token}"}, json={"command": "!probe-ar.sh", "arguments": [], "alert": {"data": {"srcip": "10.77.0.10"}}})
        data = response.json()
        print(response.status_code, data.get("data", {}).get("total_affected_items"), data.get("data", {}).get("total_failed_items"))


asyncio.run(main())
