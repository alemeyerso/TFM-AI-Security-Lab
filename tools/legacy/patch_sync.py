import re
content = open('lab/server.py', encoding='utf-8').read()

# I need to add `x_lab_token: str = Header(None)` to the parameters of the `/api/sync` endpoint, 
# and verify `x_lab_token == os.getenv("LAB_SYNC_TOKEN")`. 
# Wait, let's just make it simpler: `x_lab_token: str = fastapi.Header(None)` 
# Since fastapi is imported as `from fastapi import FastAPI, ...` I will just import Header if needed, or `fastapi.Header`.

header_import = ""
if " Header" not in content:
    content = content.replace("from fastapi import FastAPI, HTTPException", "from fastapi import FastAPI, HTTPException, Header, Security\nfrom fastapi.security import APIKeyHeader")

# Let's search for `@app.post("/api/sync")`
# def api_sync():
#     if not ENABLE_GITHUB_SYNC:
#         raise HTTPException(status_code=403, detail="Sync disabled")

# We can replace `@app.post("/api/sync")` and its def with:
new_sync_code = """@app.post("/api/sync")
async def api_sync(x_lab_token: str = Header(None)):
    if not ENABLE_GITHUB_SYNC:
        raise HTTPException(status_code=403, detail="Sync is disabled")
    if x_lab_token != os.environ.get("LAB_SYNC_TOKEN", "dummy-token-for-local"):
        raise HTTPException(status_code=401, detail="Invalid token")"""

content = re.sub(r'@app\.post\("/api/sync"\)\s*async def api_sync\(\):\s*if not ENABLE_GITHUB_SYNC:\s*raise HTTPException\(status_code=403, detail="[^"]+"\)', new_sync_code, content)

open('lab/server.py', 'w', encoding='utf-8').write(content)
