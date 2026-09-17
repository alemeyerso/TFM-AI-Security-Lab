import sys
content = open('lab/server.py', encoding='utf-8').read().split('\n')
for i, line in enumerate(content):
    if '@app.post("/api/sync")' in line:
        # replace the next line which is `async def api_sync():`
        if 'async def api_sync()' in content[i+1]:
            content[i+1] = 'async def api_sync(x_lab_token: str = fastapi.Header(None)):'
            content.insert(i+2, '    if x_lab_token != os.environ.get("LAB_SYNC_TOKEN", "dummy"): raise HTTPException(status_code=401, detail="Invalid")')
            break

# Ensure fastapi is imported
content_str = '\n'.join(content)
if 'import fastapi' not in content_str:
    content_str = 'import fastapi\n' + content_str
open('lab/server.py', 'w', encoding='utf-8').write(content_str)
print("done")
