import re
content = open('lab/server.py', encoding='utf-8').read()
content = content.replace('async def _call_ollama(model: str = Field(..., pattern=r"^[A-Za-z0-9._:/-]{1,100}$"), prompt: str)', 'async def _call_ollama(model: str, prompt: str)')
open('lab/server.py', 'w', encoding='utf-8').write(content)
