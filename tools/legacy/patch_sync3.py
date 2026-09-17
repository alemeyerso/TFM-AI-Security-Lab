content = open('lab/server.py', encoding='utf-8').read()
content = content.replace('import fastapi\n', '')
content = content.replace('from __future__ import annotations\n', 'from __future__ import annotations\nimport fastapi\n')
open('lab/server.py', 'w', encoding='utf-8').write(content)
