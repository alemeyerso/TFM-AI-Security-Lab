import re
content = open('lab/server.py', encoding='utf-8').read()
content = content.replace('allowed_hosts=["localhost", "127.0.0.1"]', 'allowed_hosts=["localhost", "127.0.0.1", "testserver"]')
open('lab/server.py', 'w', encoding='utf-8').write(content)
