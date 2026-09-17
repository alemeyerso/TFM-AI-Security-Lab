import re
content = open('lab/server.py', encoding='utf-8').read()

# 1. Add TrustedHostMiddleware
if 'TrustedHostMiddleware' not in content:
    content = content.replace('from fastapi.middleware.cors import CORSMiddleware',
                              'from fastapi.middleware.cors import CORSMiddleware\nfrom fastapi.middleware.trustedhost import TrustedHostMiddleware')
    content = content.replace('app.add_middleware(',
                              'app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1"])\napp.add_middleware(')

# 2. Modify AttackRequest
content = re.sub(r'model:\s*str', r'model: str = Field(..., pattern=r"^[A-Za-z0-9._:/-]{1,100}$")', content)
content = re.sub(r'custom_prompt:\s*Optional\[str\]\s*=\s*None', r'custom_prompt: Optional[str] = Field(default=None, max_length=32000)', content)

# 3. Sanitize model name in _save_attack_result
if 'safe = re.sub' not in content:
    content = content.replace('result["model"].replace(":", "_")', 're.sub(r"[^A-Za-z0-9._-]", "_", result["model"])')

open('lab/server.py', 'w', encoding='utf-8').write(content)
