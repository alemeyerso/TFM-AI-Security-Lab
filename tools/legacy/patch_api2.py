import re
content = open('lab/server.py', encoding='utf-8').read()

# 1. Add TrustedHostMiddleware
if 'TrustedHostMiddleware' not in content:
    content = content.replace('from fastapi.middleware.cors import CORSMiddleware',
                              'from fastapi.middleware.cors import CORSMiddleware\nfrom fastapi.middleware.trustedhost import TrustedHostMiddleware')
    content = content.replace('app.add_middleware(',
                              'app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1"])\napp.add_middleware(')

if 'from pydantic import BaseModel' in content and 'Field' not in content:
    content = content.replace('from pydantic import BaseModel', 'from pydantic import BaseModel, Field')

# 2. Modify AttackRequest carefully
# We know it looks like:
# class AttackRequest(BaseModel):
#     model: str
#     vector: str
#     ...
#     custom_prompt: Optional[str] = None
content = re.sub(r'(class AttackRequest\(BaseModel\):.*?model:\s*str)', r'\1 = Field(..., pattern=r"^[A-Za-z0-9._:/-]{1,100}$")', content, flags=re.DOTALL)
content = re.sub(r'(class AttackRequest\(BaseModel\):.*?custom_prompt:\s*Optional\[str\]\s*=\s*)None', r'\1Field(default=None, max_length=32000)', content, flags=re.DOTALL)


# 3. Sanitize model name in _save_attack_result
if 'safe = re.sub' not in content:
    content = content.replace('result["model"].replace(":", "_")', 're.sub(r"[^A-Za-z0-9._-]", "_", result["model"])')

open('lab/server.py', 'w', encoding='utf-8').write(content)
