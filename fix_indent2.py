with open('backend/app.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

for i, line in enumerate(lines):
    if line.startswith('import google.generativeai'):
        lines[i] = '    import google.generativeai as genai\n'
    if line.startswith('pass') and lines[i-1].strip() == 'except ImportError:':
        lines[i] = '    pass\n'

with open('backend/app.py', 'w', encoding='utf-8') as f:
    f.writelines(lines)
