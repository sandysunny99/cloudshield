with open('backend/app.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

new_lines = []
in_restored = False
for line in lines:
    if '# --- RESTORED CLOUD & CONTAINER ENDPOINTS ---' in line:
        in_restored = True
    elif 'if __name__ == "__main__":' in line:
        in_restored = False
        
    if in_restored and not line.startswith('@app.route') and line.startswith('    '):
        new_lines.append(line[4:])
    else:
        new_lines.append(line)

with open('backend/app.py', 'w', encoding='utf-8') as f:
    f.writelines(new_lines)
