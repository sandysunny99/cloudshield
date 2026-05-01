import codecs

with codecs.open('backend/app.py', 'r', 'utf-8') as f:
    lines = f.readlines()

# 1. Find 'return app\n'
return_app_idx = -1
for i, line in enumerate(lines):
    if line.strip() == 'return app' and line.startswith('    return app'):
        return_app_idx = i
        break

if return_app_idx != -1:
    # Remove 'return app' from its current position
    lines.pop(return_app_idx)
    
    # 2. Find the end of api_scan_aws (just before if __name__ == "__main__":)
    main_idx = -1
    for i, line in enumerate(lines):
        if line.strip() == 'if __name__ == "__main__":':
            main_idx = i
            break
            
    # 3. Indent everything from return_app_idx to main_idx by 4 spaces
    for i in range(return_app_idx, main_idx):
        if lines[i].strip(): # Only indent non-empty lines
            lines[i] = '    ' + lines[i]
            
    # 4. Insert 'return app\n' right before main_idx
    lines.insert(main_idx, '    return app\n\n')
    
    with codecs.open('backend/app.py', 'w', 'utf-8') as f:
        f.writelines(lines)
    print("Fixed indentation and moved return app!")
else:
    print("Could not find 'return app'")
