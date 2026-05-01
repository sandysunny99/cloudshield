import codecs

with codecs.open('backend/app.py', 'r', 'utf-8') as f:
    lines = f.readlines()

start_idx = -1
for i, line in enumerate(lines):
    if '# --- RESTORED CLOUD & CONTAINER ENDPOINTS ---' in line:
        start_idx = i
        break

if start_idx != -1:
    end_idx = -1
    for i in range(start_idx, len(lines)):
        if lines[i].strip() == 'if __name__ == "__main__":':
            end_idx = i
            break
            
    if end_idx != -1:
        # Also include the '    return app' that we added right before end_idx
        # wait, let's just delete everything from start_idx to end_idx, except '    return app' if it's there
        del lines[start_idx:end_idx]
        
        # Ensure return app is still there
        if lines[start_idx-1].strip() != 'return app':
            lines.insert(start_idx, '    return app\n\n')
            
        with codecs.open('backend/app.py', 'w', 'utf-8') as f:
            f.writelines(lines)
        print(f"Deleted duplicate block from {start_idx} to {end_idx}")
    else:
        print("End marker not found")
else:
    print("Start marker not found")
