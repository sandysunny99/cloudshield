with open('frontend/index.html', 'r', encoding='utf-8') as f:
    for line in f:
        if '<button' in line and 'id="btn-' in line:
            print(line.strip())
