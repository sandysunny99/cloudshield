import codecs

with open('backend/requirements.txt', 'rb') as f:
    data = f.read()

# find redis
idx = data.find(b'redis>=5.0.0')
if idx != -1:
    clean_data = data[:idx + len(b'redis>=5.0.0')] + b'\nPyJWT>=2.8.0\n'
    with open('backend/requirements.txt', 'wb') as f:
        f.write(clean_data)
    print("Fixed requirements.txt")
else:
    print("redis not found")
