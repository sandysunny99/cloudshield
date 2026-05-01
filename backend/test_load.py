import requests
import random
import time
import concurrent.futures

API_URL = "http://localhost:5000/api/agent-scan"
# Use a generic key or dummy signature to bypass HMAC during test if needed
HEADERS = {"x-agent-signature": "test-mode"} 

def send_event(i):
    try:
        payload = {
            "agent_id": f"a{i%10}",
            "cpu": random.randint(10, 100),
            "memory": random.randint(10, 100),
            "ip": "8.8.8.8" if random.random() > 0.9 else f"192.168.1.{random.randint(1, 255)}"
        }
        res = requests.post(API_URL, json=payload, headers=HEADERS, timeout=2)
        return res.status_code
    except Exception as e:
        return str(e)

def main():
    print("Starting load test: 200 events...")
    start_time = time.time()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        results = list(executor.map(send_event, range(200)))
        
    duration = time.time() - start_time
    success = sum(1 for r in results if r == 200)
    
    print(f"Test complete in {duration:.2f} seconds.")
    print(f"Successful requests: {success}/200")
    print(f"Throughput: {200/duration:.2f} req/sec")

if __name__ == "__main__":
    main()
