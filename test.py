import requests
import json

url = "http://100.95.184.60:11434/api/generate"
model = "phi3:mini"

print("=== phi3:mini Interactive Chat ===")
print("Type 'exit' to quit\n")

while True:
    prompt = input("You: ")
    if prompt.lower() in ["exit", "quit"]:
        break

    payload = {
        "model": model,
        "prompt": prompt
    }

    response = requests.post(url, json=payload, stream=True)

    print("Bot: ", end="", flush=True)
    full_text = ""

    for line in response.iter_lines():
        if line:
            try:
                data = json.loads(line)
                chunk = data.get("response", "")
                full_text += chunk
                print(chunk, end="", flush=True)  
            except json.JSONDecodeError:
                pass  

    print("\n")  


# You are a concise cybersecurity analyst. Given the single JSON log object below, output JSON ONLY with keys:",
#             '  verdict: one of "malicious", "benign", "uncertain"',
#             '  score: float between 0.0 and 1.0 (higher means more malicious) and anything above 0.5 including 0.5 is malicious under is benign',
#             '  reasons: array of short reasoning strings',
#             '  recommended_action: one of "block_ip","notify","monitor"',
#             "",
#             "Here are examples (do NOT hallucinate beyond the fields):
# "example_log": {"message":"SSH failed_login attempt from 1.2.3.4","conn_count":1},
#                 "example_out": {"verdict":"benign","score":0.12,"reasons":["single failed login, low volume"],"recommended_action":"monitor"}
#             },
#             {
#                 "example_log": {"message":"Multiple failed_login and bruteforce pattern from 203.0.113.5","conn_count":120},
#                 "example_out": {"verdict":"malicious","score":0.93,"reasons":["high connection count","bruteforce pattern"],"recommended_action":"block_ip"}
#             }
# Now analyze this log and return JSON only:
# {"timestamp": "2025-10-29T14:55:10.741Z", "event_type": "alert", "app_proto": "ssh", "proto": "TCP", "src_ip": "192.168.56.10", "src_port": 22, "dest_ip": "192.168.56.1", "dest_port": 40582, "direction": "to_client", "alert_signature_id": 2228000, "alert_signature": "SURICATA SSH invalid banner", "alert_rev": 1, "alert_severity": 3, "alert_action": "allowed", "alert_category": "Generic Protocol Command Decode", "fileinfo_filename": null, "fileinfo_size": null, "fileinfo_state": null, "fileinfo_stored": null, "http_protocol": null, "http_hostname": null, "http_http_method": null, "http_url": null, "http_status": null, "http_http_content_type": null, "flow_id": 1480740619182091, "flow_pkts_toserver": 5, "flow_pkts_toclient": 5, "flow_bytes_toserver": 361, "flow_bytes_toclient": 352, "flow_start": "2025-10-29T14:53:17.279225+0500", "source": "autosentry-client", "filebeat_host_name": "autosentry-client", "_id": "446c6c50-b4d7-11f0-a0ea-080027b4982b"}
