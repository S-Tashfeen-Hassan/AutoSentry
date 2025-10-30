import requests
import json

url = "https://sequence-bow-enhancement-output.trycloudflare.com/api/generate"
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
