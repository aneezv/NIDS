import json
import os

CONFIG_FILE = "config.json"

def apply_setup():
    print("=== NIDS Sensor Initial Setup ===")
    print("Press Enter to keep the existing [default] values.\n")
    
    # Load existing config if available, otherwise default dictionary
    data = {}
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                data = json.load(f)
        except json.JSONDecodeError:
            print(f"Warning: {CONFIG_FILE} is invalid JSON. Starting fresh.")
    
    # Define defaults and prompts
    fields = [
        ("sensor_id", "Sensor ID", "sensor_01", "Format example: sensor_4"),
        ("controller_url", "Controller URL", "https://controller.local:5000/alert", "The full URL for the controller's alert endpoint"),
        ("interface", "Network Interface", "eth0", "The interface to sniff on (e.g. eth0, wlan0)"),
        ("threshold", "Threshold", 0.083, "Expected float value between 0 and 1"),
        ("model_path", "Model Path", "model_advanced.pkl", "Path to the .pkl model file"),
        ("batch_size", "Batch Size", 10, "Number of packets to batch before inference"),
        ("cert_path", "Certificate Path", "rootCA.pem", "Path to the controller's SSL root certificate"),
        ("API_KEY", "API Key", "secure-research-demo-key-123", "Secret key for authentication")
    ]
    
    # Interactive prompt loop
    for key, prompt, fallback, hint in fields:
        current_val = data.get(key, fallback)
        print(f"{prompt} [{current_val}]  ({hint})")
        user_input = input(">> ").strip()
        
        if user_input:
            # Type casting if needed
            if isinstance(fallback, float):
                try:
                    data[key] = float(user_input)
                except ValueError:
                    print("Invalid float. Using previous value.")
            elif isinstance(fallback, int):
                try:
                    data[key] = int(user_input)
                except ValueError:
                    print("Invalid int. Using previous value.")
            else:
                data[key] = user_input
        else:
            # keep existing or default value if missing
            data[key] = current_val

    # Ensure whitelist exists
    if "whitelist" not in data:
        data["whitelist"] = [
            "127.0.0.1",
            "192.168.1.8",
            "10.0.0.50"
        ]

    # Save format
    with open(CONFIG_FILE, "w") as f:
        json.dump(data, f, indent=4)
        print(f"\n✅ Configuration saved successfully to {CONFIG_FILE}!")

if __name__ == "__main__":
    apply_setup()
