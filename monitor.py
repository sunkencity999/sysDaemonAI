import os
import json
import time
import subprocess
import datetime
import platform
import psutil

# Configuration
LOG_DIR = "./logs"
BASELINE_FILE = "./baseline.json"
CHECK_INTERVAL = 30  # seconds between checks
ADAPTATION_INTERVALS = 10  # Every N checks, ask the LLM for assessment
MODEL_NAME = "my-local-llm-model"  # The model name loaded into Ollama

def notify_user(message):
    """
    Use AppleScript to display a notification on macOS.
    """
    if platform.system() == "Darwin":
        subprocess.run(["osascript", "-e", f'display notification "{message}" with title "Network Monitor Alert"'])

def load_baseline():
    if os.path.exists(BASELINE_FILE):
        with open(BASELINE_FILE, "r") as f:
            return json.load(f)
    return {"normal_patterns": [], "history": []}

def save_baseline(baseline):
    with open(BASELINE_FILE, "w") as f:
        json.dump(baseline, f, indent=4)

def log_connections(connections):
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"connections_{timestamp}.json"
    with open(os.path.join(LOG_DIR, filename), "w") as f:
        json.dump(connections, f, indent=4)
    return filename

def get_current_connections():
    """
    Use psutil to get current network connections.
    """
    conns = psutil.net_connections(kind='inet')
    data = []
    for c in conns:
        laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else None
        raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None
        data.append({
            "pid": c.pid,
            "status": c.status,
            "local_address": laddr,
            "remote_address": raddr,
            "family": str(c.family),
            "type": str(c.type)
        })
    return data

def summarize_recent_logs(n=3):
    """
    Summarize the last n logs for the LLM prompt.
    """
    if not os.path.exists(LOG_DIR):
        return []

    logs = sorted([f for f in os.listdir(LOG_DIR) if f.startswith("connections_")])
    if not logs:
        return []

    recent = logs[-n:] if len(logs) >= n else logs
    summaries = []
    for fname in recent:
        with open(os.path.join(LOG_DIR, fname), "r") as f:
            conns = json.load(f)
        summaries.append({
            "filename": fname,
            "connection_count": len(conns),
            "sample_entries": conns[:5]  # just a few to show pattern
        })
    return summaries

def query_llm(prompt):
    """
    Query the local LLM model via Ollama.
    """
    result = subprocess.run(["ollama", "run", MODEL_NAME, "--text", prompt], 
                            capture_output=True, text=True)
    return result.stdout.strip()

def generate_llm_prompt(baseline, recent_summaries):
    """
    Generate a prompt for the LLM that includes baseline and recent summaries.
    """
    prompt = (
        "You are a local network analysis assistant. "
        "You have been monitoring the system's connections over time. "
        "You have established a baseline of normal activity and patterns. "
        "Now, I will provide you with summaries of recent connections. "
        "Please tell me if anything stands out as unusual compared to the baseline. "
        "If unusual, provide reasons and suggestions. If normal, confirm that everything is typical.\n\n"
        f"Current baseline of normal activity: {baseline['normal_patterns']}\n\n"
        "Recent summaries:\n"
    )
    for summary in recent_summaries:
        prompt += f"File: {summary['filename']}, Count: {summary['connection_count']}\nSample: {summary['sample_entries']}\n\n"
    return prompt

def main():
    baseline = load_baseline()
    iteration = 0

    while True:
        # Get current connections and log them
        connections = get_current_connections()
        log_filename = log_connections(connections)
        
        iteration += 1
        if iteration % ADAPTATION_INTERVALS == 0:
            # Every ADAPTATION_INTERVALS checks, query LLM
            recent_summaries = summarize_recent_logs()
            if recent_summaries:
                prompt = generate_llm_prompt(baseline, recent_summaries)
                llm_response = query_llm(prompt)
                
                # Check if the LLM detected something unusual
                if "unusual" in llm_response.lower() or "suspicious" in llm_response.lower():
                    notify_user("Suspicious network activity detected! Check logs for details.")
                
                # Record the LLM analysis
                baseline["history"].append({
                    "timestamp": datetime.datetime.now().isoformat(),
                    "analysis": llm_response
                })
                save_baseline(baseline)

        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    main()