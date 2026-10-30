# File: main.py
import json
import os

AGENTS_FILE = "agents.json"
CALLS_FILE = "calls.json"

def load_data(filename):
    if not os.path.exists(filename): return []
    try:
        with open(filename, "r") as file: return json.load(file)
    except json.JSONDecodeError: return []

def save_data(filename, data):
    with open(filename, "w") as file: json.dump(data, file, indent=4)

def add_agent(name):
    agents = load_data(AGENTS_FILE)
    agent_id = f"AG{len(agents) + 1:03d}"
    agents.append({"id": agent_id, "name": name, "status": "Offline"})
    save_data(AGENTS_FILE, agents)
    print(f"✅ Agent '{name}' created with ID: {agent_id}")

def update_agent_status(agent_id, new_status):
    if new_status not in ["Available", "Busy", "Offline"]:
        print("❌ Invalid status.")
        return False
    agents = load_data(AGENTS_FILE)
    for agent in agents:
        if agent["id"] == agent_id:
            agent["status"] = new_status
            save_data(AGENTS_FILE, agents)
            print(f"✅ Agent {agent_id} is now {new_status}")
            return True
    print("❌ Agent not found.")
    return False

def record_call(direction, agent_id, customer_name, customer_phone):
    if direction not in ["Inbound", "Outbound"]:
        print("❌ Direction must be Inbound or Outbound.")
        return False
    agents = load_data(AGENTS_FILE)
    assigned_agent = None
    for agent in agents:
        if agent["id"] == agent_id:
            if agent["status"] != "Available":
                print(f"❌ Agent is {agent['status']}. Cannot assign call.")
                return False
            assigned_agent = agent
            break
    if not assigned_agent:
        print("❌ Agent not found.")
        return False
    calls = load_data(CALLS_FILE)
    calls.append({
        "call_id": f"CALL{len(calls) + 1:04d}",
        "direction": direction,
        "agent_name": assigned_agent["name"],
        "customer_name": customer_name,
        "customer_phone": customer_phone
    })
    save_data(CALLS_FILE, calls)
    print(f"✅ Call recorded for {customer_name}")
    return True

def main_menu():
    while True:
        print("\n" + "="*40)
        print("   ALPHA CONTACT CENTER - STAGE 1")
        print("="*40)
        print("1. Add Agent\n2. Change Status\n3. Record Call\n4. View Calls\n5. View Agents\n6. Exit")
        choice = input("Choice: ").strip()

        if choice == "1":
            add_agent(input("Agent Name: ").strip())
        elif choice == "2":
            update_agent_status(input("Agent ID: ").strip().upper(), input("Status: ").strip().capitalize())
        elif choice == "3":
            record_call(input("Direction: ").strip().capitalize(), input("Agent ID: ").strip().upper(), input("Customer: ").strip(), input("Phone: ").strip())
        elif choice == "4":
            for c in load_data(CALLS_FILE): print(c)
        elif choice == "5":
            for a in load_data(AGENTS_FILE): print(a)
        elif choice == "6":
            break

if __name__ == "__main__":
    main_menu()