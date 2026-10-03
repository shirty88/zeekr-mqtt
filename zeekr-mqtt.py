import argparse
import json
import os
import sys
import urllib.request
import paho.mqtt.publish as publish
from zeekr_ev_api.client import ZeekrClient

# --- Configuration & Secrets Loading ---
SECRETS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "zeekr_secrets.json")

def load_secrets(filepath):
    """Loads Zeekr API and MQTT secrets from a JSON file."""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Secrets file not found: {filepath}")
    with open(filepath, 'r') as f:
        return json.load(f)

def is_evcc_charging(vehicle_name):
    """Queries the local EVCC API to check if the vehicle is actively charging."""
    try:
        req = urllib.request.Request("http://127.0.0.1:7070/api/state")
        with urllib.request.urlopen(req, timeout=2) as response:
            data = json.loads(response.read().decode())
            for lp in data.get('loadpoints', []):
                if lp.get('vehicleName') == vehicle_name:
                    return lp.get('charging', False)
    except Exception as e:
        print(f"Warning: Could not check EVCC state: {e}")
    
    # Fail-safe: Assume False to protect API limits if EVCC is unreachable
    return False

def main():
    parser = argparse.ArgumentParser(description="Zeekr API to MQTT Bridge")
    parser.add_argument("--vin", type=str, help="The VIN of the vehicle. Skips the vehicle list API call if provided.")
    parser.add_argument("--trigger", type=str, default="manual", help="The identifier of the triggering systemd instance")
    args = parser.parse_args()

    try:
        secrets = load_secrets(SECRETS_FILE)
    except Exception as e:
        print(f"Failed to load secrets: {e}")
        sys.exit(1)

    evcc_vehicle_name = secrets.get("evcc_vehicle", [])

    # 2. Pre-execution check for fast charging schedule
    if args.trigger == "fast":
        if not evcc_vehicle_name:
            print(f"Trigger is '{args.trigger}' but evcc_vehicle_name is not defined in secrets. Exiting smoothly.")
            return
        if not is_evcc_charging(evcc_vehicle_name):
            print(f"Trigger is '{args.trigger}' but {evcc_vehicle_name} is not actively charging. Exiting smoothly.")
            return

    # Extract credentials and endpoints
    zeekr_username = secrets.get("zeekr_username")
    zeekr_password = secrets.get("zeekr_password")
    mqtt_broker    = secrets.get("mqtt_broker", "127.0.0.1")
    mqtt_port      = secrets.get("mqtt_port", 1883)
    
    mqtt_auth = None
    if secrets.get("mqtt_user") and secrets.get("mqtt_pass"):
        mqtt_auth = {
            'username': secrets.get("mqtt_user"),
            'password': secrets.get("mqtt_pass")
        }

    client = ZeekrClient(
        username=zeekr_username,
        password=zeekr_password,
        hmac_access_key=secrets.get("hmac_access_key"),
        hmac_secret_key=secrets.get("hmac_secret_key"),
        password_public_key=secrets.get("password_public_key"),
        prod_secret=secrets.get("prod_secret"),
        vin_key=secrets.get("vin_key"),
        vin_iv=secrets.get("vin_iv")
    )

    try:
        print(f"Starting data sync triggered by: {args.trigger}")
        print("Authenticating...")
        client.login() 

        # Privacy layer: Fallback to secrets JSON if command line argument isn't provided
        vin = args.vin or secrets.get("vin")

        if vin:
            print(f"Using designated VIN: {vin[:4]}...{vin[-4:]}")
        else:
            print("Fetching vehicle list from API...")
            vehicles = client.get_vehicle_list()
            if not vehicles:
                print("No vehicles found.")
                return
            my_vehicle = vehicles[0]
            vin = my_vehicle.get('vin') if isinstance(my_vehicle, dict) else getattr(my_vehicle, 'vin', None)
            if not vin:
                print("Could not extract VIN.")
                return

        print(f"Fetching vehicle statistics for VIN {vin}...")
        stats = client.get_vehicle_status(vin)
        
        # Extract target nested nodes safely
        basic_status = stats.get("basicVehicleStatus", {})
        add_status = stats.get("additionalVehicleStatus", {})
        
        electric_status = add_status.get("electricVehicleStatus", {})
        maintenance_status = add_status.get("maintenanceStatus", {})
        position_status = basic_status.get("position", {})
        climate_status = add_status.get("climateStatus", {})

        # Compile data payloads
        charging_payload = electric_status
        location_payload = position_status
        climate_payload = climate_status 
        status_payload = {}
        
        for k, v in basic_status.items():
            if k != "position":
                status_payload[k] = v
                
        for k, v in maintenance_status.items():
            status_payload[k] = v

        # MQTT Message Packaging
        base_topic = f"transport/{vin}"
        msgs = []

        if charging_payload:
            msgs.append({'topic': f"{base_topic}/charging", 'payload': json.dumps(charging_payload), 'retain': True})
        if status_payload:
            msgs.append({'topic': f"{base_topic}/state", 'payload': json.dumps(status_payload), 'retain': True})
        if location_payload:
            msgs.append({'topic': f"{base_topic}/location", 'payload': json.dumps(location_payload), 'retain': True})
        if climate_payload:
            msgs.append({'topic': f"{base_topic}/climate", 'payload': json.dumps(climate_payload), 'retain': True})

        print(f"Publishing messages to MQTT broker at {mqtt_broker}...")
        publish.multiple(msgs, hostname=mqtt_broker, port=mqtt_port, auth=mqtt_auth)
        print("Zeekr MQTT broadcast successful.")

    except Exception as e:
        print(f"\nAn error occurred: {e}")
    finally:
        if hasattr(client, 'close'):
            client.close()

if __name__ == "__main__":
    main()