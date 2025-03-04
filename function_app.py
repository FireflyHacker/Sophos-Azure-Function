import logging
import azure.functions as func
import logging
import requests
import re

# TODO: Use Secrets for these values so they are not stored in the source code
SOPHOS_TOKEN_URL = "https://id.sophos.com/api/v2/oauth2/token"
SOPHOS_API_BASE = ""
SOPHOS_CLIENT_ID = ""
SOPHOS_CLIENT_SECRET = ""
SOPHOS_TENANT_ID = ""

gateway_down_pattern = r"Gateway\s+(.*?)\s+is down\."
gateway_up_pattern = r"Gateway\s+(.*?)\s+is up\."

logging.info('Starting Function')

app = func.FunctionApp()

@app.timer_trigger(schedule="0 */5 * * * *", arg_name="myTimer", run_on_startup=False,
              use_monitor=False) 
def timer_trigger(myTimer: func.TimerRequest) -> None:
    if myTimer.past_due:
        logging.info('The timer is past due!')

    logging.info('Python timer trigger function executed.')
    logging.info("Azure Function - Sophos Firewall Alert Check Triggered.")

    # Get a Sophos token
    sophos_token = get_sophos_token()
    if not sophos_token:
        logging.error("Unable to obtain Sophos token.")
        return

    # Fetch all firewall alerts
    alerts = fetch_sophos_alerts(sophos_token)

    # Identify "gateway down" and "gateway re-connected" alerts.
    gateway_down_alerts = [a for a in alerts if alert_is_gateway_down(a)]
    gateway_up_alerts = [a for a in alerts if alert_is_gateway_up(a)]

    # Attempt to pair them by the same firewall/device_id.
    resolved_pairs = []
    for down_alert in gateway_down_alerts:
        device_id = down_alert.get("device_id")
        # Find a corresponding reconnected alert for the same device
        up_alert = next((x for x in gateway_up_alerts if x.get("device_id") == device_id), None)
        if up_alert:
            # Resolve both
            resolve_alert(sophos_token, down_alert["id"])
            resolve_alert(sophos_token, up_alert["id"])
            resolved_pairs.append((down_alert["id"], up_alert["id"]))

    if resolved_pairs:
        logging.info(f"Resolved pairs of alerts: {resolved_pairs}")
    else:
        logging.info("No matching 'gateway down'/'up' pairs found.")

    logging.info("Azure Function - Sophos Firewall Alert Check Completed.")


def get_sophos_token():
    data = {
        "grant_type": "client_credentials",
        "client_id": SOPHOS_CLIENT_ID,
        "client_secret": SOPHOS_CLIENT_SECRET,
        "scope": "token"
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    try:
        resp = requests.post(SOPHOS_TOKEN_URL, data=data, headers=headers)
        resp.raise_for_status()
        return resp.json().get("access_token")
    except requests.RequestException as e:
        logging.error(f"Failed to retrieve Sophos token: {e}")
        return None

def fetch_sophos_alerts(token):
    # Get all alerts for firewalls
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Tenant-ID": SOPHOS_TENANT_ID,
        "Content-Type": "application/json"
    }

    try:
        resp = requests.get(f"{SOPHOS_API_BASE}/common/v1/alerts?product=firewall", headers=headers)
        resp.raise_for_status()
        return resp.json().get("items", [])
    except requests.RequestException as e:
        logging.error(f"Error fetching alerts: {e}")
        return []

def alert_is_gateway_down(alert):
    # Identify gateway down alerts.
    match = re.match(gateway_down_pattern, alert.get("description", ""))
    return match is not None

def alert_is_gateway_up(alert):
    # Identify gateway up alerts.
    match = re.match(gateway_up_pattern, alert.get("description", ""))
    return match is not None

def resolve_alert(token, alert_id):
    # Resolve an alert in Sophos.
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Tenant-ID": SOPHOS_TENANT_ID,
        "Content-Type": "application/json"
    }
    requestBody = {
        "action": "acknowledge",
        "message": "Gateway is back online."
    }
    try:
        resolve_url = f"{SOPHOS_API_BASE}/common/v1/alerts/{alert_id}/actions"
        resp = requests.post(resolve_url, headers=headers, json=requestBody)
        resp.raise_for_status()
        logging.info(f"Resolved alert {alert_id}")
    except requests.RequestException as e:
        logging.error(f"Failed to resolve alert {alert_id}: {e}")
