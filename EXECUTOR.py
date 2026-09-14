#EXECUTOR.py
# Standard library
from datetime import timedelta
import json
from httpx import HTTPStatusError
import requests, urllib.parse


# Third-party libraries
from azure.identity import DefaultAzureCredential
import pandas as pd
from colorama import Fore, Style
from anthropic import RateLimitError, APIError


# Local modules
import PROMPT_MANAGEMENT

# ===== QURANTINE THE VIRTUAL ENVIRONMENT =====
def get_bearer_token():
    credential = DefaultAzureCredential()
    token = credential.get_token("https://api.loganalytics.io/.default")
    return token.token

def get_mde_id_from_name(token,device_name):
    """
    Look up a device ID by its name in the Microsoft Defender for Endpoint API.
    Works of the user provide either the FQDN or the short hostname.
    
    Args:
        token (str): Bearer token for authentication.

    Returns:
        str: The device ID if found, otherwise None.
    Raises:
        Exception: If the API request fails or returns an unexpected status code.              
    """
    headers = {
        "Authorization": f"Bearer {token.token}"}
    #use 'startswith' to match both FQDN and short hostname
    
    filter_q = urlib.parse.quote(f"startswith(computerDnsName,'{device_name}') ")
    url = f"https://api.securitycenter.microsoft.com/api/machines?$filter={filter_q}"
    
    resp= request.get(url, headers=headers, timeout=30)
    resp.raise_for_status()  # Raise an exception for HTTP errors

    machines = resp.json().get("value", [])
    if not machines:
        raise Exception(f"No device found with name starting with '{device_name}'")

    # if multiple machines match , pick the first
    # add logic-- choose teh most recent aka 'lastseen'
    machine_id = machines[0]["id"]
    return machine_id


def quarantine_virtual_device(token, machine_id):
    
    headers = {
        "Authorization": f"Bearer {token.token}",
        "Content-Type": "application/json"
    }

    # Example : isolate a machine
    payload = {
        "Comment": "Isolation via Python Agentic Ai using DefaultAzureCredential",  
        "IsolationType": "Full"
    }
    
    resp = requests.post(
        f"https://api.securitycenter.microsoft.com/api/machines/{machine_id}/isolate",
        headers=headers,
        json=payload,
        timeout=30
    )

    if resp.status_code == 201 or 200:
            return True
    return False
            
# ====================================================================  



def hunt(anthropic_client, threat_hunt_system_message, threat_hunt_user_message, model):
    """
    Runs the threat hunting flow:
    1. Formats the logs into a string
    2. Selects appropriate system prompt from context
    3. Passes logs + role to model
    4. Parses and returns a raw array
    Handles rate-limit/token overage errors gracefully.
    """

    results = []

    # threat_hunt_system_message: plain string -> goes into the `system=` param
    # threat_hunt_user_message: {"role": "user", "content": ...} -> goes into messages
    messages = [threat_hunt_user_message]

    # Claude has no JSON-mode flag, so we force structured output via a tool call.
    findings_tool = {
        "name": "report_threat_hunt_findings",
        "description": "Reports the findings of a threat hunt analysis over log data, following the schema described in the formatting instructions.",
        "input_schema": {
            "type": "object",
            "properties": {
                "findings": {
                    "type": "array",
                    "description": "List of potential threats/anomalies found in the logs. Empty array if none found.",
                    "items": {
                        "type": "object",
                        "properties": {
                            "title": {"type": "string"},
                            "description": {"type": "string"},
                            "mitre": {
                                "type": "object",
                                "properties": {
                                    "tactic": {"type": "string"},
                                    "technique": {"type": "string"},
                                    "sub_technique": {"type": "string"},
                                    "id": {"type": "string"},
                                    "description": {"type": "string"}
                                }
                            },
                            "log_lines": {"type": "array", "items": {"type": "string"}},
                            "confidence": {"type": "string", "enum": ["Low", "Medium", "High"]},
                            "recommendations": {"type": "array", "items": {"type": "string"}},
                            "indicators_of_compromise": {"type": "array", "items": {"type": "string"}},
                            "tags": {"type": "array", "items": {"type": "string"}},
                            "notes": {"type": "string"}
                        }
                    }
                }
            },
            "required": ["findings"]
        }
    }

    try:
        response = anthropic_client.messages.create(
            model=model,
            max_tokens=4000,
            system=threat_hunt_system_message,
            messages=messages,
            tools=[findings_tool],
            tool_choice={"type": "tool", "name": "report_threat_hunt_findings"}
        )

        tool_use_block = next(b for b in response.content if b.type == "tool_use")
        results = tool_use_block.input
        return results

    except RateLimitError as e:
        error_msg = str(e)

        # Print dark red warning
        print(f"{Fore.LIGHTRED_EX}{Style.BRIGHT}🚨ERROR: Rate limit or token overage detected!{Style.RESET_ALL}")
        print(f"{Fore.LIGHTRED_EX}{Style.BRIGHT}The input was too large for this model or hit rate limits.")
        print(f"{Style.RESET_ALL}——————————\nRaw Error:\n{error_msg}\n——————————")
        print(f"{Fore.WHITE}Suggestions:")
        print(f"- Use fewer logs or reduce input size.")
        print(f"- Switch to a model with a larger context window.")
        print(f"- Retry later if rate-limited.\n")

        return None

    except APIError as e:
        print(f"{Fore.RED}Unexpected Anthropic API error:\n{e}")
        return None

    except Exception as e:
        print(f"{Fore.RED}Unexpected error in hunt(): {type(e).__name__}: {e}")
        return None


# Extract and parse the tool call selected by the model.
# This is Claude's tool use feature, where the model chooses a tool from the
# provided list and returns the arguments it wants to use to call it.
# In this case, the tool selected queries log data from Microsoft Defender via
# Log Analytics.
#
# Docs: https://platform.claude.com/docs/en/build-with-claude/tool-use
def get_query_context(anthropic_client, user_message, model):

    print(f"{Fore.LIGHTGREEN_EX}\nDeciding log search parameters based on user request...\n")

    system_message = PROMPT_MANAGEMENT.SYSTEM_PROMPT_TOOL_SELECTION

    response = anthropic_client.messages.create(
        model=model,
        max_tokens=2000,
        system=system_message,
        messages=[user_message],
        tools=PROMPT_MANAGEMENT.TOOLS,
        tool_choice={"type": "any"}  # forces some tool call, equivalent to OpenAI's tool_choice="required"
    )

    # TODO: Fix this (if there are no returns)
    tool_use_block = next(b for b in response.content if b.type == "tool_use")
    args = tool_use_block.input

    return args


def query_log_analytics(log_analytics_client, workspace_id, timerange_hours, table_name, device_name, fields, caller, user_principal_name):

    if table_name == "AzureNetworkAnalytics_CL":
        user_query = f'''{table_name}
| where FlowType_s == "MaliciousFlow"
| project {fields}'''

    elif table_name == "AzureActivity":
        user_query = f'''{table_name}
| where isnotempty(Caller) and Caller !in ("d37a587a-4ef3-464f-a288-445e60ed248c","ef669d55-9245-4118-8ba7-f78e3e7d0212","3e4fe3d2-24ff-4972-92b3-35518d6e6462")
| where Caller startswith "{caller}"
| project {fields}'''

    elif table_name == "SigninLogs":
        user_query = f'''{table_name}
| where UserPrincipalName startswith "{user_principal_name}"
| project {fields}'''

    else:
        user_query = f'''{table_name}
| where DeviceName startswith "{device_name}"
| project {fields}'''

    print(f"{Fore.LIGHTGREEN_EX}Constructed KQL Query:")
    print(f"{Fore.WHITE}{user_query}\n")

    print(f"{Fore.LIGHTGREEN_EX}Querying Log Analytics Workspace ID: '{workspace_id}'...")

    response = log_analytics_client.query_workspace(
        workspace_id=workspace_id,
        query=user_query,
        timespan=timedelta(hours=timerange_hours)
    )

    if len(response.tables[0].rows) == 0:
        print(f"{Fore.WHITE}No data returned from Log Analytics.")
        return { "records": "", "count": 0 }

    # Extract the table
    table = response.tables[0]

    # TODO: Handle if returns 0 events
    record_count = len(response.tables[0].rows)

    # Extract columns and rows using dot notation
    columns = table.columns  # Already a list of strings
    rows = table.rows        # List of row data

    df = pd.DataFrame(rows, columns=columns)
    records = df.to_csv(index=False)

    return { "records": records, "count": record_count }
