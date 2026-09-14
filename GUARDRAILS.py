# GUARDRAILS.py
from colorama import Fore, Style

# TODO: Provide allowed fields later
ALLOWED_TABLES = {
    "DeviceProcessEvents": { "TimeGenerated", "AccountName", "ActionType", "DeviceName", "InitiatingProcessCommandLine", "ProcessCommandLine" },
    "DeviceNetworkEvents": { "TimeGenerated", "ActionType", "DeviceName", "RemoteIP", "RemotePort" },
    "DeviceLogonEvents": { "TimeGenerated", "AccountName", "DeviceName", "ActionType", "RemoteIP", "RemoteDeviceName" },
    "AlertInfo": {},  # No fields specified in tools
    "AlertEvidence": {},  # No fields specified in tools
    "DeviceFileEvents": {"TimeGenerated","ActionType","DeviceName","FileName","FolderPath","InitiatingProcessAccountName","SHA256"},
    "DeviceRegistryEvents": {},  # No fields specified in tools
    "AzureNetworkAnalytics_CL": { "TimeGenerated", "FlowType_s", "SrcPublicIPs_s", "DestIP_s", "DestPort_d", "VM_s", "AllowedInFlows_d", "AllowedOutFlows_d", "DeniedInFlows_d", "DeniedOutFlows_d" },
    "AzureActivity": {"TimeGenerated", "OperationNameValue", "ActivityStatusValue", "ResourceGroup", "Caller", "CallerIpAddress", "Category" },
    "SigninLogs": {"TimeGenerated", "UserPrincipalName", "OperationName", "Category", "ResultSignature", "ResultDescription", "AppDisplayName", "IPAddress", "LocationDetails" },
}

# NOTE ON TIERS:
# Anthropic's usage tiers are named Start / Build / Scale / Custom (not numbered 1-5 like OpenAI),
# each with its own monthly SPEND cap:
#   Start:  $500/month    Build: $1,000/month    Scale: $200,000/month    Custom: negotiated
#
# Rate limits (RPM / ITPM / OTPM) are set per model class and scale up with tier, but the exact
# numbers per tier aren't published in a flat table the way OpenAI's are. Check your org's real
# numbers at: https://platform.claude.com/settings/limits
#
# The "tier" dict below uses representative Start-tier ITPM figures as a starting point.
# Update with your organization's real numbers from the Console link above for accuracy.
ALLOWED_MODELS = {
    "claude-haiku-4-5-20251001": {
        "max_input_tokens": 200_000, "max_output_tokens": 64_000,
        "cost_per_million_input": 1.00, "cost_per_million_output": 5.00,
        "tier": {"start": 2_000_000, "build": None, "scale": None, "custom": None}
    },
    "claude-sonnet-5": {
        "max_input_tokens": 1_000_000, "max_output_tokens": 128_000,
        "cost_per_million_input": 2.00, "cost_per_million_output": 10.00,
        "tier": {"start": 2_000_000, "build": None, "scale": None, "custom": None}
    },
    "claude-opus-5": {
        "max_input_tokens": 1_000_000, "max_output_tokens": 128_000,
        "cost_per_million_input": 5.00, "cost_per_million_output": 25.00,
        "tier": {"start": 2_000_000, "build": None, "scale": None, "custom": None}
    },
}

def validate_tables_and_fields(table, fields):

    print(f"{Fore.LIGHTGREEN_EX}Validating Tables and Fields...")
    if table not in ALLOWED_TABLES:
        print(f"{Fore.RED}{Style.BRIGHT}ERROR:{Style.RESET_ALL} "f"Table '{table}' is not in allowed list — {Fore.RED}{Style.BRIGHT}exiting.{Style.RESET_ALL}")
        exit(1)

    fields = fields.replace(' ','').split(',')

    for field in fields:
        if field not in ALLOWED_TABLES[table]:
            print(f"{Fore.RED}{Style.BRIGHT}WARNING:{Style.RESET_ALL} "
            f"Field '{field}' is not in allowed list for Table '{table}' — {Fore.RED}{Style.BRIGHT}exiting.{Style.RESET_ALL}")
            exit(1)

    print(f"{Fore.WHITE}Fields and tables have been validated and comply with the allowed guidelines.\n")

def validate_model(model):
    if model not in ALLOWED_MODELS:
        print(f"{Fore.RED}{Style.BRIGHT}ERROR:{Style.RESET_ALL} Model '{model}' is not allowed — {Fore.RED}{Style.BRIGHT}exiting.{Style.RESET_ALL}")
        raise SystemExit(1)
    else:
        print(f"{Fore.LIGHTGREEN_EX}Selected model is valid: {Fore.CYAN}{model}\n{Style.RESET_ALL}")
