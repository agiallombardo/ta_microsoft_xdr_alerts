import import_declare_test

import json
import sys
import os
import datetime
import urllib
import traceback

from splunklib import modularinput as smi
from splunklib import client


GRAPH_ALERTS_URL = 'https://graph.microsoft.com/v1.0/security/alerts_v2'
ACCESS_TOKEN = 'access_token'
CLIENT_ID = 'client_id'
CLIENT_SECRET = 'client_secret'
TENANT = 'tenant'
LOG_DIRECTORY_NAME = 'logs'
TIME_FORMAT = '%Y-%m-%dT%H:%M:%S.000Z'


class MICROSOFT_GRAPH_SECURITY(smi.Script):
    def __init__(self):
        super(MICROSOFT_GRAPH_SECURITY, self).__init__()
        self.session_key = None
        self.app_name = "ta_microsoft_xdr_alerts"
        
    def get_scheme(self):
        scheme = smi.Scheme('microsoft_graph_security')
        scheme.description = 'Microsoft Graph Security'
        scheme.use_external_validation = True
        scheme.streaming_mode_xml = True
        scheme.use_single_instance = False

        scheme.add_argument(
            smi.Argument(
                'name',
                title='Name',
                description='Name',
                required_on_create=True
            )
        )
        scheme.add_argument(
            smi.Argument(
                'tenant',
                title='Azure AD Tenant ID',
                description='Your Azure AD Tenant ID',
                required_on_create=True,
            )
        )
        scheme.add_argument(
            smi.Argument(
                'filter',
                title='OData Filter',
                description='OData filter to apply to the Microsoft Graph Security API queries',
                required_on_create=False,
            )
        )
        scheme.add_argument(
            smi.Argument(
                'app_account',
                title='Account to use',
                description='Account to use for authentication',
                required_on_create=True,
            )
        )
        return scheme

    def validate_input(self, definition: smi.ValidationDefinition):
        # Validate interval
        interval_in_seconds = int(definition.parameters.get('interval', 300))
        if interval_in_seconds < 300:
            raise ValueError("field 'Interval' should be at least 300")
        
        # Validate filter
        filter_arg = definition.parameters.get('filter')
        if filter_arg is not None and 'lastModifiedDateTime' in filter_arg:
            raise ValueError("'lastModifiedDateTime' is a reserved property and cannot be part of the filter")

    def stream_events(self, inputs: smi.InputDefinition, ew: smi.EventWriter):
        # Get session key for later use
        self.session_key = self._input_definition.metadata['session_key']
        
        for input_name, input_item in inputs.inputs.items():
            try:
                # Set up helper object for compatibility
                helper = InputHelper(input_item, input_name, self.session_key, self.app_name)
                
                # Collect events using the helper
                self.collect_events(helper, ew)
                
            except Exception as e:
                ew.log("ERROR", f"Error processing input '{input_name}': {str(e)}")
                ew.log("ERROR", traceback.format_exc())
    
    def collect_events(self, helper, ew):
        """Main function to collect events from Microsoft Graph Security API"""
        try:
            helper.log_debug("Starting event collection")
            access_token = self._get_access_token(helper)
            
            headers = {
                "Authorization": f"Bearer {access_token}",
                "User-Agent": f"MicrosoftGraphSecurity-Splunk/{self._get_app_version(helper)}"
            }
            
            interval_in_seconds = int(helper.get_arg('interval', 300))
            input_name = helper.input_name
            check_point_key = f"{input_name}_is_first_time_collecting_events"
            
            is_first_time_collecting_events = helper.get_check_point(check_point_key)
            
            if is_first_time_collecting_events is None or is_first_time_collecting_events != 'false':
                helper.save_check_point(check_point_key, 'false')
                filter_val = ''
            else:
                now = datetime.datetime.utcnow()
                interval_ago = now - datetime.timedelta(seconds=interval_in_seconds)
                filter_val = f'lastModifiedDateTime gt {interval_ago.strftime(TIME_FORMAT)} and lastModifiedDateTime lt {now.strftime(TIME_FORMAT)}'

            filter_arg = helper.get_arg('filter')
            if filter_arg and filter_arg.strip() and filter_arg != 'null':
                if filter_val:
                    filter_val += ' and '
                filter_val += filter_arg
            
            params = {'$filter': filter_val} if filter_val else {}
            
            helper.log_debug(f"Using filter: {filter_val}")
            
            response = self._send_http_request(GRAPH_ALERTS_URL, "GET", headers=headers, parameters=params)
            
            self._process_response(helper, ew, response, headers)
            
        except Exception as e:
            helper.log_error(f"Error collecting events: {str(e)}")
            helper.log_error(traceback.format_exc())

    def _get_access_token(self, helper):
        """Get access token from Microsoft Graph API"""
        account_name = helper.get_arg('app_account')
        
        # Get account details using REST API
        service = client.connect(
            token=self.session_key,
            app=self.app_name,
            owner='nobody'
        )
        
        account_collection = service.storage_passwords
        for account in account_collection:
            username = account.content.get('username')
            if username and username.startswith(f"{account_name}:"):
                client_id = account.content.get('username').split(':', 1)[1]
                client_secret = account.content.get('clear_password')
                break
        else:
            raise ValueError(f"Account '{account_name}' not found")
        
        tenant = helper.get_arg('tenant')

        _data = {
            CLIENT_ID: client_id,
            'scope': 'https://graph.microsoft.com/.default',
            CLIENT_SECRET: client_secret,
            'grant_type': 'client_credentials'
        }
        
        _url = f'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token'
        
        if (sys.version_info > (3, 0)):
            # Python 3
            import urllib.parse
            payload = urllib.parse.urlencode(_data)
        else:
            return

    def _get_app_version(self, helper):
        """Get the app version from Splunk"""
        app_version = ""
        try:
            service = client.connect(
                token=self.session_key,
                app=self.app_name,
                owner='nobody'
            )
            app_info = service.apps[self.app_name]
            app_version = app_info.content.get('version', '')
        except Exception as e:
            helper.log_error(f"Error getting app version: {str(e)}")
        
        return app_version

    def _send_http_request(self, url, method, parameters=None, payload=None, headers=None):
        """Send HTTP request and return response"""
        import requests
        
        # Configure proxy if set in Splunk
        proxies = None
        # Logic to get proxy settings would go here
        
        if parameters:
            from urllib.parse import urlencode
            url = f"{url}?{urlencode(parameters)}"
            
        try:
            response = requests.request(
                method,
                url,
                data=payload,
                headers=headers,
                proxies=proxies,
                timeout=30,
                verify=True
            )
            
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            raise Exception(f"HTTP Request Error: {str(e)}")

    def _process_response(self, helper, ew, response, headers):
        """Process the API response and write events"""
        if "error" in response:
            account = helper.get_arg('app_account')
            helper.log_error(f"Error occurred: {json.dumps(response, indent=4)}")
            raise ValueError(f"Error from Microsoft Graph API: {response.get('error', {}).get('message', 'Unknown error')}")
        
        alerts = []
        if isinstance(response.get('value'), dict):
            alerts.append(response['value'])
        elif isinstance(response.get('value'), list):
            alerts.extend(response['value'])
        
        self._remove_nulls(alerts)
        self._write_events(helper, ew, alerts)
        
        # Handle pagination
        next_link = response.get("@odata.nextLink")
        while next_link and self._is_https(next_link):
            helper.log_debug(f"Getting next page: {next_link}")
            
            response = self._send_http_request(next_link, "GET", headers=headers)
            
            alerts = []
            if isinstance(response.get('value'), dict):
                alerts.append(response['value'])
            elif isinstance(response.get('value'), list):
                alerts.extend(response['value'])
            
            self._remove_nulls(alerts)
            self._write_events(helper, ew, alerts)
            
            next_link = response.get("@odata.nextLink")

    def _write_events(self, helper, ew, alerts=None):
        """Write events to Splunk"""
        if not alerts:
            return
            
        for alert in alerts:
            event = smi.Event(
                data=json.dumps(alert),
                source=helper.get_arg('name'),
                index=helper.get_arg('index', 'default'),
                sourcetype='GraphSecurityAlert:v2',
            )
            ew.write_event(event)

    def _is_https(self, url):
        """Check if URL is https"""
        return url.startswith("https://")

    def _remove_nulls(self, d):
        """Function to remove all null or empty values from the JSON response."""
        if isinstance(d, dict):
            for k, v in list(d.items()):
                if v is None or v == '' or v == []:
                    del d[k]
                else:
                    self._remove_nulls(v)
        elif isinstance(d, list):
            for v in d:
                self._remove_nulls(v)
        return d


class InputHelper:
    """Helper class to provide compatibility with the UCC input helper interface"""
    
    def __init__(self, input_item, input_name, session_key, app_name):
        self.input_item = input_item
        self.input_name = input_name
        self.session_key = session_key
        self.app_name = app_name
        
        # Set up checkpoint directory
        self.checkpoint_dir = self._get_checkpoint_dir()
        
    def get_arg(self, arg_name, default=None):
        """Get argument value from input"""
        return self.input_item.get(arg_name, default)
    
    def get_output_index(self):
        """Get output index"""
        return self.get_arg('index', 'default')
    
    def get_input_type(self):
        """Get input type"""
        return 'microsoft_graph_security'
    
    def get_sourcetype(self):
        """Get sourcetype"""
        return 'GraphSecurityAlert:v2'
    
    def log_debug(self, message):
        """Log debug message"""
        print(f"DEBUG: {message}", file=sys.stderr)
    
    def log_info(self, message):
        """Log info message"""
        print(f"INFO: {message}", file=sys.stderr)
    
    def log_warning(self, message):
        """Log warning message"""
        print(f"WARNING: {message}", file=sys.stderr)
    
    def log_error(self, message):
        """Log error message"""
        print(f"ERROR: {message}", file=sys.stderr)
    
    def _get_checkpoint_dir(self):
        """Get checkpoint directory"""
        import os
        checkpoint_dir = os.path.join(os.environ.get('SPLUNK_HOME', ''), 'var', 'lib', 'splunk', 'modinputs', 'ta_microsoft_xdr_alerts')
        os.makedirs(checkpoint_dir, exist_ok=True)
        return checkpoint_dir
    
    def get_check_point(self, key):
        """Get checkpoint value"""
        checkpoint_file = os.path.join(self.checkpoint_dir, key)
        
        if os.path.exists(checkpoint_file):
            with open(checkpoint_file, 'r') as f:
                return f.read().strip()
        return None
    
    def save_check_point(self, key, value):
        """Save checkpoint value"""
        checkpoint_file = os.path.join(self.checkpoint_dir, key)
        
        with open(checkpoint_file, 'w') as f:
            f.write(str(value))


if __name__ == '__main__':
    exit_code = MICROSOFT_GRAPH_SECURITY().run(sys.argv)
    sys.exit(exit_code)