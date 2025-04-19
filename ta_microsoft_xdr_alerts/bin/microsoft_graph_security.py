import import_declare_test

import json
import sys
import os
import datetime
import urllib
import traceback
import time
from solnlib import conf_manager
from splunklib import client
from splunklib import modularinput as smi

GRAPH_ALERTS_URL = 'https://graph.microsoft.com/v1.0/security/alerts_v2'
ACCESS_TOKEN = 'access_token'
CLIENT_ID = 'client_id'
CLIENT_SECRET = 'client_secret'
TENANT = 'tenant'
TIME_FORMAT = '%Y-%m-%dT%H:%M:%S.000Z'
REQTIMEOUT = 30
APP_NAME = __file__.split(os.path.sep)[-3]
ACCOUNT_CONFIG_FILE = "ta_microsoft_xdr_alerts_account"
SETTINGS_CONFIG_FILE = "ta_microsoft_xdr_alerts_settings"


class MICROSOFT_GRAPH_SECURITY(smi.Script):
    def __init__(self):
        super(MICROSOFT_GRAPH_SECURITY, self).__init__()
        self._session_key = None
        self._logfile_prefix = "microsoft_graph_security_input"
        self.logger = None
        self._checkpoint_data = {}
        self._source = "MicrosoftGraphSecurity"
        self._sourcetype = "GraphSecurityAlert:V2"
        self._index = None
        self._global_account = None
        self._input_name = None
        self._eventhost = None
        
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

    def _set_logger(self, session_key, input_name):
        """Set Logger Instance"""
        try:
            from solnlib import log
            logger = log.Logs().get_logger(f"{self._logfile_prefix}-{input_name}")
            log_level = conf_manager.get_log_level(
                logger=logger,
                session_key=session_key,
                app_name=APP_NAME,
                conf_name=SETTINGS_CONFIG_FILE,
                default_log_level="INFO",
            )
            logger.setLevel(log_level)
            logger.info(f"log level set is: {log_level}")
            return logger
        except Exception as e:
            print(f"Failed to initialize logger: {str(e)}", file=sys.stderr)
            sys.exit(1)

    def stream_events(self, inputs: smi.InputDefinition, ew: smi.EventWriter):
        self._session_key = self._input_definition.metadata['session_key']
        
        # Get input parameters
        for input_name, input_item in inputs.inputs.items():
            try:
                self._input_name = input_name
                self._index = input_item.get('index', 'default')
                self._global_account = input_item.get('app_account')
                tenant = input_item.get('tenant')
                filter_arg = input_item.get('filter')
                
                # Set up logger
                self.logger = self._set_logger(self._session_key, self._input_name)
                self.logger.info(f"Starting data collection for input: {self._input_name}")
                
                # Set host information
                account_config = self._get_account_config(self._global_account)
                self._eventhost = account_config.get('endpoint', account_config.get('domain', 'microsoft.graph'))
                
                # Calculate time window
                interval_in_seconds = int(input_item.get('interval', 300))
                now = datetime.datetime.utcnow()
                interval_ago = now - datetime.timedelta(seconds=interval_in_seconds)
                
                # Create checkpoint key
                checkpoint_key = f"{self._input_name}_last_run"
                
                # Get last run time from checkpoint or use interval ago
                last_run_time = self._get_checkpoint(checkpoint_key)
                if not last_run_time:
                    self.logger.info("First time running, using interval time window")
                    last_run_time = interval_ago.strftime(TIME_FORMAT)
                
                # Create filter based on time window
                time_filter = f'lastModifiedDateTime gt {last_run_time} and lastModifiedDateTime lt {now.strftime(TIME_FORMAT)}'
                
                # Combine with user filter if provided
                if filter_arg and filter_arg.strip() and filter_arg != 'null':
                    combined_filter = f"{time_filter} and {filter_arg}"
                else:
                    combined_filter = time_filter
                
                # Collect events
                self.logger.debug(f"Using filter: {combined_filter}")
                self._collect_events(tenant, combined_filter, account_config, ew)
                
                # Update checkpoint
                self._set_checkpoint(checkpoint_key, now.strftime(TIME_FORMAT))
                
                self.logger.info(f"Data collection completed for input: {self._input_name}")
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Error processing input '{input_name}': {str(e)}")
                    self.logger.error(traceback.format_exc())
                else:
                    print(f"ERROR: Error processing input '{input_name}': {str(e)}", file=sys.stderr)
                    print(f"ERROR: {traceback.format_exc()}", file=sys.stderr)

    def _get_account_config(self, account_name):
        """Get account configuration from splunk"""
        try:
            cfm = conf_manager.ConfManager(
                self._session_key,
                APP_NAME,
                realm=f"__REST_CREDENTIAL__#{APP_NAME}#configs/conf-{ACCOUNT_CONFIG_FILE}",
            )
            
            account_config_file = cfm.get_conf(ACCOUNT_CONFIG_FILE)
            account_config = account_config_file.get(account_name)
            
            if not account_config:
                msg = f"Account '{account_name}' not found in configuration"
                if self.logger:
                    self.logger.error(msg)
                else:
                    print(f"ERROR: {msg}", file=sys.stderr)
                raise ValueError(msg)
                
            return account_config
        except Exception as e:
            msg = f"Error getting account configuration: {str(e)}"
            if self.logger:
                self.logger.error(msg)
                self.logger.error(traceback.format_exc())
            else:
                print(f"ERROR: {msg}", file=sys.stderr)
                print(f"ERROR: {traceback.format_exc()}", file=sys.stderr)
            raise

    def _get_proxy_settings(self):
        """Get proxy settings from configuration"""
        try:
            settings_cfm = conf_manager.ConfManager(
                self._session_key,
                APP_NAME,
                realm=f"__REST_CREDENTIAL__#{APP_NAME}#configs/conf-{SETTINGS_CONFIG_FILE}",
            )
            
            settings_conf = settings_cfm.get_conf(SETTINGS_CONFIG_FILE).get_all()
            
            proxy_settings = {}
            proxy_stanza = {}
            for k, v in settings_conf.get("proxy", {}).items():
                proxy_stanza[k] = v

            if not proxy_stanza or int(proxy_stanza.get("proxy_enabled", 0)) == 0:
                self.logger.info("Proxy is disabled. Returning None")
                return proxy_settings
                
            proxy_type = proxy_stanza.get("proxy_type", "http")
            proxy_port = proxy_stanza.get("proxy_port")
            proxy_url = proxy_stanza.get("proxy_url")
            proxy_username = proxy_stanza.get("proxy_username", "")
            proxy_password = proxy_stanza.get("proxy_password", "")

            if proxy_username and proxy_password:
                from urllib import parse
                proxy_username = parse.quote_plus(proxy_username)
                proxy_password = parse.quote_plus(proxy_password)
                proxy_uri = "{}://{}:{}@{}:{}".format(
                    proxy_type, proxy_username, proxy_password, proxy_url, proxy_port
                )
            else:
                proxy_uri = "{}://{}:{}".format(proxy_type, proxy_url, proxy_port)

            proxy_settings = {"http": proxy_uri, "https": proxy_uri}
            self.logger.info("Successfully fetched configured proxy details.")
            return proxy_settings
        except Exception as e:
            self.logger.error(f"Failed to fetch proxy details: {str(e)}")
            self.logger.error(traceback.format_exc())
            return {}

    def _get_access_token(self, tenant, account_config):
        """Get access token from Microsoft Graph API"""
        self.logger.debug("Getting access token")
        auth_type = account_config.get("auth_type", "basic")
        
        if auth_type.lower() == "oauth":
            # OAuth authentication
            client_id = account_config.get("client_id")
            client_secret = account_config.get("client_secret")
            access_token = account_config.get("access_token")
            refresh_token = account_config.get("refresh_token")
            
            # Check if token needs refresh
            if not access_token:
                self.logger.info("No access token found, attempting to refresh")
                access_token = self._refresh_token(tenant, client_id, client_secret, refresh_token)
            
            return access_token
        else:
            # Basic authentication (API key)
            client_id = account_config.get("username")
            client_secret = account_config.get("password")
            
            # Get token
            _data = {
                CLIENT_ID: client_id,
                'scope': 'https://graph.microsoft.com/.default',
                CLIENT_SECRET: client_secret,
                'grant_type': 'client_credentials'
            }
            
            _url = f'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token'
            
            if sys.version_info > (3, 0):
                import urllib.parse
                payload = urllib.parse.urlencode(_data)
            else:
                import urllib
                payload = urllib.urlencode(_data)
            
            headers = {'Content-Type': 'application/x-www-form-urlencoded'}
            proxies = self._get_proxy_settings()
            
            import requests
            try:
                response = requests.post(
                    _url,
                    headers=headers,
                    data=payload,
                    proxies=proxies,
                    timeout=REQTIMEOUT
                )
                response.raise_for_status()
                token_data = response.json()
                return token_data.get(ACCESS_TOKEN)
            except Exception as e:
                self.logger.error(f"Error getting access token: {str(e)}")
                self.logger.error(traceback.format_exc())
                raise

    def _refresh_token(self, tenant, client_id, client_secret, refresh_token):
        """Refresh OAuth token"""
        import requests
        import base64
        
        self.logger.info("Refreshing OAuth token")
        
        url = f'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token'
        payload = f'grant_type=refresh_token&refresh_token={refresh_token}'
        auth_value = base64.urlsafe_b64encode(
            f"{client_id}:{client_secret}".encode("utf-8").strip()
        ).decode()
        
        headers = {
            "Accept": "application/json",
            "Authorization": f"Basic {auth_value}",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        
        proxies = self._get_proxy_settings()
        
        try:
            response = requests.post(
                url, 
                headers=headers, 
                data=payload, 
                proxies=proxies, 
                timeout=REQTIMEOUT
            )
            response.raise_for_status()
            
            content = response.json()
            access_token = content.get("access_token")
            new_refresh_token = content.get("refresh_token")
            
            # Update the tokens in the configuration
            self._update_tokens(self._global_account, access_token, new_refresh_token, client_secret)
            
            return access_token
        except Exception as e:
            self.logger.error(f"Error refreshing token: {str(e)}")
            self.logger.error(traceback.format_exc())
            raise

    def _update_tokens(self, account_name, access_token, refresh_token, client_secret):
        """Update access and refresh tokens in account configuration"""
        try:
            fields = {
                "access_token": str(access_token),
                "refresh_token": str(refresh_token),
                "client_secret": str(client_secret),
            }
            
            cfm = conf_manager.ConfManager(
                self._session_key,
                APP_NAME,
                realm=f"__REST_CREDENTIAL__#{APP_NAME}#configs/conf-{ACCOUNT_CONFIG_FILE}",
            )
            conf = cfm.get_conf(ACCOUNT_CONFIG_FILE)
            conf.update(account_name, fields, fields.keys())
            
            self.logger.info(f"Updated account '{account_name}' with new access and refresh tokens")
            return True
        except Exception as e:
            self.logger.error(f"Error updating tokens: {str(e)}")
            self.logger.error(traceback.format_exc())
            return False

    def _get_app_version(self):
        """Get the app version from Splunk"""
        app_version = ""
        try:
            service = client.connect(
                token=self._session_key,
                app=APP_NAME,
                owner='nobody'
            )
            app_info = service.apps[APP_NAME]
            app_version = app_info.content.get('version', '')
        except Exception as e:
            self.logger.error(f"Error getting app version: {str(e)}")
        
        return app_version

    def _collect_events(self, tenant, filter_val, account_config, ew):
        """Collect events from Microsoft Graph Security API"""
        try:
            # Get access token
            access_token = self._get_access_token(tenant, account_config)
            if not access_token:
                self.logger.error("Failed to get access token")
                return
            
            # Build headers
            headers = {
                "Authorization": f"Bearer {access_token}",
                "User-Agent": f"MicrosoftGraphSecurity-Splunk/{self._get_app_version()}",
                "Accept": "application/json"
            }
            
            # Get proxy settings
            proxies = self._get_proxy_settings()
            
            # Build URL and params
            url = GRAPH_ALERTS_URL
            params = {'$filter': filter_val} if filter_val else {}
            
            # Request data
            processed_events = 0
            has_more = True
            
            while has_more:
                self.logger.debug(f"Making request to {url} with params {params}")
                import requests
                response = requests.get(
                    url,
                    headers=headers,
                    params=params,
                    proxies=proxies,
                    timeout=REQTIMEOUT
                )
                
                if response.status_code != 200:
                    self.logger.error(f"API request failed with status {response.status_code}: {response.text}")
                    if response.status_code in (401, 403):
                        # Token might be expired, try to refresh and retry once
                        self.logger.info("Authentication error, attempting to refresh token and retry")
                        access_token = self._get_access_token(tenant, account_config)
                        headers["Authorization"] = f"Bearer {access_token}"
                        
                        # Retry the request
                        response = requests.get(
                            url,
                            headers=headers,
                            params=params,
                            proxies=proxies,
                            timeout=REQTIMEOUT
                        )
                        
                        if response.status_code != 200:
                            self.logger.error(f"Retry failed with status {response.status_code}: {response.text}")
                            break
                    else:
                        break
                
                data = response.json()
                alerts = data.get('value', [])
                
                # Process alerts
                if not alerts:
                    self.logger.info("No alerts found")
                else:
                    for alert in alerts:
                        # Remove empty/null values
                        self._remove_nulls(alert)
                        
                        # Create and write event
                        event = smi.Event(
                            data=json.dumps(alert),
                            source=self._input_name,
                            index=self._index,
                            sourcetype=self._sourcetype,
                            host=self._eventhost
                        )
                        ew.write_event(event)
                        processed_events += 1
                
                # Check for more pages
                if '@odata.nextLink' in data:
                    url = data['@odata.nextLink']
                    params = None  # params are included in the nextLink URL
                else:
                    has_more = False
            
            self.logger.info(f"Processed {processed_events} alerts")
            
        except Exception as e:
            self.logger.error(f"Error collecting events: {str(e)}")
            self.logger.error(traceback.format_exc())

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

    def _get_checkpoint(self, key):
        """Get checkpoint from KV Store"""
        try:
            service = client.connect(
                token=self._session_key,
                app=APP_NAME
            )
            
            # Check if collection exists
            collection_name = f"{APP_NAME}_checkpoints"
            if collection_name not in service.kvstore:
                self.logger.info(f"Creating checkpoint collection: {collection_name}")
                service.kvstore.create(collection_name)
            
            # Get KV Store collection
            collection = service.kvstore[collection_name]
            
            # Try to get checkpoint
            try:
                response = collection.data.query(query=json.dumps({"_key": key}))
                if response and len(response) > 0:
                    return response[0].get("value")
            except Exception as e:
                self.logger.debug(f"Checkpoint not found: {str(e)}")
            
            return None
        except Exception as e:
            self.logger.error(f"Error getting checkpoint: {str(e)}")
            return None

    def _set_checkpoint(self, key, value):
        """Set checkpoint in KV Store"""
        try:
            service = client.connect(
                token=self._session_key,
                app=APP_NAME
            )
            
            # Check if collection exists
            collection_name = f"{APP_NAME}_checkpoints"
            if collection_name not in service.kvstore:
                self.logger.info(f"Creating checkpoint collection: {collection_name}")
                service.kvstore.create(collection_name)
            
            # Get KV Store collection
            collection = service.kvstore[collection_name]
            
            # Update or insert checkpoint
            checkpoint_data = {"_key": key, "value": value}
            try:
                # Try to update existing record
                collection.data.query_by_id(key)
                collection.data.update(key, json.dumps(checkpoint_data))
                self.logger.debug(f"Updated checkpoint {key} with value {value}")
            except Exception:
                # Record doesn't exist, create it
                collection.data.insert(json.dumps(checkpoint_data))
                self.logger.debug(f"Created checkpoint {key} with value {value}")
            
            return True
        except Exception as e:
            self.logger.error(f"Error setting checkpoint: {str(e)}")
            return False


if __name__ == "__main__":
    exit_code = MICROSOFT_GRAPH_SECURITY().run(sys.argv)
    sys.exit(exit_code)
