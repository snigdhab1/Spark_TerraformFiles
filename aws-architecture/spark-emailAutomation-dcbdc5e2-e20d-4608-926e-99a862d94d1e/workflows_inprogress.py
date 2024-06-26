
import re
import sys
import os
from os.path import join
import requests
import datetime
from configparser import ConfigParser
import json
import psycopg2
from utils import load_config, load_prompts, load_prompts_acc, junk_bypass_cases, load_prompts_response42
from spark_rds import RDSManager
import logging
import boto3
from botocore.exceptions import ClientError
from anthropic import AnthropicBedrock
from requests.auth import HTTPBasicAuth
import base64

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Set up logging to file
file_handler = logging.FileHandler('/tmp/ticket_handling.log')
file_handler.setLevel(logging.INFO)
file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(file_formatter)
logger.addHandler(file_handler)

# Add a handler to write logs to the console
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)  # Change this to logging.DEBUG if you want to see DEBUG level logs
console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(console_formatter)
logger.addHandler(console_handler)



class EmailAutomation:
    def __init__(self):
        self.CONFIG = load_config()
        self.system_message = load_prompts()
        self.acc_subcategory_prompt = load_prompts_acc()
        self.response_prompt42 = load_prompts_response42("response_prompt42")
        ## Bedrock Parameters        
        self.modelId = self.CONFIG['AWS_bedrockresources']['modelId']
        self.max_tokens = int(self.CONFIG['AWS_bedrockresources']['max_tokens'])
        self.temperature = float(self.CONFIG['AWS_bedrockresources']['temperature'])
        self.bedrock = boto3.client(service_name=self.CONFIG['AWS_bedrock']['service_name'],
                               region_name=self.CONFIG['AWS_bedrock']['region_name'])
        ## Zendesk parameters
        self.service_id = self.CONFIG["zendesk"]["service_id"]
        self.region_name = self.CONFIG["zendesk"]["region_name"]
        self.zendesksecrets = self.get_secret(self.service_id, self.region_name)
        self.subdomain = self.zendesksecrets["subdomain"]
        self.username = self.zendesksecrets["username"]
        self.password = self.zendesksecrets["password"]
        self.subdomain_sandbox = self.zendesksecrets["subdomain_sandbox"]
        self.password_sandbox = self.zendesksecrets["password_sandbox"]
        self.zendeskadminURL = self.zendesksecrets["zendeskadminURL"]
        self.password_zendeskadmin = self.zendesksecrets["password_zendeskadmin"]
        self.zoosksearchURL = self.zendesksecrets["zoosksearchURL"]
        ## Zendesk Prod cred
        self.zendesk_APItoken = self.zendesksecrets["zendesk_APItoken"]
        credentials = f"{self.username}/token:{self.zendesk_APItoken}"
        self.encoded_credentials = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')
        ## Zendesk sandbox cred
        self.zendesk_APItoken_sandbox = self.zendesksecrets["zendesk_APItoken_sandbox"]
        credentials_sandbox = f"{self.username}/token:{self.zendesk_APItoken_sandbox}"
        self.encoded_credentials_sandbox = base64.b64encode(credentials_sandbox.encode('utf-8')).decode('utf-8')
        ## Test flag
        self.test_flag = self.CONFIG["zendesk"]["test"]
        self.base_url = f'https://{self.subdomain}.zendesk.com'
        self.base_url_sandbox = f'https://{self.subdomain_sandbox}.zendesk.com'

        ## RDS dependencies
        self.rds_manager = RDSManager()


    def get_secret(self, service_id, region_name):
        # Create a Secrets Manager client
        session = boto3.session.Session()
        client = session.client(
            service_name='secretsmanager',
            region_name=region_name
        )
        try:
            get_secret_value_response = client.get_secret_value(
                SecretId=service_id
            )
        except ClientError as e:
            logger.error("Error: %s", e)
            raise e
        secrets = get_secret_value_response['SecretString']
        return json.loads(secrets)

    def generate_response_claude(self, bedrock_runtime, model_id, system_prompt, messages):
        body=json.dumps(
            {
                "anthropic_version": self.CONFIG['AWS_bedrockresources']['anthropic_version'],
                "max_tokens": self.max_tokens,
                "system": system_prompt,
                "messages": messages,
                "temperature": self.temperature
            }  
        )
        
        contentType = "application/json"
        accept = "application/json"
        trace=self.CONFIG['AWS_bedrockresources']['trace'],
        guardrailIdentifier = self.CONFIG['AWS_bedrockresources']['guardrailIdentifier']
        guardrailVersion = self.CONFIG['AWS_bedrockresources']['guardrailVersion']
        response = bedrock_runtime.invoke_model(body=body, modelId=model_id, accept=accept, contentType=contentType,
            guardrailIdentifier=guardrailIdentifier,guardrailVersion=guardrailVersion
        )
        response_body = json.loads(response.get('body').read())
        return response_body

    def parse_claude_response(self, response_ai):
        ticket_resp2 = response_ai['content'][0]['text']
        start_idx = ticket_resp2.find('{')
        end_idx = ticket_resp2.rfind('}')
        # Extract the content between '{' and '}'
        ticket_resp3 = json.loads(ticket_resp2[start_idx:end_idx+1])
        return ticket_resp3

    def check_keywords(self, text):
        keywords = self.CONFIG['CCPAparameters']['keywords']
        for keyword in keywords:
            if keyword.lower() in text.lower():
                return True
        return False

    def email_classification(self, query):
        messages = [
                {"role": "user", "content": f"Please classify the following email query and return the reponse in JSON format: {query}."},
                {"role": "assistant", "content": "json"} ]

        # Instantiate bedrock client
        try:
            response_ai = self.generate_response_claude(self.bedrock, self.modelId, self.system_message, messages)
            ticket_resp3 = self.parse_claude_response(response_ai)
            return ticket_resp3
        except requests.exceptions.HTTPError as err:
            return f"HTTP error occurred: {err}"
        except Exception as err:
            return f"An error occurred: {err}"


    def response_refining(self, query):
        messages = [
                    {"role": "user", "content": f"Personalize the following email response and return the reponse in json format: {query}."},
                    {"role": "assistant", "content": "json"} ]
        try:
            response_ai = self.generate_response_claude(self.bedrock, self.modelId, self.response_prompt42, messages)
            print(response_ai)
            ticket_resp3 = self.parse_claude_response(response_ai)
            return ticket_resp3
        except requests.exceptions.HTTPError as err:
            return f"HTTP error occurred: {err}"
        except Exception as err:
            return f"An error occurred: {err}"


    def account_validation(self, emails, phones):
        # URL for the API endpoint
        # Request body parameters
        data = {
            'email': self.username,
            'password': self.password_zendeskadmin
        }
        # Make the POST request
        response1 = requests.post(self.zendeskadminURL, data=data)

        # Process the response
        if response1.status_code == 200:
            # Request was successful
            # Extract the cookies
            za = response1.cookies.get('za')
            zs = response1.cookies.get('zs')
            # Print or use the cookies as needed

            print(response1.text)
            user_get_url_template = self.zoosksearchURL
            if za and zs:
                # URL for the user/get API endpoint
                # Parameters for the user/get request
                print("Za and zs token fetched successfully")
                logger.info("Za and zs token fetched successfully")
            else:
                # 'za' or 'zs' cookie is missing
                logger.error("Unable to fetch zs and za tokens")
                sys.exit(1)

            # Reponse for all emails in list should be null
            user_data_list=[]
            for email in emails:
                # Replace placeholders with actual values
                user_get_url = user_get_url_template.format(email, za, zs)
                print(email)
                # Make the user/get GET request
                user_get_response = requests.get(user_get_url)
                # Make the user/get GET request
                # user_get_response = requests.get(user_get_url, params=user_get_params)
                if user_get_response.status_code == 200:
                    # Request was successful
                    user_data = user_get_response.json()
                    # Process the user data as needed
                    print(user_data)
                    user_data_list.append(user_data)
                else:
                    # Request failed
                    print('Failed to fetch user data:', user_get_response.status_code, user_get_response.text)
            acc_found = any(response['response']['info']['type'] != 'error' for response in user_data_list)
            if acc_found:
                return False
            else:
                return True
        else:
            # Request failed
            print('Failed to fetch data:', response1.status_code, response1.text)
        return False


    def validation_42cr(self, text):
        ## Extracting all emails and phone numbers from the text
        email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
        emails = re.findall(email_pattern, text)
        emails = list(set(emails))
        emails = [email for email in emails if email != self.CONFIG['CCPAparameters']['sender']]
        mobile_pattern = r"\b\d{10}\b"
        phone_pattern = r'\+\d{11}'
        phone1 = re.findall(mobile_pattern, text)
        phone2 = re.findall(phone_pattern, text)
        phone1.extend(phone2)
        phone1 = list(set(phone1))
        ## Email Validation through API
        # try:
        #     # If any account is found for any email in list of emails then account_status=False
        #     account_status = self.account_validation(emails, phone1)
        # except ConnectionError as e:
        #     print('Connection error:', e)
        #     print("Re-trying validation...")
        #     account_status = self.account_validation(emails, phone1) 
        account_status=True
        return account_status, emails


    def get_response_from_rds(self, table, num):
        num = str(num)
        rds_manager = RDSManager()
        response = rds_manager.get_response(table, num)
        rds_manager.close_connection
        return response
    

    def add_ticket_response(self, ticketid, ticket_response, classification, url_ticket, headers):
        # response, url_ticket, headers = self.automation_mode(ticketid)
        endnote = load_prompts_response42("ccpa_endnote")
        if classification == "Account Related Issue/request":
            ticket_response = ticket_response + "\n\n" + endnote
            data = {
                "ticket": {
                    "comment": {
                        "body": ticket_response,
                        "public": "false"
                    },
                    "status": "new",
                    "tags": ['Automation_classification','CCPA_request']
                }
            }
        elif classification == "Junk":
            data = {
                "ticket": {
                    "comment": {
                        "body": ticket_response,
                        "public": "false"
                    },
                    "status": "new",
                    "tags": ['Automation_classification','Junk']
                }
            }
        # elif classification == "No Phone Support":
        #     if ticket_response==False:
        #         data = {
        #         "ticket": {
        #             "status": "new",
        #             "tags": ['Automation_classification','Other case', 'non-automation workflow']
        #         }
        #     }
        #     else:
        #         ticket_response = ticket_response + "\n\n" + endnote
        #         data = {
        #             "ticket": {
        #                 "comment": {
        #                     "body": ticket_response,
        #                     "public": "false"
        #                 },
        #                 "status": "new",
        #                 "tags": ['Automation_classification','No Phone Support']
        #             }
        #         }
        else:
            data = {
                "ticket": {
                    "status": "new",
                    "tags": ['Automation_classification','Other case', 'non-automation workflow']
                }
            }
        try:
            if self.test_flag:
                response = requests.put(url_ticket, headers=headers, json=data, auth=(self.username, self.password_sandbox))
                if response.status_code == 200:
                    logger.info("Ticket response updated successfully for %s ticket Id", str(ticketid))
                    return "Ticket response updated successfully"
            else:
                response = requests.put(url_ticket, headers=headers, json=data, auth=(self.username, self.password))
                if response.status_code == 200:
                    logger.info("Ticket response updated successfully for %s ticket Id", str(ticketid))
                    return "Ticket response updated successfully"
        except Exception as err:
            logger.error("Error: Failed to update ticket  %s  Response: %s", ticketid, err)
            return f"An error occurred: Ticket response update Failed: {err}"


    def is_zoosk_ticket(self, ticket_resp):
        brand_id = ticket_resp['ticket']['brand_id']
        if self.test_flag:
            headers = {
                'Authorization': f'Basic {self.encoded_credentials_sandbox}',
                'Content-Type': 'application/json'
            }
            brand_url = self.base_url_sandbox + self.CONFIG['zendeskAPIs']['brand_api'].format(brand_id=brand_id)
            # response_brand = requests.get(brand_url, auth=(self.username, self.password_sandbox), headers=headers)
            response_brand = requests.get(brand_url, headers=headers)
        else:
            brand_url = self.base_url + self.CONFIG['zendeskAPIs']['brand_api'].format(brand_id=brand_id)
            headers = {
                'Authorization': f'Basic {self.encoded_credentials}',
                'Content-Type': 'application/json'
            }
            # Make the GET request
            response_brand = requests.get(brand_url, headers=headers)
        if response_brand.status_code == 200:
            brand_info = response_brand.json()['brand']
            # Extract the brand name
            brand_name = brand_info.get('name')
            brand_name = brand_name.split(' ')[0]
            print("=====>", brand_name)
            if brand_name=='Zoosk':
                return True
        else:
            print("Error fetching Brand details:", response_brand.status_code, response_brand.text)
            logger.error("Error in fetching Brand name details: %s, %s", response_brand.status_code, response_brand.text)
            return False



    def response_no_phone_support(self, ticket_resp):
        requester_id = ticket_resp['ticket']['requester_id']
        if self.is_zoosk_ticket(ticket_resp):
            if self.test_flag:
                user_url = self.base_url_sandbox + self.CONFIG['zendeskAPIs']['user_api'].format(requester_id=requester_id)
                # user_url = f"https://{self.subdomain_sandbox}.zendesk.com/api/v2/users/{requester_id}.json"
                headers = {
                    'Authorization': f'Basic {self.encoded_credentials_sandbox}',
                    'Content-Type': 'application/json'
                }
                # user_response = requests.get(user_url, auth=(self.username, self.password_sandbox), headers=headers)
                user_response = requests.get(user_url, headers=headers)
            else:
                user_url = self.base_url + self.CONFIG['zendeskAPIs']['user_api'].format(requester_id=requester_id)
                # user_url = f"https://{self.subdomain}.zendesk.com/api/v2/users/{requester_id}.json"
                headers = {
                    'Authorization': f'Basic {self.encoded_credentials}',
                    'Content-Type': 'application/json'
                }
                user_response = requests.get(user_url, headers=headers)
            if user_response.status_code == 200:
                user = user_response.json()['user']
                sender_name = user['name']
                sender_name_first = sender_name.split(" ")[0]
                print("Sender Name:", sender_name)
            else:
                print("Error fetching user details:", user_response.status_code, user_response.text)
                logger.error("Error in fetching sender name details: %s, %s", user_response.status_code, user_response.text)
            response_content = self.get_response_from_rds(self.CONFIG['databaseparameters']['table'], 446)
            resp = self.response_refining(response_content)
            print(resp)
            if "error" in resp:
                logger.error("Error in response refining: %s", resp)
                sys.exit(1)
            # Load JSON string
            resp_446 = json.dumps(resp, indent=4)
            resp_446 = json.loads(resp_446)

            # Pretty print the response
            text_with_names = resp_446['personalized_response'].replace('[[[ticket.requester.first_name]]]', "")
            text_with_names = text_with_names.replace(", .", ".\n\n")
            text_with_names = f"Hi {sender_name_first},\n\n" + text_with_names
            print(text_with_names)
            return text_with_names
        else:
            logger.info("Not a Zoosk Ticket")
            return False




    def automation_mode(self, ticketid):
        if self.test_flag:
            print("Testing mode: sandox cases")
            url_ticket = self.base_url_sandbox + self.CONFIG['zendeskAPIs']['ticket_api'].format(ticketid=ticketid)
            logger.info("Info: Processing started for %s ticket Id", str(ticketid))
            headers = {
                'Authorization': f'Basic {self.encoded_credentials_sandbox}',
                'Content-Type': 'application/json'
            }
            # response = requests.get(url_ticket, auth=(self.username, self.password_sandbox), headers=headers)
            response = requests.get(url_ticket, headers=headers)
        else:
            print("Production Mode")
            headers = {
                'Authorization': f'Basic {self.encoded_credentials}',
                'Content-Type': 'application/json'
            }
            url_ticket = self.base_url + self.CONFIG['zendeskAPIs']['ticket_api'].format(ticketid=ticketid)
            response = requests.get(url_ticket, headers=headers)
            logger.info("Info: Processing started for %s ticket Id", str(ticketid))
        return response, url_ticket, headers




    def automation_workflow(self, ticketid):
        print(ticketid)
        response, url_ticket, headers = self.automation_mode(ticketid)
        ## check status of ticket url response
        if response.status_code == 200:
            ticket_resp = response.json()
            text = ticket_resp['ticket']['description']
            # query = clean_ticket(text)
            ticket_resp1 = self.email_classification(text)
            if "error" in ticket_resp1:
                print("Error:", ticket_resp1)
                logger.error("Error: %s", ticket_resp1)
                sys.exit(1)
            # ticket_resp2 = json.loads(ticket_resp1)
            ticket_resp['ticket'].update(ticket_resp1)
            print(ticket_resp)
            ticket_classification = ticket_resp1['Classification']
            print('===>', ticket_classification)
            match = self.check_keywords(ticket_resp['ticket']['description'])
            print(match)
            # if (ticket_classification== "Account Related Issue/request" and ticket_resp['ticket']['via']['source']['from']['address'] == CONFIG['CCPAparameters']['sender']) | (ticket_classification== "Account Related Issue/request" and match):   
            if ticket_classification== "Account Related Issue/request" and match:
            # if match:
                account_status, emails = self.validation_42cr(text)
                print(emails)
                if account_status:
                    response_content = self.get_response_from_rds(self.CONFIG['databaseparameters']['table'], 42)
                    # print("Response from RDS:", response_content)
                    # print("Macro 42")
                    resp = self.response_refining(response_content)
                    print(resp)
                    if "error" in resp:
                        logger.error("Error in response refining: %s", resp)
                        sys.exit(1)
                    # Load JSON string
                    resp_42 = json.dumps(resp, indent=4)
                    resp_42 = json.loads(resp_42)
                    print(resp_42)
                    # Pretty print the response
                    text_with_emails = resp_42['personalized_response'].replace('[[[enter email addresses here]]]', '\n'.join(emails))
                    text_with_emails = text_with_emails.replace('{EMAIL}', self.CONFIG['CCPAparameters']['support'])
                    print(text_with_emails)
                    logger.info("Response from RDS: %s", response_content)
                    logger.info("Macro 42")
                    self.rds_manager.log_to_database(ticketid, f"Macro 42")
                    tick_resp = self.add_ticket_response(ticketid, text_with_emails,ticket_classification, url_ticket, headers)
                    if "error" in tick_resp:
                        sys.exit(1)
                else:
                    print("Account found - Cant apply Macro 42")
                    logger.info("Account found - Cant apply Macro 42")
                    self.rds_manager.log_to_database(ticketid, f"Account found - Cant apply Macro 42")
            elif ticket_classification == "Junk":
                no_junk = junk_bypass_cases(ticket_resp['ticket']['description'])
                if no_junk:
                    logger.info("Info: Junk - out of scope case")
                    self.rds_manager.log_to_database(ticketid, "Junk - out of scope case")
                    print("Junk - out of scope case")
                    return "Junk - out of scope case"
                else:
                    logger.info("Junk")
                    self.rds_manager.log_to_database(ticketid, "Junk")
                    text_with_emails="Junk"
                    tick_resp = self.add_ticket_response(ticketid, text_with_emails,ticket_classification, url_ticket, headers)
                    if "error" in tick_resp:
                        sys.exit(1)
                    self.rds_manager.log_to_database(ticketid, "Junk - Ticket Response updated succesfully")
            elif ticket_classification == "No Phone Support":
                logger.info("No Phone Support Workflow")
                text_with_names = self.response_no_phone_support(ticket_resp)
                if text_with_names==False:
                    tick_resp = self.add_ticket_response(ticketid, text_with_names, ticket_classification, url_ticket, headers)
                    self.rds_manager.log_to_database(ticketid, "No Phone Support - Not a Zoosk Ticket case")
                else:
                    tick_resp = self.add_ticket_response(ticketid, text_with_names,ticket_classification, url_ticket, headers)
                    if "error" in tick_resp:
                        sys.exit(1)
                    self.rds_manager.log_to_database(ticketid, "No Phone Support - Ticket Response updated succesfully")
            else:
                logger.info("Other Category")
                print("Other Category")
                tick_resp = self.add_ticket_response(ticketid, "others", ticket_classification, url_ticket, headers)
                self.rds_manager.log_to_database(ticketid, "Other Category")

        
        else:
            logger.info(f"Ticket with ID {ticketid} not found in Zendesk.")
            self.rds_manager.log_to_database(ticketid, f"Ticket with ID {ticketid} not found in Zendesk.")
            return



# EmailAutomation().automation_workflow(521)



