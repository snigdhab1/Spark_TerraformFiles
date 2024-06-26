
# import numpy as np
# import pandas as pd
import re
import sys
import os
from os.path import join
import requests
import datetime
from configparser import ConfigParser
import json
import psycopg2
from utils import load_config, load_prompts, load_prompts_acc, junk_bypass_cases, load_prompts_response42,get_secret
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

        ## RDS dependencied
        self.rds_manager = RDSManager()


    def get_secret(self, service_id, region_name):
        # Create a Secrets Manager client
        session = boto3.session.Session()
        client = session.client(
            service_name=self.CONFIG['zendesk']['service_name'],
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
    
    def check_keywords(text):
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
            return f"HTTP error occurred in email_classification function: {err}"
        except Exception as err:
            return f"An error occurred in email_classification function: {err}"


    def response_refining(self, query):
        messages = [
                    {"role": "user", "content": f"Personalize the following email response and return the reponse in json format: {query}."},
                    {"role": "assistant", "content": "json"} ]
        try:
            response_ai = self.generate_response_claude(self.bedrock, self.modelId, self.response_prompt42, messages)
            ticket_resp3 = self.parse_claude_response(response_ai)
            return ticket_resp3
        except requests.exceptions.HTTPError as err:
            return f"HTTP error occurred in response_refining function: {err}"
        except Exception as err:
            return f"An error occurred in response_refining function: {err}"


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
            print(response1.text)
            user_get_url_template = "https://admin.zoosk.com/api/v5.php?rpc=user/get&email={}&za={}&zs={}"
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
                # Make the user/get GET request
                user_get_response = requests.get(user_get_url)
                # Make the user/get GET request
                # user_get_response = requests.get(user_get_url, params=user_get_params)
                if user_get_response.status_code == 200:
                    # Request was successful
                    user_data = user_get_response.json()
                    # Process the user data as needed
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
            email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
            emails = re.findall(email_pattern, text)
            emails = list(set(emails))
            emails = [email for email in emails if email != self.CONFIG['CCPAparameters']['sender']]
            # if not emails:
            #     account_status=True
            #     print("No emails found for Account validation.")
            #     return account_status, emails
            # Test
            # emails.append("Ankitas12@hexaware.com")
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
        
    def check_keywords(self, text):
        keywords = self.CONFIG['CCPAparameters']['keywords']
        for keyword in keywords:
            if keyword.lower() in text.lower():
                return True
        return False
    

    def add_ticket_response(self, ticketid, ticket_response, classification, url_ticket, headers):
        if classification == "Account Related Issue/request":
            endnote = load_prompts_response42("ccpa_endnote")
            if ticket_response=="Not_a_Zoosk_Ticket":
                data = {
                "ticket": {
                    "comment": {
                        "body": self.CONFIG['CCPAparameters']['ccpa_false'],
                        "public": self.CONFIG['ticket_response']['public']
                    },
                    "status": self.CONFIG['ticket_response']['status'],
                    "tags": ['Automation_classification','CCPA_request','Not_a_Zoosk_Ticket']
                }
            }
            elif ticket_response=="Account_Exist":
                data = {
                "ticket": {
                    "comment": {
                        "body": self.CONFIG['CCPAparameters']['ccpa_acc_found'],
                        "public": self.CONFIG['ticket_response']['public']
                    },
                    "status": self.CONFIG['ticket_response']['status'],
                    "tags": ['Automation_classification','CCPA_request','Account_Found_Cant_apply_Macro_42']
                }
            }
            elif ticket_response=="CCPA_Out_Of_Scope_Case":
                data = {
                "ticket": {
                    "comment": {
                        "body": self.CONFIG['CCPAparameters']['CCPA_OutOfScope'],
                        "public": self.CONFIG['ticket_response']['public']
                    },
                    "status": self.CONFIG['ticket_response']['status'],
                    "tags": ['Automation_classification','CCPA_request','CCPA_Out_Of_Scope_Case']
                }
            }
            else:
                ticket_response = ticket_response + "\n\n" + endnote
                data = {
                    "ticket": {
                        "comment": {
                            "body": ticket_response,
                            "public": self.CONFIG['ticket_response']['public']
                        },
                        "status": self.CONFIG['ticket_response']['status'],
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
                    "status": self.CONFIG['ticket_response']['status'],
                    "tags": ['Automation_classification','Junk']
                }
            }
        else:
            data = {
                "ticket": {
                    "comment": {
                        "body": ticket_response,
                        "public": "false"
                    },
                    "status": self.CONFIG['ticket_response']['status'],
                    "tags": ['Automation_classification','Other_category, non_automation_workflow']
                }
            }
        try:
            print("Inside add_ticket_response function")
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
            
                

        #         response = requests.put(url_ticket, headers=headers, json=data)
        #         # response = requests.put(url_ticket, headers=headers, json=data, auth=(self.username, self.password_sandbox))
        #         print(response)
        #         if response.status_code == 200:
        #             logger.info("Ticket response updated successfully for %s ticket Id", str(ticketid))
        #             return "Ticket response updated successfully"
        #     else:
        #         response = requests.put(url_ticket, headers=headers, json=data, auth=(self.username, self.password))
        #         if response.status_code == 200:
        #             logger.info("Ticket response updated successfully for %s ticket Id", str(ticketid))
        #             return "Ticket response updated successfully"
        # except Exception as err:
        #     logger.error("Error: Failed to update ticket  %s  Response: %s", ticketid, err)
        #     return f"An error occurred: Ticket response update Failed: {err}"




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
            print("=====> Brand_name: ", brand_name)
            if brand_name=='Zoosk':
                return True
        else:
            print("Error fetching Brand details:", response_brand.status_code, response_brand.text)
            logger.error("Error in fetching Brand name details: %s, %s", response_brand.status_code, response_brand.text)
            return False
            
    def get_requester_details(self, requester_id, headers):
        if self.test_flag:
            user_url = self.base_url_sandbox + self.CONFIG['zendeskAPIs']['user_api'].format(requester_id=requester_id)
            user_response = requests.get(user_url, headers=headers)
        else:
            user_url = self.base_url + self.CONFIG['zendeskAPIs']['user_api'].format(requester_id=requester_id)
            user_response = requests.get(user_url, headers=headers)
        if user_response.status_code == 200:
            user = user_response.json()['user']
            # sender_name = user['name']
            requester_email = user['email']
            return requester_email
        else:
            print("Error fetching requester_email details:", user_response.status_code, user_response.text)
            logger.error("Error in fetching srequester_email details: %s, %s", user_response.status_code, user_response.text)
            return f"An error occurred:Unable to find requesters email for ccpa: {err}"
            

    def CCPA_automation_workflow(self, ticket_resp, ticket_classification, text, url_ticket, headers):
        try:
            requester_id = ticket_resp['ticket']['requester_id']
            requester_email =self. get_requester_details(requester_id, headers)
            if self.is_zoosk_ticket(ticket_resp):
                # match = self.check_keywords(ticket_resp['ticket']['description'])
                # print(match)
                # if (ticket_classification== "Account Related Issue/request" and ticket_resp['ticket']['via']['source']['from']['address'] == CONFIG['CCPAparameters']['sender']) | (ticket_classification== "Account Related Issue/request" and match):   
                if ticket_classification== "Account Related Issue/request" and requester_email==self.CONFIG['CCPAparameters']["sender"]:
                # if match:
                    account_status, emails = self.validation_42cr(text)
                    if account_status:
                        response_content = self.get_response_from_rds(self.CONFIG['databaseparameters']['table'], self.CONFIG['databaseparameters']['macro_num'])
                        resp = self.response_refining(response_content)
                        if "error" in resp:
                            logger.error("Error in response refining: %s", resp)
                            return f"Error in response refining: {resp}"
                        # Load JSON string
                        resp_42 = json.dumps(resp, indent=4)
                        resp_42 = json.loads(resp_42)
                        # Pretty print the response
                        text_with_emails = resp_42['personalized_response'].replace('[[[enter email addresses here]]]', '\n'.join(emails))
                        text_with_emails = text_with_emails.replace('{EMAIL}', self.CONFIG['CCPAparameters']['support'])
                        logger.info("Response from RDS: %s", response_content)
                        logger.info("Macro 42")
                        return text_with_emails
                        # tick_resp = self.add_ticket_response(ticketid, text_with_emails,ticket_classification, test=True)
                        # if "error" in tick_resp:
                        #     sys.exit(1)
                    else:
                        return "Account_Exist"
                else:
                    return "CCPA_Out_Of_Scope_Case"
            else:
                logger.info("Not a Zoosk Ticket")
                return "Not_a_Zoosk_Ticket"
        except requests.exceptions.HTTPError as err:
            return f"HTTP error occurred in CCPA_automation_workflow function: {err}"
        except Exception as err:
            return f"An error occurred in CCPA_automation_workflow function: {err}"




    def automation_mode(self, ticketid):
        try:
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
        except requests.exceptions.HTTPError as err:
            return f"HTTP error occurred in automation_mode function: {err}"
        except Exception as err:
            return f"An error occurred in automation_mode function: {err}"


    def automation_workflow(self, ticketid, test=False):
        response, url_ticket, headers = self.automation_mode(ticketid)
        ## check status of ticket url response
        if response.status_code == 200:
            ticket_resp = response.json()
            text = ticket_resp['ticket']['description']
            ## Email classification flow
            ticket_resp1 = self.email_classification(text)
            if "error" in ticket_resp1:
                print("Error in email_classification: ", ticket_resp1)
                logger.error("Error: %s", ticket_resp1)
                return f"Error occured in fetching response from email_classification: {ticket_resp1}"
            # ticket_resp2 = json.loads(ticket_resp1)
            ticket_resp['ticket'].update(ticket_resp1)
            ticket_classification = ticket_resp1['Classification']
            print('===> Ticket Classification: ', ticket_classification)
            # Check classification catagory
            if ticket_classification.strip()=="Account Related Issue/request":
                logger.info("CCPA Workflow starts")
                print("CCPA Workflow starts")
                text_with_emails = self.CCPA_automation_workflow(ticket_resp, ticket_classification, text, url_ticket, headers)
                if "error" in text_with_emails:
                    logger.error(f"Error occured in fetching response from CCPA_automation_workflow function: {text_with_emails}")
                    self.rds_manager.log_to_database(ticketid, f"Error occured in fetching response from CCPA_automation_workflow function: {text_with_emails}")
                    return f"Error occured in CCPA_automation_workflow : {text_with_emails}"
                elif text_with_emails=="Not_a_Zoosk_Ticket":
                    tick_resp = self.add_ticket_response(ticketid, text_with_emails, ticket_classification, url_ticket, headers)
                    self.rds_manager.log_to_database(ticketid, self.CONFIG['CCPAparameters']['ccpa_false'])
                    logger.info("Not_a_Zoosk_Ticket")
                    return "CCPA - Not a Zoosk Ticket case."
                elif text_with_emails=="Account_Exist":
                    tick_resp = self.add_ticket_response(ticketid, text_with_emails, ticket_classification, url_ticket, headers)
                    self.rds_manager.log_to_database(ticketid, self.CONFIG['CCPAparameters']['ccpa_acc_found'])
                    logger.info("Account found - Cant apply Macro 42")
                    return "CCPA case - Account found - Can't apply Macro 42 case."
                elif text_with_emails=="CCPA_Out_Of_Scope_Case":
                    tick_resp = self.add_ticket_response(ticketid, text_with_emails, ticket_classification, url_ticket, headers)
                    self.rds_manager.log_to_database(ticketid, self.CONFIG['CCPAparameters']['CCPA_OutOfScope'])
                    logger.info("CCPA case - Out Of Scope Case.")
                    return "CCPA case - Out Of Scope Case."
                else:
                    tick_resp = self.add_ticket_response(ticketid, text_with_emails, ticket_classification, url_ticket, headers)
                    self.rds_manager.log_to_database(ticketid, self.CONFIG['CCPAparameters']['ccpa_success'])
                    logger.info("CCPA case - Ticket Response updated succesfully")
                    return "CCPA case - Ticket Response updated succesfully"
            elif ticket_classification == "Junk":
                logger.info("Junk Workflow start")
                print("Junk Workflow start")
                no_junk = junk_bypass_cases(ticket_resp['ticket']['description'])
                if no_junk:
                    logger.info("Info: Junk - out of scope case")
                    self.rds_manager.log_to_database(ticketid, self.CONFIG['Junkparameters']['junk_oos'])
                    print("Junk - out of scope case")
                    text_with_emails = self.CONFIG['Junkparameters']['junk_oos']
                    tick_resp = self.add_ticket_response(ticketid, text_with_emails,ticket_classification, url_ticket, headers)
                    return "Junk - out of scope case"
                else:
                    logger.info("Junk")
                    text_with_emails = self.CONFIG['Junkparameters']['junk_resp']
                    tick_resp = self.add_ticket_response(ticketid, text_with_emails,ticket_classification, url_ticket, headers)
                    if "error" in tick_resp:
                        return f"Error occured in fetching response from add_ticket_response function: {tick_resp}"
                    self.rds_manager.log_to_database(ticketid, "Junk - Ticket Response updated succesfully")
                    return "Junk - Ticket Response updated succesfully"
            else:
                logger.info("Other Category")
                print("Other Category")
                other_resp = self.CONFIG['ticket_response']['other_catagory']
                tick_resp = self.add_ticket_response(ticketid, other_resp, ticket_classification, url_ticket, headers)
                self.rds_manager.log_to_database(ticketid, other_resp)
                return other_resp

        else:
            if "error" in response:
                logger.error(f"Error occured in reading Ticket with ID {ticketid} in Zendesk.")
                self.rds_manager.log_to_database(ticketid, f"Error occured in reading Ticket with ID {ticketid} in Zendesk.")
                print(f"Error occured in reading Ticket with ID {ticketid} in Zendesk. ")
                sys.exit(1)
                return f"Error occured in reading Ticket in automation_workflow: {response}"
            return f"Error occured in reading Ticket in automation_workflow main function"



# EmailAutomation().automation_workflow(516)






