import json
import re
import os
from os.path import join
import requests
import datetime
from configparser import ConfigParser
import openai
from openai import OpenAI
import psycopg2
from utils import load_config
import boto3
from workflows import EmailAutomation
import logging


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

class MyLambdaClass:
    def __init__(self):
        self.CONFIG = load_config()
        self.EmailAutomation_instance = EmailAutomation()
        print("HELLO : LAMBDA EXECUTION STARTS")

    def lambda_handler(self, event, context):
        # Parse the incoming JSON data
        body = event.get('body')
        if not body:
            logger.error('Missing body in event or event is not found')
            print('Missing body in event or event is not found')
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Missing body in event'})
            }
        else:
            logger.info('Event body received successfully.')
        
        # Parse the JSON body if necessary
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            logger.error('Invalid JSON in body.')
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Invalid JSON in body'})
            }
            
        # Ensure 'ticket' is present in the parsed data
        ticket = data.get('ticket')
        if not ticket:
            logger.error('Missing ticket in body.')
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Missing ticket in body'})
            }
        else:
            logger.info('Ticket body received successfully.')
            

        # Ensure 'ticket_id' is present in the ticket data
        ticketid = ticket.get('ticket_id')
        print(ticketid)
        if not ticketid:
            logger.error('Missing ticket id in ticket body.')
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Missing ticket_id in ticket'})
            }
        else:
            logger.info('Ticket id received successfully.')
            print('Ticket id received successfully.')
            
        ## Automation flow
        print("Automation Pipeline Starts")
        ## For static ticket id run for testing through config
        # result = self.EmailAutomation_instance.automation_workflow(self.CONFIG['Testing']['ticketid'], test=self.CONFIG['Testing']['test'])

        ## For webhook trigger
        result = self.EmailAutomation_instance.automation_workflow(ticketid)
        print(result)
        print("Automation Pipeline Ends")
        print("LAMBDA EXECUTION ENDS")
        return ticketid, result
    
# Create an instance of the class
lambda_instance = MyLambdaClass()

# Handler method for AWS Lambda
def lambda_handler(event, context):
    return lambda_instance.lambda_handler(event, context)
    
