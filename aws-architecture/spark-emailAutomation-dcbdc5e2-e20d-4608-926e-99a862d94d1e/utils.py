import re
import os
from configparser import ConfigParser
from os.path import join
import requests
import boto3

def load_config():
    config = ConfigParser()
    config.read("config.ini")
    return config

    
def load_prompts():
    CONFIG  = load_config()
    delimiter = "####"
    prompt_path = CONFIG["path"]["prompt_path"]
    prompt_base = CONFIG["prompts"]["system_prompt"]
    path = join(prompt_path,prompt_base)+".txt"
    file_data = open(path,"r").read()
    prompt = f"""{file_data}"""
    return prompt
    
def load_prompts_acc():
    CONFIG  = load_config()
    delimiter = "####"
    prompt_path = CONFIG["path"]["prompt_path"]
    acc_prompt_base = CONFIG["prompts"]["acc_subcategory_prompt"]
    acc_promptpath = join(prompt_path,acc_prompt_base)+".txt"
    file_data = open(acc_promptpath, "r", encoding='utf-8').read()
    prompt = f"""{file_data}"""
    return prompt

def load_prompts_response42(anyprompt):
    CONFIG  = load_config()
    delimiter = "####"
    prompt_path = CONFIG["path"]["prompt_path"]
    response_prompt42_base = CONFIG["prompts"][anyprompt]
    acc_promptpath = join(prompt_path, response_prompt42_base) + ".txt"
    file_data = open(acc_promptpath, "r", encoding='utf-8').read()
    prompt = f"""{file_data}"""
    return prompt


def junk_bypass_cases(text):
    # get attachment filename if any
    pattern = r'\b[a-zA-Z0-9_-]+\.(?:jpg|jpeg|txt)\b'
    # Search for the pattern in the text
    matches = re.findall(pattern, text)
    words = text.split()
    # Check if the description has only one word and does not end with file extensions
    if len(words) == 1 and matches:
        print(matches)
        return True
    else:
        return False

def is_single_word_email(description):
    # Split the description into words
    words = description.split()

    # Check if the description has only one word and does not end with file extensions
    if len(words) == 1 and not words[0].endswith(('.txt', '.pdf', '.docx', '.doc')):
        return True
    else:
        return False


def get_secret(service_id, region_name):
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
