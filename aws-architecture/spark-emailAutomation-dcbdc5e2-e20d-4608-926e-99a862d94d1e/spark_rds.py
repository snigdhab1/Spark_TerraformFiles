import psycopg2
from utils import load_config
import logging
import datetime
import boto3
from botocore.exceptions import ClientError
import json

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

CONFIG  = load_config()

class RDSManager:
    def __init__(self):
        ## Connection parameters
        self.connection = None
        self.cursor = None
        self.rds_name = CONFIG["databaseparameters"]["rds_name"]
        self.region_name = CONFIG["databaseparameters"]["region_name"]
        self.secrets = self.get_secret(self.rds_name, self.region_name)
        self.ENDPOINT = self.secrets['host']
        self.PORT = self.secrets['port']
        self.USER = self.secrets['username']
        self.REGION = self.region_name
        self.DBNAME = self.secrets['username']
        self.PASSWORD = self.secrets['password']

    def get_secret(self, rds_name, region_name):
        # Create a Secrets Manager client
        session = boto3.session.Session()
        client = session.client(
            service_name='secretsmanager',
            region_name=region_name
        )

        try:
            get_secret_value_response = client.get_secret_value(
                SecretId=rds_name
            )
        except ClientError as e:
            raise e

        secrets = get_secret_value_response['SecretString']
        return json.loads(secrets)


    def connect_to_rds(self):
        try:
            self.connection = psycopg2.connect(host=self.ENDPOINT, port=self.PORT, 
                                               database=self.DBNAME, user=self.USER, 
                                               password=self.PASSWORD, sslrootcert="SSLCERTIFICATE")
            self.cursor = self.connection.cursor()
            logger.info("Connection successfull to  RDS database")
        except psycopg2.Error as e:
            print("Unable to connect to the database:", e)
            logger.error("Unable to connect to RDS database: %s", e)

    def get_response(self, table, num):
        num = str(num)
        if not self.cursor:
            self.connect_to_rds()
        query = f"SELECT content FROM {table} WHERE number = %s"
        self.cursor.execute(query, (num,))
        response = self.cursor.fetchone()
        if response:
            logger.info("Response fetched succesfully from RDS database")
            return response[0]
        else:
            logger.info("Response not found in RDS database")
            return None
            

    def close_connection(self):
        if self.cursor:
            self.cursor.close()
            logger.info("Cursor closed for RDS database")
        if self.connection:
            self.connection.close()
            logger.info("connection closed for RDS database")



    def log_to_database(self, ticketid, message):
        # Connect to your AWS RDS instance
        try:
            connection = psycopg2.connect(host=self.ENDPOINT, port=self.PORT, 
                                          database=self.DBNAME, user=self.USER, 
                                          password=self.PASSWORD, sslrootcert="SSLCERTIFICATE")
            cursor = connection.cursor()

            # Check if a row already exists for the ticket ID
            cursor.execute("SELECT * FROM logs WHERE ticket_id = %s", (ticketid,))
            existing_row = cursor.fetchone()

            if existing_row:
                # Update the existing row
                timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                cursor.execute("UPDATE logs SET time = %s, message = %s WHERE ticket_id = %s", (timestamp, message, ticketid))
            else:
                # Insert a new row
                timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                cursor.execute("INSERT INTO logs (ticket_id, time, message) VALUES (%s, %s, %s)", (ticketid, timestamp, message,))
            
            connection.commit()
        except psycopg2.Error as e:
            logger.error("Error occurred while logging to database: %s", e)
        finally:
            if cursor:
                cursor.close()
            if connection:
                connection.close()
    

