from datetime import datetime
import boto3
import os

arn = os.environ['SF_ARN']
sf_client = boto3.client('stepfunctions')

def check_hour_differences(date_time_str):
    NUMBER_OF_DAYS=86400 * 1 #Multiple 86,400 by the number of days desired.
    date_time_obj = datetime.strptime(date_time_str, '%b %d, %Y, %I:%M:%S %p')
    now = datetime.now()
    difference = now - date_time_obj
    print(difference.total_seconds() / 3600.0)
    
    if difference.total_seconds() > NUMBER_OF_DAYS:
        return True
    else:
        return False

def lambda_handler(event, context):
    #date_time_str = event['detail']['resources'][0]['details']['awsEcrContainerImage']['pushedAt']
    image_hash = event['detail']['resources'][0]['details']['awsEcrContainerImage']['imageHash']
    date_time_str = "Jul 20, 2022, 6:59:23 PM"
    result = check_hour_differences(date_time_str)
    response = sf_client.start_execution(
        stateMachineArn=arn,
        name=image_hash,
        input='"input": "{image_hash}"',
    )   
    
    return result
