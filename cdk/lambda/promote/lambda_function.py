import json
import boto3
import sys
import base64
import os

ssm_client = boto3.client('ssm')
sfn_client = boto3.client('stepfunctions')

region = os.environ['AWS_REGION']

def lambda_handler(event, context):
    activity_task_id = event['queryStringParameters']['taskToken']
    print(activity_task_id)
    
    #This is an example of using StepFunctions Activities to add a manual validation step. This will add at least a minute to execution steps.
    #Running this directly through Git workflows is possible too.

    #response = sfn_client.send_task_success(
    #    taskToken=activity_task_id,
    #    output='string',
    #)

    #This response should be left a 200, with a relevant message passed as well if there is an error. This returns the response to API Gateway.
    return {
        "statusCode": 200,
    }
