import json
import boto3
import sys
import base64
import os
import urllib.parse
from pprint import pprint
from botocore.config import Config
from botocore.exceptions import ClientError
from collections import defaultdict
from inspector import InspectorFinding
#from emailfunctions import get_summary_header, get_summary_footer, build_summary_html, build_summary, build_email, send_email #This file and the functions imported create HTML formatting. This very basic functionality can be replaced by formatting libraries if desired.
from findings import process_findings

s3_client = boto3.client('s3',config=Config(signature_version='s3v4'))
ses_client = boto3.client('ses')
ssm_client = boto3.client('ssm')
sfn_client = boto3.client('stepfunctions')

summary=[]
findingresult={}
summaryresults=defaultdict(list)
region = os.environ['AWS_REGION']

def is_json(var):
    try: 
        json_object = json.loads(var)
    except ValueError as e:
        return False
    return True
    
def notifysecurity(findings):
    #Here we're looking to define what warrants a notification. Critical and High should trigger a result but medium and low can as well.
    if not findings:
        notify=True
    else:
        
        if findings['critical'] != "":
            notify=True
        if findings['high'] != "":
            notify=True
        if findings['medium'] != "":
            notify=True
        if findings['low'] != "":
            notify=True
        if findings['info'] != "":
            notify=True
        if findings['undefined'] != "":
            notify=True
    return notify

def notifydevelopers(findings):
    #Here we're looking to define what warrants a notification. Critical and High should trigger a result but medium and low can as well.
    if not findings:
        notify=True
    else:
        
        if findings['critical'] != "":
            notify=True
        if findings['high'] != "":
            notify=True
        if findings['medium'] != "":
            notify=True
        if findings['low'] != "":
            notify=True
        if findings['info'] != "":
            notify=True
        if findings['undefined'] != "":
            notify=True
    return notify

def get_secret(secret_name):
    region_name = region

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    # In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
    # See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
    # We rethrow the exception by default.

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
    else:
        # Decrypts secret using the associated KMS key.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
            return secret
        else:
            decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])
            return decoded_binary_secret
            
def get_scan_results(bucket, object_path):            
    #We are pulling out the Inspector results, stored in an AWS S3 object (vulnerability scan results) for processing.
    s3_object = s3_client.get_object(
        Bucket=bucket,
        Key=object_path
    )   
    return s3_object
    
def process_scan_results(s3_object):
    #We are pulling out the Inspector results, stored in an AWS S3 object (vulnerability scan results) for processing.

    #This reads the S3 object, and translates it into JSON for processing. Currently the API returns a malformed JSON response if the image was an un-supported image type, or the image does not exist.
    filedata = s3_object['Body'].read().decode('utf-8')
    #Ensure no edge cases where findings don't exist.
    if is_json(filedata):
        json_content = json.loads(filedata)
    else:
        json_content = {}
        json_content['findings'] = []
    return json_content

#Basic wrapper for the get findings report status call. This can be adjusted for custom retry logic, formatting the results, etc.
def check_status(report_id):
    report_response = client.get_findings_report_status(
        report_id=report_id
    )
    return report_response

#Presigned URL's allow for secure storage of S3 objects (non-public access) while still allowing anyone with the URL to view results. This allows for easy distribution of findings. Anyone with this link will have access to the object. Set the expiration param to a desired value keeping security, vs. desired response time in mind.
def create_presigned_url(bucket_name, object_name, expiration=86400):
    """Generate a presigned URL to share an S3 object

    :param bucket_name: string
    :param object_name: string
    :param expiration: Time in seconds for the presigned URL to remain valid
    :return: Presigned URL as string. If error, returns None.
    """
    #Get the Secret ARN that stores the access credentials for the S3 Report User. This allows for pre-signed URL's to be valid for up to 7 days instead of a maximum of 6 hours.
    secret_id = os.environ['SECRET_ID']
    access_key = os.environ['ACCESS_KEY_ID']
    access_secret_key = get_secret(secret_id) 
    
    # Generate a presigned URL for the S3 object
    s3_config = Config(
        region_name=region,
        signature_version='s3v4',
    )
    endpoint_url = 'https://s3.' + region + '.amazonaws.com'
    s3_client = boto3.client(
        's3', 
        config=s3_config, 
        region_name=region, 
        endpoint_url=endpoint_url,
        aws_access_key_id=access_key, 
        aws_secret_access_key=access_secret_key
    )
    try:
        response = s3_client.generate_presigned_url('get_object',
                                                    Params={'Bucket': bucket_name,
                                                            'Key': object_name},
                                                    ExpiresIn=expiration
                                                    )
    except ClientError as e:
        logging.error(e)
        return None

    # The response contains the presigned URL
    return response

def lambda_handler(event, context):
    pprint(event)
    
    result   = []
    findings = {}
    response = {}
    scan     = False
    
    bucket      = event['finding']['Bucket']
    report_id   = event['finding']['ReportId']
    activity_id = event['finding']['sfn_arn']
    
    response['message']            = {}
    response['message']['email']   = {}
    response['message']['default'] = {}    

    response['notify']       = {}
    response['image_digest'] = event['detail']['image-digest']
    response['repo_name']    = event['detail']['repository-name']
    
    if event['finding']['Status'] == "NO_FINDINGS":
        scan = False
        
    if event['finding']['Status'] == "SUCCEEDED":
        scan = True        
    
    if not scan:
        object_path="report/no_findings.html"
        object_summary_path="report/no_findings.html"
        s3_object = get_scan_results(bucket, object_path)
        
    if scan:
        object_path         = (report_id + '.json')
        object_summary_path = (report_id + '_summary.html')
        s3_object           = get_scan_results(bucket, object_path)
        json_content        = process_scan_results(s3_object)

    #These two calls add to the email summary the full results, and summary results via presigned URL's.
    fullresultsurl=create_presigned_url(bucket, object_path),
    summaryresultsurl=create_presigned_url(bucket, object_summary_path),

    #This pulls from the process finding module. Logic in this file is mostly for HTML processing. This can be easily moved into HTML libraries for more powerful formatting but that introduces libraries, and vulnerability management. Formatted results (JSON/Dict objects) are used by SNS and SES later.
    results, findings, email_body, sns_body = process_findings(event, json_content, fullresultsurl, summaryresultsurl)

    #Here we're storing the formatted summary into S3. This allows access by anyone with the presigned URL.
    s3_client.put_object(
        Body=results,
        Bucket=bucket,
        Key=object_summary_path,
        ContentType='text/html'
    )

    #Different teams may want different notification levels. Operations may want an email for every build. Devs may 
    #only want notifications upon security issues.
    notify_developers = notifydevelopers(findings)    
    notify_security   = notifysecurity(findings)

    response['notify']['developers'] = False
    response['notify']['security'] = False 
        
    response['notify']['security'] = True
    response['message']['email']   = sns_body
    response['message']['default'] = sns_body
    response['message']['sms']     = sns_body
        
    print(response)
    return response
