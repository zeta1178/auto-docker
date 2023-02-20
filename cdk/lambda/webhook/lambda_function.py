import json
import boto3 
#import crypto
import requests
import urllib.parse
import os
import asyncio
import logging
import io
import hmac, hashlib
import pprint

loop = asyncio.get_event_loop()
s3_client = boto3.client('s3')
s3_tc     = boto3.s3.transfer.TransferConfig
sm_client = boto3.client('secretsmanager') 

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context): 

    # print(f"Incoming event: {event}")
    try:
        # collect the event and pass into a json object
        eventBody= event['body']
        body_json=json.loads(eventBody)
        # print(f"event_body: {body_json}")
        
        # make lowercase the keys for the event object
        normalizedHeaders= normalizeObject(event['headers'])
        
        # locates the secret value
        git_secret = json.loads( (sm_client.get_secret_value(
            SecretId=os.environ.get('BITBUCKET_SECRET')
        )['SecretString']))['secret']
        git_token = json.loads( (sm_client.get_secret_value(
            SecretId=os.environ.get('BITBUCKET_TOKEN')
        )['SecretString']))['pat']

        # modified for use in bitbucket
        if ( (body_json.get('changes')[0].get('ref')).get('type') =="BRANCH") is False :
            logger.info('Invalid event type')
            raise "Invalid event type"

        # modified for use in bitbucket
        # if (checkSignature(git_secret,normalizedHeaders['x-hub-signature'],eventBody)) is False:
            # logger.info("Invalid webhook message signature")
            # return responseToApiGw("Signature is not Valid", 401)
        

        # modified for use in bitbucket
        # if ('x-event-key' in normalizedHeaders) and (normalizedHeaders['x-event-key'] == 'diagnostics:ping'):
        if ('x-event-key' in normalizedHeaders) and (normalizedHeaders['x-event-key'] == 'repo:refs_changed'):
            logger.info('Webhook configured successfully')

        # modified for use in bitbucket
        repoConfig = {
            "serverUri": os.environ.get('BITBUCKET_SERVER_URI'),
            "projectName": body_json.get('repository').get('project').get('key'),
            "repoName": body_json.get('repository').get('name'),
            "projectId": str(body_json.get('repository').get('project').get('id')),
            "branch": (body_json.get('changes')[0].get('ref')).get('displayId'),
            "token": git_token
        }
        
        # display the current config values
        logger.info(f"repoConfig: {repoConfig}")
        
        # download an archive of the repo
        file = loop.run_until_complete(downloadFile(repoConfig))
        
        # Upload the repository archive package to S3 bucket
        logger.info("Info, >>> uploadFile()")
        conf = s3_tc(multipart_threshold=10000, max_concurrency=4)
        exArg= {
            "ServerSideEncryption": "AES256"
        }
        s3Upload = s3_client.upload_fileobj(io.BytesIO(file), os.environ.get('S3BUCKET'), f"{repoConfig['projectName']}/{repoConfig['repoName']}/{repoConfig['branch']}.zip", Config=conf, ExtraArgs=exArg)
        logger.info("Info, <<< uploadFile()")

        # display success message
        logger.info('Exiting successfully')
        return responseToApiGw("Success", 200)
    
    except Exception as e:
        # display error
        logger.info(f"Error: {e}")
        return responseToApiGw("An unknown error has occurred. Please contact the administrator", 500)

# function to make lower case the header keys
def normalizeObject(inputObject):
    logger.info("Info, >>> normalizeObject()") 
    outputObject={}
    for key, value in inputObject.items():
        outputObject[key.lower()] = value
    logger.info("Info, <<< normalizeObject()")
    return outputObject

async def downloadFile(repoConfig):
    logger.info("Info, >>> downloadFile()")

    baseURL = repoConfig['serverUri']
    
    # modified for use in bitbucket --->##rest/api/1.0/projects
    URL     = f"/rest/api/latest/projects/{repoConfig['projectName']}/repos/{repoConfig['repoName']}/archive?at=refs/heads/{repoConfig['branch']}&format=zip"
    headers = {
            "Authorization" : f"Bearer {repoConfig['token']}"
            }
    
    logger.info(f"URL: {baseURL}{URL}")
    try:
        req = requests.Request('GET', urllib.parse.urljoin(baseURL, URL), headers=headers)
        response = requests.get( urllib.parse.urljoin(baseURL, URL), headers=headers, stream=True)
        # response = requests.get( urllib.parse.urljoin(baseURL, URL), stream=True) 
        logger.info("Info, <<< downloadFile()") 
        return response.content
    except Exception as e:
        print(f"Error{e}")
        raise (e)

# checkSignature(os.environ.get('BITBUCKET_SECRET'),normalizedHeaders['x-hub-signature'],eventBody)) is False:
def checkSignature(signingSecret, signature, body):
    logger.info("Info, >>> signingSecret()") 
    
    # modified for bitbucket
    hash=hmac.new(signingSecret, body, hashlib.sha256).hexdigest()
    signatureHash = signature.split("=")
    if signatureHash[1] == hash :
           
        logger.info("Info, <<< signingSecret()")
        return True
    else:
        logger.info("Info, <<< signingSecret()")
        return False                   

def responseToApiGw(detail=None, statusCode=None):
    body={}
    if statusCode is None :
        raise TypeError("responseToApiGw() expects at least argument statusCode")
    if statusCode is None and detail is None:
        raise TypeError("responseToApiGw() expects at least arguments statusCode and detail")
    if statusCode == 200 and detail is not None:  
        body= {
                "statusCode": statusCode,
                "message": detail
        }
    elif statusCode == 200 and detail is None:
        body={
                "statusCode": statusCode
            }
    else:
        body={
                "statusCode": statusCode,
                "fault": detail
            }    
    response = {
                "statusCode": statusCode,
                "body": json.dumps(body),
                "headers": {
                    "Content-Type": "application/json",
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "POST, GET",
                    "Access-Control-Allow-Headers": "Origin, X-Requested-With, Content-Type, Accept"
                }
        } 
    return response 