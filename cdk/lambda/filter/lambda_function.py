import boto3
import os
import time
import json
import logging
from botocore.exceptions import ClientError

client = boto3.client('inspector2')
boto3.set_stream_logger('boto3.resources', logging.INFO)
#boto3.set_stream_logger(name='botocore')

#This builds params for the inspector call later. This is outside of the handler because it will be static.
params = {
      'filterCriteria': {
          'ecrImageHash': [
          {
              'comparison': 'EQUALS',
              'value': ''
          }
          ]
      },
      'reportFormat': 'JSON',
      's3Destination': {
          'bucketName': '',
          'kmsKeyArn': ''
      }
}

#This is a wrapper for the get report status check. This can be modified to include custom retry logic, processing, etc.
def check_status(reportId):
    #print(reportId)
    report_response = client.get_findings_report_status(
        reportId=reportId
    )
    print(report_response)
    return report_response
    
def return_report(params, status, reportId, event):
    print(params, status, reportId)

    if status == 'NONE':
        response = client.create_findings_report(**params)
        print("No report in-progress, starting a new findings report.")
        report_details = check_status(response['reportId'])
        status = report_details['status']
        reportId = report_details['reportId']
        return(status, reportId)   
        
    if status == 'IN_PROGRESS':
        report_details = check_status(reportId)
        status = report_details['status']
        reportId = report_details['reportId']
        return(status, reportId)
        
    elif status == 'SUCCEEDED':
        status = event['finding']['Status']
        reportId="NONE"
        return(status, reportId)
        
    elif status == 'FAILED' or status == 'REPORT_GENERATION_FAILED':
        #If this call fails, we want to retry via the StepFunctions retry policy using backoff. There can be edge cases where this runs before the Inspector service knows about the Image upload. The wait state will help.
        print("Previous create findings report attempt failed. Retrying.")
        status="NONE"
        status, reportId = return_report(params, status, reportId, event)
        return(status, reportId)
    return(status, reportId)
    
def lambda_handler(event, context):
    print(event)
    params['filterCriteria']['ecrImageHash'][0]['value'] = event['detail']['image-digest'] 
    params['s3Destination']['bucketName'] = os.environ['BUCKET'] 
    params['s3Destination']['kmsKeyArn'] = os.environ['KMSKEY']
    
    if 'finding' in event:
        status=event['finding'].get('Status', 'NONE') #If this has been invoked before, there will be a status. If not, get initial findings.
        reportId = event['finding'].get('ReportId', 'NONE') #If this has been invoked before, there will be reportId. If not, get initial findings.
    else:
        status="NONE"
        reportId="NONE"
    status, reportId = return_report(params, status, reportId, event)
    
    results=[]
    report={}
    report['ReportId'] = reportId
    report['Status'] = status
    report['Bucket'] = params['s3Destination']['bucketName'] 
    report['KmsKeyArn'] = params['s3Destination']['kmsKeyArn']
    report['digest'] = event['detail']['image-digest']
    report['repo_name'] = event['detail']['repository-name']
    print(report)
    return(report)
