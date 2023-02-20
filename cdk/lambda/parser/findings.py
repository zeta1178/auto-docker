from collections import defaultdict
import botocore.exceptions
from pprint import pprint

from emailfunctions import get_summary_header, get_summary_footer, build_summary_html, build_summary, build_email, build_sns
summaryresults=defaultdict(list)
findings={}
summaryheader = get_summary_header()
summaryfooter = get_summary_footer()

def build_body(findings, event):
    body={}
    body['findings']          = findings,
    body['scan-status']       = event['detail']['scan-status'],
    body['repository-name']   = event['detail']['repository-name'],
    body['resources']         = event['resources'],
    body['image-digest']      = event['detail']['image-digest'],
    body['image-tags']        = event['detail']['image-tags'],
    body['region']            = event['region'],
    return body

#This prepares a dict that is used to send an email if there are no findings.
def summary_no_findings(event, fullresultsurl, summaryresultsurl):
    findings = "No Vulnerabilities detected"
    body = build_body(findings, event)
    return(body)

#This prepares a dict that is used to send an email if there are findings.
def summary_findings(event, fullresultsurl, summaryresultsurl):
    findings = event['detail']['finding-severity-counts'],
    body = build_body(findings, event)
    return(body)
    
def build_summary_html_with_findings(json_lines):    
    for line in json_lines:
        if line:
            names=[]
            version=[]

            for package in line['packageVulnerabilityDetails']['vulnerablePackages']:
                names.append(package['name'])
                version.append(package['version'])
                
                if line['packageVulnerabilityDetails'].get("vendorSeverity") is not None:
                    vendorSeverity=line['packageVulnerabilityDetails']['vendorSeverity'],
                else:
                    vendorSeverity="NA"
                if line['packageVulnerabilityDetails'].get("vulnerabilityId") is not None:
                    vulnerabilityId=line['packageVulnerabilityDetails']['vulnerabilityId']
                else:
                    vulnerabilityId="NA"                
    
            fragment = build_summary_html(
                    description     = line['description'],
                    inspectorScore  = line['inspectorScore'],
                    cvss            = line['packageVulnerabilityDetails']['cvss'],
                    sourceUrl       = line['packageVulnerabilityDetails']['sourceUrl'],
                    source          = line['packageVulnerabilityDetails']['source'], #cut?
                    vendorSeverity  = vendorSeverity,
                    vulnerabilityId = vulnerabilityId,
                    packageName     = names,
                    version         = version,
                    remediation     = line['remediation'],
                    resources       = line['resources'],
                    status          = line['status'],
                    severity        = line['severity'],
                    title           = line['title'],
                    finding_type    = line['type'],
                    )
            summaryresults[line['severity']].append(fragment)
        else:
            summaryresults['CRITICAL'].append("NA")
            summaryresults['HIGH'].append("NA")
            summaryresults['MEDIUM'].append("NA")
            summaryresults['LOW'].append("NA")
            summaryresults['INFORMATIONAL'].append("NA")
            summaryresults['UNDEFINED'].append("NA")

    #This builds the actual output. See fragment above, this can be expanded. Currently this is used to build the summary email and HTML file.
    criticalfindings      = ''.join(summaryresults['CRITICAL'])
    highfindings          = ''.join(summaryresults['HIGH'])
    mediumfindings        = ''.join(summaryresults['MEDIUM'])
    lowfindings           = ''.join(summaryresults['LOW'])
    infofindings          = ''.join(summaryresults['INFORMATIONAL'])
    undefinedfindings     = ''.join(summaryresults['UNDEFINED'])
    findings['critical']  = criticalfindings
    findings['high']      = highfindings
    findings['medium']    = mediumfindings
    findings['low']       = lowfindings
    findings['info']      = infofindings
    findings['undefined'] = undefinedfindings

    results = ' '.join(
        map(str, (
        summaryheader,
        criticalfindings,
        highfindings,
        mediumfindings,
        lowfindings,
        infofindings,
        undefinedfindings,
        summaryfooter
        ))
    )
    return results, findings
    
def build_summary_html_without_findings():
    criticalfindings  = "NA"
    highfindings      = "NA"
    mediumfindings    = "NA"
    lowfindings       = "NA"
    infofindings      = "NA"
    undefinedfindings = "NA"  
    
    results = ' '.join(
        map(str, (
        summaryheader,
        criticalfindings,
        highfindings,
        mediumfindings,
        lowfindings,
        infofindings,
        undefinedfindings,
        summaryfooter
        ))
    )
    return results, findings    
    
def build_finding_summary(json_lines):
    print(json_lines)
    if json_lines['findings']:
        html = build_summary_html_with_findings(json_lines)
    else:
        html = build_summary_html_without_findings()
    return html        
    
    
#This file is used by the Lambda function exporting process_findings. This takes the Inspector findings, simplifies them into only desired outputs and creates a summary.
def process_findings(event, findings_json, fullresultsurl, summaryresultsurl):
    print("Processing findings")
    findings = findings_json['findings']
    if findings:
        print('findings found.')
        body = summary_findings(event, fullresultsurl, summaryresultsurl)
        results, findings = build_finding_summary(findings_json)    

    elif not findings:
        print('no findings found.')
        body = summary_no_findings(event, fullresultsurl, summaryresultsurl)
        results, findings = build_finding_summary(findings_json)  

    #pprint(body)
    expiration=3600

    #SNS currently does not allow for nicely formatted emails. This builds a simple email using static HTML fragments and only the minimum useful fields 
    #from the Inspector results and sends it via the SES service.
    email_body=build_email(
        findings          = body['findings'],
        reponame          = body['repository-name'],
        resources         = body['resources'],
        imagedigest       = body['image-digest'],
        tags              = body['image-tags'],
        region            = body['region'],
        fullresultsurl    = fullresultsurl,
        summaryresultsurl = summaryresultsurl,
    )

    #This sends a HTML email via the SNS service. This will need to be adjusted to only the findings desired and with formatting removed.
    sns_body=build_sns(
        findings          = body['findings'],
        reponame          = body['repository-name'],
        resources         = body['resources'],
        imagedigest       = body['image-digest'],
        tags              = body['image-tags'],
        region            = body['region'],
        fullresultsurl    = fullresultsurl,
        summaryresultsurl = summaryresultsurl,
    )

    return(results, findings, email_body, sns_body)