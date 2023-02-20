def get_summary_header():
    HTML_FRAGMENT = """
        <!DOCTYPE html>
        <html>
            <body>
                <div style="background-color:#eee;padding:10px 20px;">
                    <h2 style="font-family:Georgia, 'Times New Roman', Times, serif;culor#454349;">Findings summary</h2>
                </div>
                <div style="padding:20px 0px">
                    <div style="height: 500px;width:400px">
                        <div style="text-align:left;">
    """
    return HTML_FRAGMENT

def get_summary_footer():
    HTML_FRAGMENT = """
                        </div>
                    </div>
                </div>
            </body>
        </html>
    """
    return HTML_FRAGMENT

def build_summary_html(
        description     = "Summary of finding",
        inspectorScore  = 0,
        cvss            = 'NONE',
        sourceUrl       = 'NONE',
        source          = 'NONE',
        vendorSeverity  = 'NONE',
        packageName     = 'NONE',
        resources       = 'NONE',
        status          = 'NONE',
        severity        = 'NONE',
        title           = 'NONE',
        vulnerabilityId = 'NONE',
    ):
    HTML_FRAGMENT = """
                                <p>Title: """ + str(title) + """</p>
                                <p>Severity: """ + str(severity) + """</p>
                                <p>Description:</p>
                                <p><ul>
                                    """ + str(description) + """
                                </ul></p> 
                                <ul>
                                <p>Status:""" + str(status) + """
                                <p>CVE: <a href='""" + str(sourceUrl) + """'>"""+ str(vulnerabilityId) + """</a>
                                <p>Package Names: """ + str(packageName) + """
                                <p>
                                    Vulnerability  CVSS:
                                        <ul>""" + str(cvss) + """</ul>
                                </p>
                                <p>
                                    Affected Resources
                                        <ul>""" + str(resources) + """</ul>
                                </p>
                                </ul>
    """
    return HTML_FRAGMENT

def build_summary(
        body='NONE'
    ):
    HTML_FRAGMENT = """
        <div style="text-align:left;">
            """ + str(body) + """
        </div>
    """

def build_email(
    findings          = 'NONE',
    region            = 'NONE',
    reponame          = 'NONE',
    imagedigest       = 'NONE',
    tags              = 'NONE',
    resources         = 'NONE',
    fullresultsurl    = 'NONE',
    summaryresultsurl = 'NONE',
    ):
    HTML_FRAGMENT = """
        <!DOCTYPE html>
        <html>
            <body>
                <div style="background-color:#eee;padding:10px 20px;">
                    <h2 style="font-family:Georgia, 'Times New Roman', Times, serif;culor#454349;">CVE findings</h2>
                </div>
                <div style="padding:20px 0px">
                    <div style="height: 500px;width:400px">
                        <div style="text-align:left;">
                            <h3>Findings</h3>
                            <p><ul>
                                """ + str(findings) + """
                            </ul></p>                            
                            Region
                            <p><ul>
                                """ + str(region) + """
                            </ul></p>
                            Repository
                            <p><ul>
                                """ + str(reponame) + """
                            </ul></p>
                            Image Hash Number
                            <p><ul>
                                """ + str(imagedigest) + """
                            </ul></p>
                            Tags
                            <p><ul>
                                """ + str(tags) + """
                            </ul></p>
                            Resources
                            <p><ul>
                                """ + str(resources) + """
                            </ul></p>
                            <p><ul>
                                <a href=""" + str(summaryresultsurl).strip('\()') + """>Summary results</a>
                            </ul></p>                                
                            <p><ul>
                                <a href=""" + str(fullresultsurl).strip('\()') + """>Full results</a>
                            </ul></p>
                        </div>
                    </div>
                </div>
            </body>
        </html>
    """
    return HTML_FRAGMENT
#SNS isn't nicely formatted, so this provides the nicest formatting possible, with the details that matter.
#Defaults are simply to display nothing if no values are set - scans ideally have no findings so a none is okay.
def build_sns(
    findings          = 'NONE',
    region            = 'NONE',
    reponame          = 'NONE',
    imagedigest       = 'NONE',
    tags              = 'NONE',
    resources         = 'NONE',
    fullresultsurl    = 'NONE',
    summaryresultsurl = 'NONE',
    ):
    MESSAGE_BODY = """
        Findings: """ + str(findings).strip('\()').replace("'", "") + """
        Region: """ + str(region).strip('\()').replace("'", "") + """
        Repository: """ + str(reponame).strip('\()').replace("'", "") + """
        Image Hash Number: """ + str(imagedigest).strip('\()').replace("'", "") + """
        Tags: """ + str(tags).strip('\()').replace("'", "") + """
        Resources: """ + str(resources).strip('\()').replace("'", "") + """
        Summary Results: """ + str(summaryresultsurl).strip('\()').replace("'", "") + """
        Full Results: """ + str(fullresultsurl).strip('\()').replace("'", "") + """
        See summary and full results links for details.
        """
    return MESSAGE_BODY 

#This is used for SES or other email types. This will create headers for the email.
def send_email(client, body, subject, from_address, to_address):
    response = client.send_email(
        Source=from_address,
        Destination={
            'ToAddresses': [
                to_address,
            ],
        },
        Message={
            'Subject': {
                'Data': subject,
                'Charset': 'UTF-8'
            },
            'Body': {
                'Html': {
                    'Data': body,
                    'Charset': 'UTF-8'
                }
            }
        },
    )
