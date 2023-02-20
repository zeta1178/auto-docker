import json
import aws_cdk as cdk
from aws_cdk import (
    Duration,
    Stack,
    NestedStack,
    NestedStackProps,
    RemovalPolicy,
    aws_stepfunctions_tasks as tasks,
    aws_ecr,
    aws_lambda,
    aws_stepfunctions as sfn,
    aws_logs,
    aws_inspectorv2 as inspector,
    aws_kms,
    aws_ssm,
    aws_events,
    aws_sns as sns,
    aws_lambda,
    aws_apigateway,
    aws_iam,    
    aws_s3,
    aws_ec2,
    aws_secretsmanager,
    aws_s3_deployment,
    aws_s3_assets as assets,
    aws_codebuild,
    Environment,
    Fn,
    CfnDynamicReference,
    CfnDynamicReferenceService,
    SecretValue,
)
from constructs import Construct
import os

class ScannerStack(Stack): 

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        def security_group(id):
            return aws_ec2.SecurityGroup.from_security_group_id(self, id, id)     

        #Setup of variables. Lambda runs in a VPC, no egress traffic.
        subnet_id_1 = aws_ssm.StringParameter.value_from_lookup(
            self, "/amtrak/cloud-solutions/lambda/subnet1")
        subnet_id_2 = aws_ssm.StringParameter.value_from_lookup(
            self, "/amtrak/cloud-solutions/lambda/subnet2")
        vpc_id = aws_ssm.StringParameter.value_from_lookup(
            self, "/amtrak/cloud-solutions/vpc")
        sg_id_1 = aws_ssm.StringParameter.value_from_lookup(
            self, "/amtrak/cloud-solutions/lambda/security-group-id")
        bitbucket_uri = aws_ssm.StringParameter.value_from_lookup(
            self, "/amtrak/cloud-solutions/devsecops/bitbucket/uri")            
        vpc = aws_ec2.Vpc.from_lookup(self, 'vpc',
          vpc_id = vpc_id,
        )        

        subnet_1         = aws_ec2.Subnet.from_subnet_id(self, "subnet1", subnet_id_1)        
        subnet_2         = aws_ec2.Subnet.from_subnet_id(self, "subnet2", subnet_id_2)
        security_group_1 = aws_ec2.SecurityGroup.from_security_group_id(self, "Lambda Security Group", sg_id_1)
        vpc_subnets      = aws_ec2.SubnetSelection(subnets=[subnet_1, subnet_2])            

        #This creates Secrets Manager credentials for a user and password allowing the Lambda function to generate a pre-signed URL that lasts longer 
        #than 6 hours. This also creates an access key which can and should have rotation policies created, and grants access to the Lambda function 
        #to utilize them to signed URL's.
        vulnerability_report_user = aws_iam.User(self, "ECRScannerS3User")

        report_bucket = aws_s3.Bucket(
            self, "ReportBucket",
            versioned=False,
            enforce_ssl=True,
            intelligent_tiering_configurations=[aws_s3.IntelligentTieringConfiguration(
                name="VulnerabilityReportArchive",
                archive_access_tier_time=Duration.days(90),
                deep_archive_access_tier_time=Duration.days(180),
            )],
            object_ownership=aws_s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
            block_public_access=aws_s3.BlockPublicAccess.BLOCK_ALL,
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
        )        

        #The report bucket is used to store Inspector reports, and the Inspector service needs access to S3 permissions. The arnlike string can be 
        #made more specific, and the resources ARN can be scoped as well.
        report_bucket.add_to_resource_policy(aws_iam.PolicyStatement(
            effect=aws_iam.Effect.ALLOW,
            actions=["s3:putObject", "s3:putObjectACL", "s3:AbortMultipartUpload"],
            resources=[f'{report_bucket.bucket_arn}/*'],
            principals=[aws_iam.ServicePrincipal("inspector2.amazonaws.com")],
            conditions={
                'StringEquals': {
                    'aws:SourceAccount': f'{self.account}',
                },
                'ArnLike': {
                    'aws:SourceArn': f'arn:aws:inspector2:{self.region}:{self.account}:report/*'
                }
            },
        ))        

        #This is a catch-all in case no results are found. This can occur when an un-supported image type is passed to Inspector, if something
        #goes wrong during the scan, etc. Failures should be rare, but this prevents malformed notifications with a pre-generated report that 
        #can be customized as-needed. This can also be used as a failsafe - message contents can indicate manual review is necessary and this can
        #be extended to cover high or critical findings - or even used for custom filtering - IE, a cryptographic library always triggers a manual review.
        aws_s3_deployment.BucketDeployment(self, "DeployNoFindingsTemplate",
            sources=[aws_s3_deployment.Source.asset("./assets/", exclude=["*", "!no_findings.html"])],
            destination_bucket=report_bucket,
            destination_key_prefix='report',
            prune=False
        )     

        #This is created so that pre-signed URL's work - this is an additional user granted read access to the S3 repo. This user is used to 
        #pre-sign URL's so that vulnerability reviewers can securely download them without signing in, or granting public access to these repos.
        report_bucket.grant_read(vulnerability_report_user)

        #This key is used by the Inspector service to encrypt vulnerability findings. The resource policy lets the Inspector service decrypt, encrypt, 
        #and generate a key only for reports from this account, and a single region.
        inspector_key = aws_kms.Key(self, "InspectorKMSKey",
            enable_key_rotation=True,
            ##alias='S3ReportKey'
        )
        inspector_key.add_to_resource_policy(aws_iam.PolicyStatement(
            effect=aws_iam.Effect.ALLOW,
            actions=["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey*"],
            resources=['*'],
            principals=[aws_iam.ServicePrincipal("inspector2.amazonaws.com")],
            conditions={
                'StringEquals': {
                     'aws:SourceAccount': f'{self.account}',
                },
                'ArnLike': {
                     'aws:SourceArn': f'arn:aws:inspector2:{self.region}:{self.account}:report/*'
                }
            },
        ))
        inspector_key.grant_decrypt(vulnerability_report_user) 

        #This is created so that pre-signed URL's work - this is an additional user granted read access to the S3 repo. This user is used to 
        #pre-sign URL's so that vulnerability reviewers can securely download them without signing in, or granting public access to these repos.
        report_bucket.grant_read(vulnerability_report_user)        

        inspector_key.add_to_resource_policy(aws_iam.PolicyStatement(
            effect=aws_iam.Effect.ALLOW,
            actions=["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey*"],
            resources=['*'],
            principals=[aws_iam.ServicePrincipal("inspector2.amazonaws.com")],
            conditions={
                'StringEquals': {
                     'aws:SourceAccount': f'{self.account}',
                },
                'ArnLike': {
                     'aws:SourceArn': f'arn:aws:inspector2:{self.region}:{self.account}:report/*'
                }
            },
        ))
        inspector_key.grant_decrypt(vulnerability_report_user)

        #This creates an IAM key that lets the Lambda function build a report and generate a pre-signed URL. Without this the report would quickly
        #Expire.
        access_key = aws_iam.AccessKey(self, "ECRScannerS3UserKey", user=vulnerability_report_user)

        #This stores the access key and secret key in SSM. This allows the function to utilize the IAM user without
        #Storing credentials in a non-secure location.
        create_vulnerability_report_user_secret = aws_secretsmanager.Secret(self, "ECRScannerS3UserCreds",
                secret_string_value=access_key.secret_access_key
        )

        image_param = aws_ssm.StringParameter(
            self, "ImageParameter",
            string_value="IN_PROGRESS",
            description='Param for Lambda'
        )        

        #Including Boto with your Lambda function isn't mandatory, but it is a good practice as it ensures included features are present.
        #In this case, inspector2 features were not present in the included Lambda Boto3 version. This layer is attached to all included Lambda
        #functions to simplify updates and management.
        boto_layer = aws_lambda.LayerVersion(self, "BotoLayer",
            removal_policy=RemovalPolicy.DESTROY,
            code = aws_lambda.AssetCode('lambda/layer/boto3'),
            compatible_runtimes = [aws_lambda.Runtime.PYTHON_3_9],
        )        

        lambda_filter_role = aws_iam.Role(self, "lambda_filter_role",
            assumed_by=aws_iam.ServicePrincipal("lambda.amazonaws.com")
        ) 
        lambda_filter_role.add_managed_policy(aws_iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole"))
        lambda_filter_role.add_managed_policy(aws_iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaVPCAccessExecutionRole"))        
        
        lambda_parser_role = aws_iam.Role(self, "lambda_parser_role",
            assumed_by=aws_iam.ServicePrincipal("lambda.amazonaws.com")
        )                 
        lambda_parser_role.add_managed_policy(aws_iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole"))
        lambda_parser_role.add_managed_policy(aws_iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaVPCAccessExecutionRole"))

        lambda_promotion_role = aws_iam.Role(self, "lambda_promotion_role",
            assumed_by=aws_iam.ServicePrincipal("lambda.amazonaws.com")
        )                 
        lambda_promotion_role.add_managed_policy(aws_iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole"))
        lambda_promotion_role.add_managed_policy(aws_iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaVPCAccessExecutionRole"))

        #This function takes the Image hash from the uploaded Docker image and begins an inspector report for it. This function currently has the Boto3 package included in the Git archive as the Lambda environment 
        #only has Boto3 1.18 which includes an old version of the Inspector libraries. See https://docs.aws.amazon.com/lambda/latest/dg/lambda-python.html for the current version. 
        #Once this is 1.21 or newer the Boto3 dependencies can be removed. The inspector_statement lines add permission to make inspector2 API calls. 
        #This function is invoked by the StepFunction service which loops over it until the report finishes. A retry is included in case the original request fails.
        filter_function = aws_lambda.Function(self, 'VulnerabilityScannerFilter',
          code=aws_lambda.AssetCode('lambda/filter'),
          runtime=aws_lambda.Runtime.PYTHON_3_9,
          layers=[boto_layer],
          timeout=Duration.seconds(300),
          memory_size=512,
          tracing = aws_lambda.Tracing.ACTIVE,
          insights_version=aws_lambda.LambdaInsightsVersion.VERSION_1_0_98_0,
          vpc = vpc,
          vpc_subnets=vpc_subnets,          
          handler='lambda_function.lambda_handler',
          role=lambda_filter_role,
          #security_groups=[sg_id],  
          #security_groups = security_groups        
          environment={
              "BUCKET": report_bucket.bucket_name,
              "KMSKEY": inspector_key.key_arn
          } #This environment variable is used to store the Vulnerable results per scan.
        )
        inspector_statement = aws_iam.PolicyStatement()
        inspector_statement.add_actions("inspector2:ListFindings", "inspector2:CreateFindingsReport", "inspector2:GetFindingsReportStatus")
        inspector_statement.add_resources("*") #This adds to the Lambda function a policy granting access to the inspector v2 API.
        filter_function.add_to_role_policy(inspector_statement) #This adds the policy to the role.

        #This function is invoked by the StepFunction service and consumes the report generated from the Filter Lambda function. 
        #It creates a HTML formatted email using the SES service and in the output includes details that StepFunctions sends to the SNS service 
        #for consumation by automated systems, text notifications, or simple (unformatted) emails. A single retry is included in case one 
        #of the calls fails.
        parser_function = aws_lambda.Function(self, 'VulnerabilityScannerParser',
          code=aws_lambda.AssetCode('lambda/parser'),
          runtime=aws_lambda.Runtime.PYTHON_3_9,
          timeout=Duration.seconds(300),
          memory_size=3008,
          layers=[boto_layer],
          handler='lambda_function.lambda_handler',
          role=lambda_parser_role,
          tracing = aws_lambda.Tracing.ACTIVE,
          insights_version=aws_lambda.LambdaInsightsVersion.VERSION_1_0_98_0,
          vpc = vpc,
          vpc_subnets=vpc_subnets,           
          #security_groups=[sg_id],          
          environment={
              "BUCKET": report_bucket.bucket_name, #This is used by the Inspector service to store results.
              "KMSKEY": inspector_key.key_arn, #This is used by the Inspector service to store results.
              "SECRET_ID": create_vulnerability_report_user_secret.secret_name, #This is used for pre-signed URL's for S3 keys.
              "ACCESS_KEY_ID": access_key.access_key_id, #This is used for pre-signed URL's for S3 keys.
              "API": "amazon.com" #api.rest_api_id, #This is consumed to build the email sent via SNS/SES.
          }
        )
        
        #This grants decrypt permissions to the Parser Lambda function so it can read the Inspector findings.
        inspector_key.grant_decrypt(parser_function)
        #The parser function needs to be able to save summary finding reports to the S3 bucket as well. This allows the generated email to contain pre-signed links 
        #allowing anyone on the email distrobution list to consume them.
        report_bucket.grant_read_write(parser_function) 
        #This grands both read and write access to both the filter Lambda function to the S3 bucket used to store reports.
        report_bucket.grant_read_write(filter_function) 

        #These lines grant access to the Parser function to send nicely formatted emails via the SES service. Note that the email address can be configured to pull via Environment variables, or SSM params.
        ses_statement=aws_iam.PolicyStatement()
        ses_statement.add_actions("ses:SendEmail", "ses:SendRawEmail")
        ses_statement.add_resources("*")
        parser_function.add_to_role_policy(ses_statement)

        #This allows the Lambda function to read from a SSM Parameter store value for the email distrolist. This can also be defined in CDK instead (prevents a SSM lookup each invoke) 
        #at the cost of being less intuitive (have to manage the Lambda env value or re-run the CDK stack to update an email address.)
        ssm_statement=aws_iam.PolicyStatement()
        ssm_statement.add_actions("ssm:GetParameter")

        ssm_statement.add_resources(f'arn:aws:ssm:{self.region}:{self.account}:parameter/amtrak/cloud-solutions/devsecops/ecr/email')
        parser_function.add_to_role_policy(ssm_statement)
        parser_role=aws_iam.Role.from_role_name(self, "parser_function_role", parser_function.role.role_arn)

        #Ensure the Parser function can utilize an IAM User to pre-sign URL's for the reports. This is needed because otherwise 
        #reports would expire quickly (within minutes).
        create_vulnerability_report_user_secret.grant_read(parser_function)

        promote_approval = sfn.Succeed(self, "Completed.")
        no_notification = sfn.Succeed(self, "No notification needed. Successful.")
        completed = sfn.Succeed(self, "Completed")

        #This step is a visual to help understand why the Filter loop failed as StepFunction logs can be verbose.
        notify_step = sfn.Pass(self, "Notification stage")

        #These steps help track with a visual if the Parser function completed successfully, or if something went wrong.
        processing_complete = sfn.Pass(self, "Findings acknowledged.")
        #send_failure = tasks.SnsPublish(self, "Publish message",
        report_failure_notify = tasks.SnsPublish(self, "Notification formatting failed.",
            topic=sns.Topic(self, "report-failure-topic"),
            message=sfn.TaskInput.from_object({
                "message": "Could not generate email summary of findings, manual review required.",
                "detail": sfn.JsonPath.string_at("$.message.detail")
            })            
        )  

        notify_failure_notify = tasks.SnsPublish(self, "Notification sending failed.",
            topic=sns.Topic(self, "publish-failure-topic"),
            message=sfn.TaskInput.from_object({
                "message": "Could not send message to teams.",
                "detail": sfn.JsonPath.string_at("$.message.detail")
            })            
        ) 

        inspector_failure_notify = tasks.SnsPublish(self, "Inspector scan failed.",
            topic=sns.Topic(self, "inspector-failure-topic"),
            message=sfn.TaskInput.from_object({
                "message": "Inspector scan failed. Manual review required.",
                "detail": sfn.JsonPath.string_at("$.message.detail")
            })            
        )

        finding_failure = sfn.Fail(self, "Process failed. Manual review required.",
            error="FindingFailure",
            cause="Manual review of the image is required."
        )

        #This is the StepFunctions Lambda task. This runs in a loop until the Inspector report completes. It adds findings to the output 
        #(result path) to be consumed by the Parser function. 
        get_results = tasks.LambdaInvoke(self, "Get Finding Results",
            lambda_function=filter_function,
            result_path='$.finding',
            result_selector={
                'ReportId': sfn.JsonPath.string_at("$.Payload.ReportId"),
                'KmsKeyArn': sfn.JsonPath.string_at("$.Payload.KmsKeyArn"), 
                'Bucket': sfn.JsonPath.string_at("$.Payload.Bucket"),
                'Status': sfn.JsonPath.string_at("$.Payload.Status"),
                'digest': sfn.JsonPath.string_at("$.Payload.digest"),
                'repo_name': sfn.JsonPath.string_at("$.Payload.repo_name"),
                'sfn_arn': 'NONE',
            },
            retry_on_service_exceptions=True
        )
        get_results.add_retry(max_attempts=5)

        #This is the StepFunctions wrapper for the Parser Lambda task. 
        process_findings = tasks.LambdaInvoke(self, "Process Results",
            lambda_function=parser_function,
            result_path='$.report',
            output_path='$.report',
            result_selector={
                'notify': sfn.JsonPath.string_at("$.Payload.notify"),
                'message': sfn.JsonPath.string_at("$.Payload.message"),
                'image_digest': sfn.JsonPath.string_at("$.Payload.image_digest"),
                'repo_name': sfn.JsonPath.string_at("$.Payload.repo_name"),
                #'param': sfn.JsonPath.string_at("$.Payload.param"),
            },
            retry_on_service_exceptions=True
        )
        process_findings.add_catch(report_failure_notify.next(finding_failure))

        #This workflow is used to notify the security team. This can be via subscriptions (text, email) or application subscriptions 
        #(automated workflows). Escalation can be baked into this process by adding StepFunction activities and wait states and adjusting 
        #timeouts. This way a team may need to click a link within a period, it rolls up to leadership if nothing occurs 
        #within 15m, the up the chain, etc.
        notify_security = tasks.SnsPublish(self, "Send Security SNS message",
            topic=sns.Topic(self, "security-topic"),
            message=sfn.TaskInput.from_json_path_at("$.message"),
            result_path="$.finding.security",
            message_per_subscription_type=True,
        )

        #This workflow is used to notify developers. This can be via subscriptions (text, email) or application subscriptions (automated workflows). 
        #Escalation can be baked into this process by adding StepFunction activities and wait states and adjusting timeouts. This way a team may 
        #need to click a link with a period, it rolls up to leadership if nothing occurs within 15m, the up the chain, etc.

        notify_developers = tasks.SnsPublish(self, "Send Developers SNS message",
            topic=sns.Topic(self, "dev-topic"),
            message=sfn.TaskInput.from_json_path_at("$.message"),
            result_path="$.finding.devs",
            message_per_subscription_type=True
        )

        # What to do in case everything succeeded
        close_notify = sfn.Pass(self, "Notification Successful")

        #This creates the StepFunction LogGroup.
        sf_log_group = aws_logs.LogGroup(self, "image_approval")

        #This wait is used by the Filter Lambda task while it loops waiting for the inspector report to complete. 
        findings_wait = sfn.Wait(self, "Wait",
            time=sfn.WaitTime.duration(Duration.seconds(10))
        ).next(get_results) #This is defining a wait state for the StepFunction workflow.

        findings_complete = sfn.Choice(self, "Wait for Findings Report to complete")
        findings_complete.when(sfn.Condition.is_not_present("$.finding.Status"), get_results.next(findings_complete))
        findings_complete.when(sfn.Condition.string_equals("$.finding.Status", "SUCCEEDED"), process_findings)
        findings_complete.when(sfn.Condition.string_equals("$.finding.Status", "NO_FINDINGS"), process_findings)
        findings_complete.when(sfn.Condition.string_equals("$.finding.Status", "FAILED"), findings_wait)
        findings_complete.when(sfn.Condition.string_equals("$.finding.Status", "IN_PROGRESS"), findings_wait)
        findings_complete.when(sfn.Condition.string_equals("$.finding.Status", "REPORT_GENERATION_FAILED"), findings_wait)
        findings_complete.otherwise(inspector_failure_notify.next(finding_failure))

        dev_done=sfn.Pass(self, "No developer notificiations.")
        sec_done=sfn.Pass(self, "No security notificiations.")

        #Decision to notify or not based on logic from Promotion function.
        notify_devs = sfn.Choice(self, "Send SNS to Developers?")
        notify_devs.when(sfn.Condition.boolean_equals("$.notify.developers", True), notify_developers)
        notify_devs.otherwise(dev_done)
        #notify_devs.afterwards().next(dev_done)

        #Decision to notify or not based on logic from Promotion function. The security team decides
        #if this gets promoted, or removed.
        notify_sec = sfn.Choice(self, "Send SNS to Security?")
        notify_sec.when(sfn.Condition.boolean_equals("$.notify.security", True), notify_security)
        notify_sec.otherwise(sec_done)

        parallel = sfn.Parallel(self, "Notify teams of findings.")
        parallel.branch(notify_devs)
        parallel.branch(notify_sec)
        parallel.add_retry(max_attempts=1)
        parallel.add_catch(notify_failure_notify)
        parallel.next(completed)

        #This creates the actual stepfunction states. There are two meain workflows each that have substeps. The first is the filter workflow, the second is the parser and notify workflow.
        definition = findings_complete.afterwards().next(parallel)

        sfn_role = aws_iam.Role(self, "sfn_role",
            assumed_by=aws_iam.ServicePrincipal("states.amazonaws.com")
        ) 

        #This builds the actual State Machine, sets a 15 minute timeout, and sets a very verbose logging level. Adjust the timeout and the log level for prod.
        state_machine = sfn.StateMachine(self, "ScannerWorkflow",
            definition=definition,
            timeout=Duration.minutes(15),
            logs=sfn.LogOptions(
                destination=sf_log_group,
                level=sfn.LogLevel.ALL
            ),
            #role=sfn_role,
        )
        sf_log_group.grant_write(state_machine)
        #This function runs every time a scan result comes in. If the scan result is from a new (<24 hour) image nothing happens.
        #If the image is older it triggers a scan. This allows new CVE's to be caught with the option of 
        validate_image_creation_date_function = aws_lambda.Function(self, 'ValidateDateFunction',
          code=aws_lambda.AssetCode('lambda/validate_date'),
          runtime=aws_lambda.Runtime.PYTHON_3_9,
          #This environment variable is used to store the Vulnerable results per scan.
          timeout=Duration.seconds(30),
          memory_size=128,
          vpc = vpc,
          tracing = aws_lambda.Tracing.ACTIVE,
          insights_version=aws_lambda.LambdaInsightsVersion.VERSION_1_0_98_0,
          vpc_subnets=vpc_subnets,           
          environment={
            "SF_ARN": state_machine.state_machine_arn, #This allows the function to trigger the workflow if it hasn't been scanned
            #in the last 24 hours.
          },          
          handler='lambda_function.lambda_handler',
        )                

        state_machine.grant_start_execution(validate_image_creation_date_function)

        # creates topic for CodeBuild Notifications
        code_build_topic = sns.Topic(self, "code_build_topic",
            # display_name="CodeBuild Notification Topic"
        )

        # creates role for codebuild project 
        codebuild_role = aws_iam.Role(self, "codebuild_role",
          assumed_by=aws_iam.ServicePrincipal("codebuild.amazonaws.com")
        )
        
        # allow role for codebuild to publish to topic
        code_build_topic.grant_publish(codebuild_role)

        aws_ssm.StringParameter(self, "ScannerStepFunction",
            description="This holds the arn for the StepFunction to be consumed by apps.",
            parameter_name="/amtrak/devsecops/container-build-pipeline/scanner-arn",
            string_value=state_machine.state_machine_arn,
        )

        aws_ssm.StringParameter(self, "ScannerValidateDateFunction",
            description="This holds the arn for the StepFunction to be consumed by apps.",
            parameter_name="/amtrak/devsecops/container-build-pipeline/validate-date-function",
            string_value=validate_image_creation_date_function.function_arn,
        )
        self.scanner_stepfunction=state_machine
        self.validate_date_function=validate_image_creation_date_function

        #This key is used by client stacks to encrypt topics. This is shared between stacks.
        topic_key = aws_kms.Key(self, "TopicKey",
            enable_key_rotation=True,
        )        
        aws_ssm.StringParameter(self, "TopicKeyParam",
            description="Key used to encrypt Container Build Pipeline SNS topics.",
            parameter_name="/amtrak/devsecops/container-build-pipeline/topic-key",
            string_value=topic_key.key_arn,
        )        

        
    #Export objects.
    @property
    def outputs(self):
        return self     