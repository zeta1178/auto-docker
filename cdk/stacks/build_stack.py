from constructs import Construct
from aws_cdk import (
    Stack,
    RemovalPolicy,
    Duration,
    Aws,
    Aspects,
    aws_codepipeline_actions,
    aws_events_targets,
    aws_codepipeline,
    aws_secretsmanager,
    aws_codebuild,
    aws_iam,
    aws_lambda,
    aws_events_targets as aws_targets,
    aws_ecr,
    aws_sns,
    aws_stepfunctions,
    aws_s3,
    aws_ssm,
    aws_events,  
    aws_kms,
)
from cdk_nag import (
    AwsSolutionsChecks, 
    NagSuppressions, 
)


class BuildStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, namespace, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        #Setup of variables. 
        artifact_bucket_arn = aws_ssm.StringParameter.value_from_lookup(
            self, "/amtrak/devsecops/container-build-pipeline/artifact-bucket"
        )        
        scanner_stepfunction_arn = aws_ssm.StringParameter.value_from_lookup(
            self, "/amtrak/devsecops/container-build-pipeline/scanner-arn"
        )
        validate_date_function_arn = aws_ssm.StringParameter.value_from_lookup(
            self, "/amtrak/devsecops/container-build-pipeline/validate-date-function"
        )

        topic_key_arn = aws_ssm.StringParameter.value_from_lookup(
            self, "/amtrak/devsecops/container-build-pipeline/topic-key"
        )        

        if artifact_bucket_arn.startswith("dummy-value-for-"):
            artifact_bucket_arn        = "arn:aws:s3:::dummy-role-arn"

        if scanner_stepfunction_arn.startswith("dummy-value-for-"):
            scanner_stepfunction_arn   = f"arn:aws:states:{Aws.REGION}:{Aws.ACCOUNT_ID}:dummy-role-arn"

        if validate_date_function_arn.startswith("dummy-value-for-"):
            validate_date_function_arn = f"arn:aws:lambda:{Aws.REGION}:{Aws.ACCOUNT_ID}:dummy-role-arn"

        if topic_key_arn.startswith("dummy-value-for-"):
            topic_key_arn              = f"arn:aws:kms:{Aws.REGION}:{Aws.ACCOUNT_ID}:key/dummy-role-arn"


        artifact_bucket        = aws_s3.Bucket.from_bucket_arn(self, "ArtifactBucket", artifact_bucket_arn)
        validate_date_function = aws_lambda.Function.from_function_arn(self, "ValidateDateFunction", validate_date_function_arn)
        scanner_stepfunction   = aws_stepfunctions.StateMachine.from_state_machine_arn(self, "StateMachine", scanner_stepfunction_arn)
        topic_key              = aws_kms.Key.from_key_arn(self, "TopicKey", topic_key_arn)

        image_repo = aws_ecr.Repository(
            self, "ECR",
            repository_name=namespace,
            removal_policy=RemovalPolicy.DESTROY,
            image_scan_on_push=True
        )             
        
        ironbank_credentials = aws_secretsmanager.Secret.from_secret_name_v2(
            self, "ironbank_user", "/amtrak/devsecops/codebuild/ironbank/credentials"         
        )  

        codebuild_role = aws_iam.Role(self, "codebuild_role",
            assumed_by=aws_iam.ServicePrincipal("codebuild.amazonaws.com")
        )

        codepipeline_role = aws_iam.Role(self, "codepipeline_role",
            assumed_by=aws_iam.ServicePrincipal("codepipeline.amazonaws.com")
        )        

        ironbank_credentials.grant_read(codebuild_role)  
        artifact_bucket.grant_read_write(codepipeline_role)
        artifact_bucket.grant_read_write(codebuild_role)
        codepipeline_role.grant_assume_role(codebuild_role)

        cb_docker_build = aws_codebuild.PipelineProject(
            self, "DockerBuild",
            encryption_key=topic_key,
            role=codebuild_role,

            #For either buildspec approach minimize the number of variations where possible. Many variations increase
            #technical debt and the cost of updates.

            #This approach allows the buildspec to be pulled in from the target repo. This gives anyone who manages
            #that repo the ability to do anything that Codebuild can do.

            #build_spec=aws_codebuild.BuildSpec.from_source_filename(
            #    filename='docker_build_buildspec.yml'),

            #This approach keeps the buildspec contained in the CDK project. It still allows people to append items to each stage
            #and simplifies usage. The downside is the complete buildspec is obscured and customized buildspecs may be needed
            #to support multiple private repositories, not use private repositories, etc. 
            build_spec=aws_codebuild.BuildSpec.from_object_to_yaml({
                "version": "0.2",
                "phases": {
                    "pre_build": {
                        "commands": [
                            "REPO_TAG=$(date '+%Y%m%d%H%M%S')",
                            "IMAGE_VERSION_TAG=$REPO_NAME-$(date '+%Y%m%d%H%M%S')",
                            "[ -f *.sh ] && chmod +x *.sh",                                                                                
                            "[ -f ./pre-build.sh ] && ./pre-build.sh",                                                                
                            "echo Logging in to Amazon ECR...",
                            "aws ecr get-login-password --region $AWS_DEFAULT_REGION | docker login --username AWS --password-stdin $ACCT_ID.dkr.ecr.$AWS_DEFAULT_REGION.amazonaws.com",
                        ]
                    },
                    "build": {
                        "commands": [
                            "echo Build started on `date`",
                            "[ -f ./build.sh ] && ./build.sh",                          
                            "echo login to IronBank...",
                            "echo $IB_PASS | docker login registry1.dso.mil -u $IB_USER --password-stdin",
                            "echo Building the Docker image...",
                            "docker build -t $REPO_NAME:$REPO_TAG . --build-arg BASE_DATE=$REPO_TAG",
                            "docker tag $REPO_NAME:$REPO_TAG $ECR_URI:$IMAGE_VERSION_TAG",
                        ]
                    },
                    "post_build": {
                        "commands": [
                            "echo Build completed on `date`",
                            "[ -f ./post-build.sh ] && ./post-build.sh",                          
                            "echo Pushing the Docker image...",
                            "docker push $ECR_URI:$IMAGE_VERSION_TAG",
                            "printf '[{\"name\":\"Docker-Image\",\"imageUri\":\"%s\"}]' \"$ECR_URI:$IMAGE_VERSION_TAG\" > image.json",
                            "cat image.json"                         
                        ]
                    }
                },
                "shell": "bash",
                "artifact": {
                    "files": "image.json"
                },
                "env": {
                    "secrets-manager" : {
                        'IB_USER'  : "/amtrak/devsecops/codebuild/ironbank/credentials:user",
                        'IB_PASS'  : "/amtrak/devsecops/codebuild/ironbank/credentials:password",
                    }    
                },
            }),

            environment=aws_codebuild.BuildEnvironment(
                privileged=True,
            ),
            #These values let CodeBuild know where to push images into after they are built. This uses the previously generated 
            #ECR repos.
            environment_variables={
                'ECR_URI': aws_codebuild.BuildEnvironmentVariable(
                    value=image_repo.repository_uri),
                'ECR_NAME': aws_codebuild.BuildEnvironmentVariable(
                    value=image_repo.repository_name),
                'ACCT_ID': aws_codebuild.BuildEnvironmentVariable(
                    value=Aws.ACCOUNT_ID),
                'REPO_NAME': aws_codebuild.BuildEnvironmentVariable(
                    value=namespace),
            },
            description='Pipeline for CodeBuild',
            timeout=Duration.minutes(60),
        )

        # define the s3 artifact
        source_output = aws_codepipeline.Artifact(artifact_name='source')
        source_action = aws_codepipeline_actions.S3SourceAction(
            action_name="S3Source",
            bucket_key=f"DEVOPS/{namespace}/master.zip",
            bucket=artifact_bucket,
            output=source_output
        )

        build_action = aws_codepipeline_actions.CodeBuildAction(
            action_name="CodeBuild",
            project=cb_docker_build,
            input=source_output,
            outputs=[aws_codepipeline.Artifact()],  # optional
            #execute_batch_build=True,  # optional, defaults to false
            #combine_batch_build_artifacts=True
        )

        pipeline = aws_codepipeline.Pipeline(self, "BuildImage",
            role=codepipeline_role,
            stages=[aws_codepipeline.StageProps(
                stage_name="Source",
                actions=[source_action]
            ), aws_codepipeline.StageProps(
                stage_name="Build",
                actions=[build_action]
            )
            ],
            artifact_bucket=artifact_bucket
        )        

        topic = aws_sns.Topic(self, "Topic",
            display_name="CodeBuild Notification Topic",
            master_key=topic_key
        )           

        topic.grant_publish(codebuild_role)

        sf_target=aws_targets.SfnStateMachine(
            scanner_stepfunction
        )

        #We want CodeBuild to be able to push to the generated Repo.
        image_repo.grant_pull_push(codebuild_role)
       
        #initial_upload_complete.add_target(sf_target)
        image_repo.on_image_scan_completed("ImageScanCompleted").add_target(sf_target) #Scan images upon upload.

        verify_target=aws_targets.LambdaFunction(validate_date_function)
        #We want to catch not just initial scans, but also scans when new CVE's are published. 
        inspector_scan_event_bridge_rule = aws_events.Rule(self, "InspectorScanFinding",
            event_pattern=aws_events.EventPattern(
                source=["aws.inspector2"],
                detail={
                    "detail-type": ["Inspector2 Finding"],
                    "repository-name": [ image_repo.repository_name ],
                    "detail.resources.0.type": [ { "prefix": "AWS_ECR_CONTAINER_IMAGE" } ],
                },
            )
        )        
        inspector_scan_event_bridge_rule.add_target(verify_target)  
                                                                            
        #This uses cron patterns to run the Pipeline. This will take the last S3 object uploaded, and re-build the container.
        #The dockerfile must contain update commands or the rebuilt image will be similar to the last image.
        cb_target = aws_events_targets.CodePipeline(pipeline)
        EventWeeklyRule = aws_events.Rule(self, "ScheduleRule",
            schedule=aws_events.Schedule.cron(day="*", minute="00", hour="23"),
            targets=[cb_target]
        )
        Aspects.of(self).add(AwsSolutionsChecks())
        NagSuppressions.add_stack_suppressions(
            self,
            suppressions=[
                {
                    "id": "AwsSolutions-IAM5", 
                    "reason": "CodeBuild/CodePipeline have wildcard S3 actions, but restricted to only the artifactbucket."
                }
            ]
        )
        NagSuppressions.add_stack_suppressions(
            self,
            suppressions=[
                {
                    "id": "AwsSolutions-CB3", 
                    "reason": "CodeBuild is creating Docker images. Priviledged mode is needed."
                }
            ]
        )        
