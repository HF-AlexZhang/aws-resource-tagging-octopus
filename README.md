## Introduction
This repository contains scripts designed to efficiently tag all existing AWS resources for Octopus. While these scripts are valuable for initial tagging, they become unnecessary once all AWS resources are imported into Terraform for ongoing management

## Quick Start

### Authenticate to AWS
Before using the provided scripts, make sure you authenticate to your AWS account by setting environment variables for your AWS access key and secret key. You can do this using the following commands:
```
export AWS_DEFAULT_REGION=ap-southeast-2
export AWS_ACCESS_KEY_ID=your-access-key-id
export AWS_SECRET_ACCESS_KEY=your-secret-access-key
```
### Tag Resources

Run the following command to tag all resources based on the defined tagging logic:

```shell
python tag_resources.py
```

### Validate Tags

To ensure that all the resources have received the expected tags, you can use the unit tests provided:

```shell
pytest test_resource_tagging.py -s
```

### Retrieve Octopus Resources
Execute this command to retrieve a list of Octopus resources. Please be aware that certain AWS resources are not supported by the Resource Groups Tagging API.

```shell
aws resourcegroupstaggingapi get-resources --output json | jq -r '.ResourceTagMappingList[] | select(.ResourceARN | test("octopus"; "i")) | .ResourceARN'
```
