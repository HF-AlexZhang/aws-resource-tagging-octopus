ACCOUNT_ID = 532495396307
RESOURCE_FILE = "octopus_resources.yaml"

tags = {
    "Alliance": "scm-tech-procurement",
    "Tribe": "planning-and-procurement-au",
    "Squad": "planning-and-procurement",
    "Project": "Octopus",
}

aws_tags = [{"Key": key, "Value": val} for key, val in tags.items()]
