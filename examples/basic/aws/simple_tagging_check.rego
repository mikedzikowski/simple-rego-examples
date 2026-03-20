package crowdstrike

# Simple Resource Tagging Check
# Description: Basic example to check if resources have required tags

default result := "fail"

# Pass if resource has required tags
result = "pass" if {
    input.tags.Environment
    input.tags.Owner
}

# Allow resources to explicitly opt out with no-tag-check tag
result = "pass" if {
    input.tags["no-tag-check"] == "true"
}