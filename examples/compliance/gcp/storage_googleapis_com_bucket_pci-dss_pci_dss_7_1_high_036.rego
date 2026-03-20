package crowdstrike

# Storage Bucket Access Limitations
# Framework: PCI-DSS Requirement 7.1
# Control ID: PCI-DSS-7.1
# Severity: HIGH
# Description: Storage buckets should limit access to cardholder data by business need-to-know

default result := "fail"

# Skip non-storage.googleapis.com/Bucket resources
result = "skip" if {
    input.resource_type != "storage.googleapis.com/Bucket"
}

# Pass if lifecycle policy exists for data management
result = "pass" if {
    input.resource_type == "storage.googleapis.com/Bucket"
    input.configuration.lifecycle.rule
    count(input.configuration.lifecycle.rule) > 0
}
