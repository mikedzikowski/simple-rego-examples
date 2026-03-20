package crowdstrike

# Simple Azure Storage HTTPS Check
# Description: Basic example to check if Azure Storage accounts require HTTPS

default result := "fail"

# Skip non-Azure Storage resources
result = "skip" if {
    input.resource_type != "Microsoft.Storage/storageAccounts"
}

# Pass if HTTPS is enforced
result = "pass" if {
    input.resource_type == "Microsoft.Storage/storageAccounts"
    input.configuration.enableHttpsTrafficOnly == true
}