package crowdstrike

# GKE Transmission Confidentiality
# Framework: NIST 800-53 SC-8 (Transmission Confidentiality)
# Control ID: NIST-SC-8
# Severity: HIGH
# Description: GKE clusters should protect transmission confidentiality

default result := "fail"

# Skip non-container.googleapis.com/Cluster resources
result = "skip" if {
    input.resource_type != "container.googleapis.com/Cluster"
}

# Pass if encryption is enabled
result = "pass" if {
    input.resource_type == "container.googleapis.com/Cluster"
    input.configuration.databaseEncryption.state == "ENCRYPTED"
}
