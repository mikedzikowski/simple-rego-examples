package crowdstrike

# Advanced OCI Instance Security Policy
# Comprehensive security checks for OCI instances including network, encryption, and monitoring

default result := "fail"

# Skip non-OCI Core Instance resources
result = "skip" if {
    input.resource_type != "OCI::Core::Instance"
}

# Helper function to check encryption
is_encrypted(instance) if {
    instance.configuration.sourceDetails.kmsKeyId != ""
}

# Helper function to check network security
secure_network(instance) if {
    # Instance should be in a private subnet
    not instance.configuration.primaryVnic.assignPublicIp
    # Security lists should exist
    count(instance.configuration.primaryVnic.nsgIds) > 0
}

# Helper function to check monitoring
monitoring_enabled(instance) if {
    instance.configuration.agentConfig.isManagementDisabled == false
    instance.configuration.agentConfig.isMonitoringDisabled == false
}

# Helper function to check instance shape security
secure_shape(instance) if {
    # Prefer standard shapes over old generations
    startswith(instance.configuration.shape, "VM.Standard")
    not startswith(instance.configuration.shape, "VM.Standard1")
}

# Pass if all security requirements are met
result = "pass" if {
    input.resource_type == "OCI::Core::Instance"
    is_encrypted(input)
    secure_network(input)
    monitoring_enabled(input)
    secure_shape(input)
}

# Provide specific failure reasons
violation contains msg if {
    input.resource_type == "OCI::Core::Instance"
    not is_encrypted(input)
    msg := "Instance boot volume is not encrypted with customer-managed key"
}

violation contains msg if {
    input.resource_type == "OCI::Core::Instance"
    not secure_network(input)
    msg := "Instance has public IP or insufficient network security groups"
}

violation contains msg if {
    input.resource_type == "OCI::Core::Instance"
    not monitoring_enabled(input)
    msg := "Instance monitoring or management agent is disabled"
}