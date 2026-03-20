package crowdstrike

# Simple OCI Instance Shape Check
# Description: Basic example to check OCI instance shapes

default result := "fail"

# Skip non-OCI Core Instance resources
result = "skip" if {
    input.resource_type != "OCI::Core::Instance"
}

# Pass if using recommended instance shape
result = "pass" if {
    input.resource_type == "OCI::Core::Instance"
    startswith(input.configuration.shape, "VM.Standard")
}

# Also pass for flexible shapes
result = "pass" if {
    input.resource_type == "OCI::Core::Instance"
    contains(input.configuration.shape, "Flex")
}