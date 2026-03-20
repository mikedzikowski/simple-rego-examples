package crowdstrike

# Ensure EKS API Server is Not Publicly Accessible
# Framework: CIS Kubernetes Benchmark v1.6.0
# Control ID: CIS-K8S-1.2.1
# Severity: CRITICAL
# Description: EKS clusters should not expose API server publicly

default result := "fail"

# Skip non-AWS::EKS::Cluster resources
result = "skip" if {
    input.resource_type != "AWS::EKS::Cluster"
}

# Pass if API server is not publicly accessible
result = "pass" if {
    input.resource_type == "AWS::EKS::Cluster"
    input.configuration.resourcesVpcConfig.endpointPublicAccess == false
}

# Alternative: Pass if public access is restricted (not open to 0.0.0.0/0)
result = "pass" if {
    input.resource_type == "AWS::EKS::Cluster"
    input.configuration.resourcesVpcConfig.endpointPublicAccess == true
    input.configuration.resourcesVpcConfig.endpointPrivateAccess == true
    not "0.0.0.0/0" in input.configuration.resourcesVpcConfig.publicAccessCidrs
}
