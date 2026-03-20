# 🛡️ CrowdStrike Security Policy Examples

This directory contains **comprehensive security policy examples** organized by complexity and purpose to help you implement effective cloud security posture management with CrowdStrike Falcon. Each directory follows a consistent cloud provider structure (AWS, Azure, GCP, OCI).

## 📁 **Directory Structure**

### 🎯 **Basic Examples** (`/basic/`)
Simple, straightforward policy examples perfect for learning Rego fundamentals:

#### AWS (`/basic/aws/`)
- **simple_s3_public_access.rego**: Check S3 bucket public access settings
- **simple_ec2_ssh_check.rego**: Verify EC2 SSH security configurations
- **simple_tagging_check.rego**: Basic resource tagging validation

#### Azure (`/basic/azure/`)
- **simple_azure_https_check.rego**: Azure Storage HTTPS enforcement
- **simple_keyvault_access.rego**: Basic Key Vault access policy validation

#### GCP (`/basic/gcp/`)
- **simple_gcp_labels_check.rego**: GCP instance labeling validation
- **simple_firewall_check.rego**: Basic firewall rule security check

#### OCI (`/basic/oci/`)
- **simple_instance_shape.rego**: OCI instance shape validation

### 🚀 **Advanced Examples** (`/advanced/`)
Complex, production-ready policies with multiple conditions, helper functions, and detailed violation reporting:

#### AWS (`/advanced/aws/`)
- **enhanced_s3_security.rego**: Comprehensive S3 security with helper functions
- **smart_resource_age_policy.rego**: Resource lifecycle management with exemptions

#### Azure (`/advanced/azure/`)
- **advanced_storage_security.rego**: Comprehensive Azure Storage security checks

#### GCP (`/advanced/gcp/`)
- **advanced_compute_security.rego**: Multi-layered GCP Compute instance security

#### OCI (`/advanced/oci/`)
- **advanced_instance_security.rego**: Comprehensive OCI instance security validation

### 📋 **Compliance Examples** (`/compliance/`)
Multi-framework security policies that map to established security standards:

#### AWS (`/compliance/aws/`) - 19 Policies
Covering 6 critical resource types:
- **AWS::S3::Bucket** (4 controls): CIS-2.1.1, NIST SC-7, PCI-DSS 1.3, SOC2 CC6.1
- **AWS::EC2::Instance** (4 controls): CIS-4.1, NIST AC-3, SOC2 CC6.2, PCI-DSS 2.1
- **AWS::EKS::Cluster** (3 controls): CIS K8S-1.2.1, NIST SC-8, SOC2 CC6.7
- **AWS::DynamoDB::Table** (3 controls): CIS-2.2.1, NIST SC-28, PCI-DSS 3.4
- **AWS::CloudTrail::Trail** (3 controls): CIS-3.1, NIST AU-2, SOC2 CC7.2
- **AWS::ECS::Cluster** (2 controls): CIS Docker-2.1, NIST SI-4

#### Azure (`/compliance/azure/`) - 14 Policies
Covering 4 critical resource types:
- **Microsoft.Storage/storageAccounts** (4 controls): CIS-3.1, NIST SC-8, PCI-DSS 4.1, SOC2 CC6.7
- **Microsoft.KeyVault/vaults** (4 controls): CIS-8.1, NIST SC-28, PCI-DSS 3.6, SOC2 CC6.8
- **Microsoft.Compute/virtualMachines** (3 controls): CIS-7.1, NIST SC-28, SOC2 CC6.1
- **Microsoft.ContainerService/managedClusters** (3 controls): CIS K8S-1.2.1, NIST AC-3, SOC2 CC6.2

#### GCP (`/compliance/gcp/`) - 9 Policies
Covering 3 critical resource types:
- **storage.googleapis.com/Bucket** (3 controls): CIS-5.1, NIST AC-3, PCI-DSS 7.1
- **compute.googleapis.com/Instance** (3 controls): CIS-4.1, NIST SC-7, SOC2 CC6.1
- **container.googleapis.com/Cluster** (3 controls): CIS K8S-1.2.1, NIST SC-8, SOC2 CC6.7

#### OCI (`/compliance/oci/`) - 6 Policies
Covering 2 critical resource types:
- **OCI::Core::Instance** (3 controls): OCI-SEC-1, NIST SC-8, SOC2 CC6.1
- **OCI::ContainerEngine::Cluster** (3 controls): OCI-K8S-1, NIST AC-3, SOC2 CC6.7

## 🎯 **Security Framework Coverage**

The **compliance examples** represent a breakthrough in security posture visibility where each policy maps to **established security frameworks**:

| Framework | Coverage | Controls | Business Value |
|-----------|----------|----------|----------------|
| **🏛️ CIS Benchmarks** | AWS, Azure, GCP, Kubernetes, Docker | 15 controls | Industry baseline security compliance |
| **📋 NIST 800-53** | Federal security requirements | 15 controls | Government/enterprise compliance |
| **🔒 SOC2** | Trust Services Criteria | 12 controls | Vendor assurance & audit readiness |
| **💳 PCI-DSS** | Payment Card Industry | 6 controls | Financial data protection compliance |
| **☁️ Cloud Best Practices** | Provider-specific security | Custom | Cloud-native security optimization |

## 🚀 **Getting Started**

### **For Learning Rego**
Start with the `basic/` examples which demonstrate fundamental Rego concepts and simple security checks.

### **For Production Use**
Progress to the `advanced/` examples which include helper functions, complex logic, and detailed violation reporting.

### **For Compliance Auditing**
Use the `compliance/` examples which map to specific framework controls and provide audit-ready security validation.

## 📋 **Policy Structure Examples**

### **Basic Policy Pattern**
```rego
package crowdstrike

default result := "fail"

result = "skip" if {
    input.resource_type != "TARGET_TYPE"
}

result = "pass" if {
    input.resource_type == "TARGET_TYPE"
    input.configuration.security_setting == expected_value
}
```

### **Advanced Policy Pattern**
```rego
package crowdstrike

default result := "fail"

# Helper functions
is_secure(resource) if {
    # Complex validation logic
}

result = "pass" if {
    input.resource_type == "TARGET_TYPE"
    is_secure(input)
}

violation contains msg if {
    # Specific failure reasons
}
```

### **Compliance Policy Pattern**
```rego
package crowdstrike

# Framework: NIST 800-53 SC-8
# Control ID: NIST-SC-8
# Severity: HIGH
# Description: Transmission Confidentiality

default result := "fail"

result = "pass" if {
    input.resource_type == "TARGET_TYPE"
    # Framework-specific security check
}
```

## 📊 **Usage with CrowdStrike API**

```bash
# Test a policy against your resources
curl -X POST 'https://api.crowdstrike.com/cloud-policies/entities/evaluation/v1' \
  -H 'Authorization: Bearer YOUR_TOKEN' \
  -d '{
    "cloud_provider": "aws",
    "resource_type": "AWS::S3::Bucket",
    "ids": ["your-bucket-resource-id"],
    "logic": "package crowdstrike\n..."
  }'
```

## 📖 **Additional Resources**

- [comprehensive_security_generator.py](../comprehensive_security_generator.py) - Multi-framework policy generator
- [SECURITY_REVIEW_REPORT.md](../SECURITY_REVIEW_REPORT.md) - Security analysis report
- [apiexample.txt](../apiexample.txt) - CrowdStrike API documentation with real schemas
- [CrowdStrike API Documentation](https://falcon.crowdstrike.com/documentation)

---
✅ **Total: 55+ policies across basic, advanced, and compliance categories**

🛡️ **Comprehensive security posture visibility across CIS, NIST 800-53, SOC2, and PCI-DSS frameworks**