# CrowdStrike Rego Policy Examples

> **⚠️ Community Repository Disclaimer**
> This is a **community-built repository** created with assistance from Claude AI and is **not officially supported by CrowdStrike**. These policy examples are provided for educational and reference purposes. For official support, documentation, and production-ready policies, please refer to CrowdStrike's official documentation and support channels.

A comprehensive collection of **61 security policy examples** for CrowdStrike Falcon Cloud Security Posture Management (CSPM), organized by complexity and compliance frameworks.

## 📋 What's Included

- **8 Basic Examples**: Simple policies for learning Rego fundamentals
- **5 Advanced Examples**: Advanced examples with helper functions and violation reporting
- **48 Compliance Examples**: Multi-framework policies mapped to CIS, NIST 800-53, SOC2, and PCI-DSS

## 🔗 Quick Links to Examples

### 🎯 Popular Basic Examples
- **[AWS S3 Public Access Check](./examples/basic/aws/simple_s3_public_access.rego)** - Block public S3 bucket access
- **[AWS EC2 SSH Security](./examples/basic/aws/simple_ec2_ssh_check.rego)** - Check SSH security groups
- **[Azure Storage HTTPS](./examples/basic/azure/simple_azure_https_check.rego)** - Enforce HTTPS on storage accounts
- **[Azure Key Vault Access](./examples/basic/azure/simple_keyvault_access.rego)** - Validate Key Vault access policies
- **[GCP Compute Labels](./examples/basic/gcp/simple_gcp_labels_check.rego)** - Check instance labeling
- **[GCP Firewall Rules](./examples/basic/gcp/simple_firewall_check.rego)** - Validate firewall configurations

### 🏗️ Advanced Policy Examples
- **[Enhanced AWS S3 Security](./examples/advanced/aws/enhanced_s3_security.rego)** - Comprehensive S3 compliance
- **[Advanced Azure Storage](./examples/advanced/azure/advanced_storage_security.rego)** - Multi-layer storage security
- **[GCP Compute Security](./examples/advanced/gcp/advanced_compute_security.rego)** - Instance security hardening
- **[OCI Instance Security](./examples/advanced/oci/advanced_instance_security.rego)** - Comprehensive OCI controls

### 🛡️ Compliance Framework Examples

#### AWS Compliance Policies
- **[CIS S3 Public Access](./examples/compliance/aws/aws_s3_bucket_cis_cis_2_1_1_high_001.rego)** - CIS 2.1.1 control
- **[NIST S3 Boundary Protection](./examples/compliance/aws/aws_s3_bucket_nist_nist_sc_7_high_002.rego)** - NIST SC-7 control
- **[PCI-DSS S3 Access](./examples/compliance/aws/aws_s3_bucket_pci-dss_pci_dss_1_3_critical_003.rego)** - PCI-DSS 1.3 control
- **[SOC2 EC2 Privileged Access](./examples/compliance/aws/aws_ec2_instance_soc2_soc2_cc6_2_high_007.rego)** - SOC2 CC6.2 control
- **[CIS EKS API Security](./examples/compliance/aws/aws_eks_cluster_cis_cis_k8s_1_2_1_critical_009.rego)** - Kubernetes API protection

#### Azure Compliance Policies
- **[CIS Storage Security](./examples/compliance/azure/microsoft_storage_storageaccounts_cis_cis_3_1_high_020.rego)** - CIS 3.1 control
- **[NIST VM Encryption](./examples/compliance/azure/microsoft_compute_virtualmachines_nist_nist_sc_28_high_029.rego)** - NIST SC-28 control
- **[PCI-DSS Key Vault](./examples/compliance/azure/microsoft_keyvault_vaults_pci-dss_pci_dss_3_6_critical_026.rego)** - PCI-DSS 3.6 control
- **[SOC2 AKS Security](./examples/compliance/azure/microsoft_containerservice_managedclusters_soc2_soc2_cc6_2_high_033.rego)** - SOC2 CC6.2 control

#### GCP Compliance Policies
- **[CIS Compute Public IP](./examples/compliance/gcp/compute_googleapis_com_instance_cis_cis_4_1_medium_037.rego)** - CIS 4.1 control
- **[NIST Storage Access](./examples/compliance/gcp/storage_googleapis_com_bucket_nist_nist_ac_3_high_035.rego)** - NIST AC-3 control
- **[SOC2 GKE Security](./examples/compliance/gcp/container_googleapis_com_cluster_soc2_soc2_cc6_7_high_042.rego)** - SOC2 CC6.7 control

#### OCI Compliance Policies
- **[CIS Instance Shape](./examples/compliance/oci/oci_core_instance_oci_oci_sec_1_medium_043.rego)** - OCI security best practices
- **[NIST Container Security](./examples/compliance/oci/oci_containerengine_cluster_nist_nist_ac_3_high_047.rego)** - NIST AC-3 control

## 🚀 Quick Start

1. **Browse by category**: Click any link above to jump directly to examples
2. **Start with basics**: Try the [S3 public access policy](./examples/basic/aws/simple_s3_public_access.rego) first
3. **Explore advanced**: Check [enhanced S3 security](./examples/advanced/aws/enhanced_s3_security.rego) for complex examples
4. **Framework mapping**: Use compliance policies for audit requirements

## 📝 Basic Example

Here's a simple S3 public access policy to get you started:

```rego
package crowdstrike

# Simple S3 Public Access Check
# Description: Basic example to check if S3 bucket allows public access

default result := "fail"

# Skip non-S3 resources
result = "skip" if {
    input.resource_type != "AWS::S3::Bucket"
}

# Pass if public access is blocked
result = "pass" if {
    input.resource_type == "AWS::S3::Bucket"
    input.supplementaryConfiguration.BucketPublicAccessBlockConfiguration.blockPublicAcls == true
}
```

This policy demonstrates the core pattern:
- **Default to fail**: Security-first approach
- **Resource filtering**: Skip irrelevant resources
- **Clear validation**: Simple pass condition

## 📁 Directory Structure

```
examples/
├── basic/          # Simple learning examples
│   ├── aws/        # 3 AWS basic policies
│   ├── azure/      # 2 Azure basic policies
│   ├── gcp/        # 2 GCP basic policies
│   └── oci/        # 1 OCI basic policy
├── advanced/       # Advanced examples
│   ├── aws/        # 2 AWS advanced policies
│   ├── azure/      # 1 Azure advanced policy
│   ├── gcp/        # 1 GCP advanced policy
│   └── oci/        # 1 OCI advanced policy
└── compliance/     # Framework-mapped policies
    ├── aws/        # 19 policies across 6 resource types
    ├── azure/      # 14 policies across 4 resource types
    ├── gcp/        # 9 policies across 3 resource types
    └── oci/        # 6 policies across 2 resource types
```

## 🛡️ Security Frameworks Covered

| Framework | Controls | Purpose |
|-----------|----------|---------|
| **CIS Benchmarks** | 15 controls | Industry baseline security compliance |
| **NIST 800-53** | 15 controls | Government/enterprise compliance |
| **SOC2** | 12 controls | Vendor assurance & audit readiness |
| **PCI-DSS** | 6 controls | Financial data protection compliance |

## 📖 Usage

These policies are designed to work with CrowdStrike's Cloud Security Posture Management API. Each policy includes:

- **Resource type validation** to ensure appropriate evaluation
- **Real security configuration checks** based on actual CrowdStrike schemas
- **Framework mapping** for compliance reporting
- **Modern Rego syntax** for compatibility

## 🔍 Policy Validation

All policies have been validated for:
- ✅ Correct CrowdStrike resource schemas
- ✅ Modern Rego syntax compatibility
- ✅ Consistent file naming (lowercase)
- ✅ Framework control mappings

---
*Generated for CrowdStrike Falcon CSPM - Comprehensive security posture visibility across multi-cloud environments*