def run_cloud_posture_scan(payload: dict) -> dict:
    """
    Executes Multi-Cloud Security Posture Assessment (AWS, Azure, GCP).
    Uses live boto3 SDK when connectionMode == 'LIVE' and credentials are provided,
    or runs structured sandbox posture evaluation when connectionMode == 'DEMO_SIMULATION'.
    """
    provider = (payload.get("provider") or "AWS").upper()
    account_id = str(payload.get("accountIdentifier") or "000000000000")
    connection_mode = payload.get("connectionMode") or "DEMO_SIMULATION"
    credentials = payload.get("credentials") or {}
    regions = payload.get("regions") or ["us-east-1"]
    primary_region = regions[0] if regions else "us-east-1"

    if connection_mode == "LIVE":
        if provider == "AWS":
            try:
                import boto3
                session = boto3.Session(
                    aws_access_key_id=credentials.get("accessKeyId") or credentials.get("principal"),
                    aws_secret_access_key=credentials.get("secretAccessKey") or credentials.get("secretOrExternalId"),
                    region_name=primary_region
                )
                s3 = session.client("s3")
                buckets_resp = s3.list_buckets()
                resources = []
                findings = []
                for b in buckets_resp.get("Buckets", []):
                    b_name = b["Name"]
                    is_public = False
                    try:
                        pab = s3.get_public_access_block(Bucket=b_name)
                        cfg = pab.get("PublicAccessBlockConfiguration", {})
                        if not all([cfg.get("BlockPublicAcls"), cfg.get("BlockPublicPolicy")]):
                            is_public = True
                    except Exception:
                        is_public = True

                    resources.append({
                        "service_type": "S3",
                        "resource_type": "AWS::S3::Bucket",
                        "resource_id": f"arn:aws:s3:::{b_name}",
                        "resource_name": b_name,
                        "region": primary_region,
                        "is_public": is_public,
                        "encryption_enabled": True,
                        "configuration": {"bucketName": b_name}
                    })
                    if is_public:
                        findings.append({
                            "source_type": "CLOUD_CSPM",
                            "rule_id": "AWS-S3-LIVE-001",
                            "title": f"S3 Bucket '{b_name}' Lacks Full Public Access Block",
                            "description": f"Live AWS S3 check found bucket {b_name} without full PublicAccessBlock enforcement.",
                            "category": "STORAGE",
                            "severity": "HIGH",
                            "cvss_score": 8.2,
                            "cwe_id": "CWE-284",
                            "affected_asset": f"arn:aws:s3:::{b_name}",
                            "remediation_summary": "Enable BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, and RestrictPublicBuckets.",
                            "compliance_controls": ["A.8.24", "CC6.1"],
                            "evidence": {"bucket": b_name, "mode": "LIVE_BOTO3"}
                        })
                return {"resources": resources, "findings": findings, "mode": "LIVE_AWS_BOTO3"}
            except Exception as exc:
                raise ValueError(f"Live AWS SDK connection failed: {exc}")
        else:
            raise ValueError(
                f"Live {provider} Cloud SDK inspection requires valid {provider} credentials (or select DEMO_SIMULATION mode)."
            )

    # DEMO_SIMULATION mode: Deterministic Multi-Cloud CSPM evaluation in Python
    resources = []
    findings = []
    suffix = account_id[-4:] if len(account_id) >= 4 else "0001"

    if provider == "AWS":
        bucket_name = f"prod-customer-backups-{suffix}"
        resources.extend([
            {
                "service_type": "S3",
                "resource_type": "AWS::S3::Bucket",
                "resource_id": f"arn:aws:s3:::{bucket_name}",
                "resource_name": bucket_name,
                "region": primary_region,
                "is_public": True,
                "encryption_enabled": False,
                "configuration": {
                    "PublicAccessBlockConfiguration": {"BlockPublicAcls": False, "BlockPublicPolicy": False},
                    "ServerSideEncryption": "NONE"
                }
            },
            {
                "service_type": "EC2",
                "resource_type": "AWS::EC2::SecurityGroup",
                "resource_id": "sg-09a8b7c6d5e4f3210",
                "resource_name": "prod-web-ssh-sg",
                "region": primary_region,
                "is_public": True,
                "encryption_enabled": True,
                "configuration": {
                    "IpPermissions": [{"FromPort": 22, "ToPort": 22, "IpProtocol": "tcp", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]
                }
            },
            {
                "service_type": "IAM",
                "resource_type": "AWS::IAM::User",
                "resource_id": f"arn:aws:iam::{account_id}:user/ci-deploy-admin",
                "resource_name": "ci-deploy-admin",
                "region": "global",
                "is_public": False,
                "encryption_enabled": True,
                "configuration": {"MfaActive": False, "AttachedPolicies": ["AdministratorAccess"], "AccessKeyAgeDays": 142}
            },
            {
                "service_type": "RDS",
                "resource_type": "AWS::RDS::DBInstance",
                "resource_id": f"arn:aws:rds:{primary_region}:{account_id}:db:analytics-postgres-01",
                "resource_name": "analytics-postgres-01",
                "region": primary_region,
                "is_public": False,
                "encryption_enabled": False,
                "configuration": {"StorageEncrypted": False, "PubliclyAccessible": False, "Engine": "postgres"}
            }
        ])

        findings.extend([
            {
                "source_type": "CLOUD_CSPM",
                "rule_id": "AWS-S3-001",
                "title": "S3 Bucket Allows Public Read ACL & Lacks Server-Side Encryption",
                "description": f"AWS S3 bucket '{bucket_name}' has BlockPublicAccess disabled and SSE encryption unconfigured.",
                "category": "STORAGE",
                "severity": "CRITICAL",
                "cvss_score": 9.3,
                "cwe_id": "CWE-284",
                "affected_asset": f"arn:aws:s3:::{bucket_name}",
                "remediation_summary": "Enable S3 BlockPublicAccess (aws s3api put-public-access-block) and enforce SSE-KMS or AES256 default bucket encryption.",
                "compliance_controls": ["A.8.24", "CC6.1"],
                "evidence": {"bucket": bucket_name, "blockPublicAcls": False, "sse": "NONE", "simulationMode": True}
            },
            {
                "source_type": "CLOUD_CSPM",
                "rule_id": "AWS-EC2-SG-022",
                "title": "Security Group Allows Unrestricted SSH (TCP/22) Ingress from 0.0.0.0/0",
                "description": "Security Group sg-09a8b7c6d5e4f3210 permits inbound SSH port 22 from the entire internet (0.0.0.0/0).",
                "category": "NETWORK",
                "severity": "HIGH",
                "cvss_score": 8.2,
                "cwe_id": "CWE-284",
                "affected_asset": "sg-09a8b7c6d5e4f3210 (prod-web-ssh-sg)",
                "remediation_summary": "Remove 0.0.0.0/0 ingress on port 22 and use AWS Systems Manager Session Manager or restrict to corporate VPN CIDR.",
                "compliance_controls": ["A.8.20", "CC6.6"],
                "evidence": {"securityGroupId": "sg-09a8b7c6d5e4f3210", "port": 22, "cidr": "0.0.0.0/0", "simulationMode": True}
            },
            {
                "source_type": "CLOUD_CSPM",
                "rule_id": "AWS-IAM-004",
                "title": "Privileged IAM User Lacks MFA & Holds Wildcard AdministratorAccess",
                "description": "IAM user ci-deploy-admin has AdministratorAccess (*:*) attached without Multi-Factor Authentication (MFA) and access keys older than 90 days.",
                "category": "IAM",
                "severity": "CRITICAL",
                "cvss_score": 9.1,
                "cwe_id": "CWE-250",
                "affected_asset": f"arn:aws:iam::{account_id}:user/ci-deploy-admin",
                "remediation_summary": "Enforce hardware/virtual MFA on all IAM users, replace static keys with OIDC IAM Roles, and scope down AdministratorAccess.",
                "compliance_controls": ["A.5.15", "A.8.2", "A.8.5", "CC6.1", "CC6.2"],
                "evidence": {"userName": "ci-deploy-admin", "mfaActive": False, "policy": "AdministratorAccess", "keyAgeDays": 142, "simulationMode": True}
            },
            {
                "source_type": "CLOUD_CSPM",
                "rule_id": "AWS-RDS-002",
                "title": "RDS Database Instance Storage Encryption at Rest Disabled",
                "description": "RDS PostgreSQL instance analytics-postgres-01 does not have storage encryption enabled at rest.",
                "category": "ENCRYPTION",
                "severity": "HIGH",
                "cvss_score": 7.4,
                "cwe_id": "CWE-311",
                "affected_asset": f"arn:aws:rds:{primary_region}:{account_id}:db:analytics-postgres-01",
                "remediation_summary": "Take an RDS snapshot, copy the snapshot with KMS encryption enabled, and restore the encrypted DB instance.",
                "compliance_controls": ["A.8.24", "CC6.1"],
                "evidence": {"dbInstanceIdentifier": "analytics-postgres-01", "storageEncrypted": False, "simulationMode": True}
            }
        ])
    elif provider == "AZURE":
        resources.extend([
            {
                "service_type": "Storage",
                "resource_type": "Microsoft.Storage/storageAccounts",
                "resource_id": f"/subscriptions/{account_id}/resourceGroups/rg-prod/providers/Microsoft.Storage/storageAccounts/stprodblobs01",
                "resource_name": "stprodblobs01",
                "region": primary_region,
                "is_public": True,
                "encryption_enabled": True,
                "configuration": {"allowBlobPublicAccess": True, "minimumTlsVersion": "TLS1_0"}
            },
            {
                "service_type": "Network",
                "resource_type": "Microsoft.Network/networkSecurityGroups",
                "resource_id": f"/subscriptions/{account_id}/resourceGroups/rg-prod/providers/Microsoft.Network/networkSecurityGroups/nsg-rdp-open",
                "resource_name": "nsg-rdp-open",
                "region": primary_region,
                "is_public": True,
                "encryption_enabled": True,
                "configuration": {"destinationPortRange": "3389", "sourceAddressPrefix": "*", "access": "Allow"}
            }
        ])
        findings.extend([
            {
                "source_type": "CLOUD_CSPM",
                "rule_id": "AZ-STORAGE-001",
                "title": "Azure Storage Account Allows Anonymous Public Blob Access & TLS 1.0",
                "description": "Storage account stprodblobs01 permits anonymous public blob access and allows legacy TLS 1.0 connections.",
                "category": "STORAGE",
                "severity": "HIGH",
                "cvss_score": 8.1,
                "cwe_id": "CWE-284",
                "affected_asset": "stprodblobs01 (Microsoft.Storage/storageAccounts)",
                "remediation_summary": "Disable allowBlobPublicAccess and set minimumTlsVersion to TLS1_2 in Azure Storage configuration.",
                "compliance_controls": ["A.8.24", "CC6.1", "CC6.7"],
                "evidence": {"allowBlobPublicAccess": True, "minimumTlsVersion": "TLS1_0", "simulationMode": True}
            },
            {
                "source_type": "CLOUD_CSPM",
                "rule_id": "AZ-NSG-3389",
                "title": "Azure NSG Allows Unrestricted RDP (TCP/3389) from Internet",
                "description": "Network Security Group nsg-rdp-open allows inbound RDP port 3389 from any source (*).",
                "category": "NETWORK",
                "severity": "CRITICAL",
                "cvss_score": 9.0,
                "cwe_id": "CWE-284",
                "affected_asset": "nsg-rdp-open (Microsoft.Network/networkSecurityGroups)",
                "remediation_summary": "Restrict RDP access using Azure Bastion or Just-In-Time (JIT) VM access in Microsoft Defender for Cloud.",
                "compliance_controls": ["A.8.20", "CC6.6"],
                "evidence": {"port": 3389, "source": "*", "access": "Allow", "simulationMode": True}
            }
        ])
    elif provider == "GCP":
        resources.extend([
            {
                "service_type": "CloudStorage",
                "resource_type": "storage.googleapis.com/Bucket",
                "resource_id": f"projects/{account_id}/buckets/gcp-ml-training-datasets",
                "resource_name": "gcp-ml-training-datasets",
                "region": primary_region,
                "is_public": True,
                "encryption_enabled": True,
                "configuration": {"iamBindings": [{"role": "roles/storage.objectViewer", "members": ["allUsers"]}]}
            },
            {
                "service_type": "ComputeEngine",
                "resource_type": "compute.googleapis.com/Firewall",
                "resource_id": f"projects/{account_id}/global/firewalls/default-allow-ssh-world",
                "resource_name": "default-allow-ssh-world",
                "region": "global",
                "is_public": True,
                "encryption_enabled": True,
                "configuration": {"sourceRanges": ["0.0.0.0/0"], "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}]}
            }
        ])
        findings.extend([
            {
                "source_type": "CLOUD_CSPM",
                "rule_id": "GCP-GCS-001",
                "title": "GCP Cloud Storage Bucket Grants ObjectViewer to allUsers",
                "description": "GCS bucket gcp-ml-training-datasets has IAM binding granting roles/storage.objectViewer to allUsers.",
                "category": "STORAGE",
                "severity": "CRITICAL",
                "cvss_score": 9.1,
                "cwe_id": "CWE-284",
                "affected_asset": f"projects/{account_id}/buckets/gcp-ml-training-datasets",
                "remediation_summary": "Remove allUsers and allAuthenticatedUsers from bucket IAM bindings and enforce Uniform Bucket-Level Access.",
                "compliance_controls": ["A.8.24", "CC6.1"],
                "evidence": {"member": "allUsers", "role": "roles/storage.objectViewer", "simulationMode": True}
            },
            {
                "source_type": "CLOUD_CSPM",
                "rule_id": "GCP-FW-022",
                "title": "GCP VPC Firewall Rule Allows Ingress SSH (TCP/22) from 0.0.0.0/0",
                "description": "VPC Firewall rule default-allow-ssh-world allows unrestricted TCP/22 access from 0.0.0.0/0.",
                "category": "NETWORK",
                "severity": "HIGH",
                "cvss_score": 8.0,
                "cwe_id": "CWE-284",
                "affected_asset": f"projects/{account_id}/global/firewalls/default-allow-ssh-world",
                "remediation_summary": "Restrict SSH source ranges to Google Cloud IAP (35.235.240.0/20) and use Identity-Aware Proxy tunneling.",
                "compliance_controls": ["A.8.20", "CC6.6"],
                "evidence": {"firewall": "default-allow-ssh-world", "sourceRanges": ["0.0.0.0/0"], "port": 22, "simulationMode": True}
            }
        ])

    return {"resources": resources, "findings": findings, "mode": "DEMO_SIMULATION"}
