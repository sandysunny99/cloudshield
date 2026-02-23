export type Severity = 'critical' | 'high' | 'medium' | 'low';
export type ResourceType = 'compute' | 'storage' | 'network' | 'iam' | 'container';
export type FindingStatus = 'open' | 'in_progress' | 'resolved';
export type ComplianceFramework = 'hipaa' | 'nist' | 'iso' | 'pci';

export interface Finding {
    id: string;
    title: string;
    description: string;
    severity: Severity;
    resource: string;
    resourceType: ResourceType;
    riskScore: number;
    cvssScore?: number;
    status: FindingStatus;
    discoveredAt: string;
    framework: ComplianceFramework[];
    cve?: string;
    tags: string[];
    remediationCommand?: string;
    remediationTerraform?: string;
    mitre?: {
        tactic: string;
        technique: string;
        id: string;
    };
}

export const mockFindings: Finding[] = [
    {
        id: 'F-101',
        title: 'Container Escape via runc Vulnerability',
        description: 'A flaw in runc allows a malicious container to overwrite the host runc binary and execute arbitrary code on the host.',
        severity: 'critical',
        resource: 'prd-k8s-cluster-01',
        resourceType: 'container',
        riskScore: 9.8,
        cvssScore: 10.0,
        status: 'open',
        discoveredAt: '2026-02-23T08:30:00Z',
        framework: ['nist', 'iso'],
        cve: 'CVE-2024-21626',
        tags: ['exploit', 'container-escape', 'runc'],
        remediationCommand: 'sudo apt-get update && sudo apt-get install --only-upgrade runc',
        remediationTerraform: 'resource "aws_eks_node_group" "main" {\n  ami_type = "AL2_x86_64"\n}',
        mitre: { tactic: 'Privilege Escalation', technique: 'Escape to Host', id: 'T1611' }
    },
    {
        id: 'F-102',
        title: 'S3 Bucket Publicly Accessible',
        description: 'The S3 bucket contains customer PII and is currently accessible by the public.',
        severity: 'critical',
        resource: 's3://prod-customer-data',
        resourceType: 'storage',
        riskScore: 9.2,
        cvssScore: 8.8,
        status: 'open',
        discoveredAt: '2026-02-22T14:15:00Z',
        framework: ['hipaa', 'nist'],
        tags: ['data-exfiltration', 'public-access'],
        remediationCommand: 'aws s3api put-public-access-block --bucket prod-customer-data --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"',
        remediationTerraform: 'resource "aws_s3_bucket_public_access_block" "block" {\n  bucket = aws_s3_bucket.data.id\n  block_public_acls = true\n}',
        mitre: { tactic: 'Exfiltration', technique: 'Exfiltration to Cloud Storage', id: 'T1537' }
    },
    {
        id: 'F-103',
        title: 'Overly Permissive IAM Role',
        description: 'The Lambda execution role has AdministratorAccess policy attached.',
        severity: 'high',
        resource: 'arn:aws:iam::1234:role/LambdaRole',
        resourceType: 'iam',
        riskScore: 8.5,
        cvssScore: 7.2,
        status: 'in_progress',
        discoveredAt: '2026-02-21T09:45:00Z',
        framework: ['nist'],
        tags: ['iam', 'least-privilege'],
        mitre: { tactic: 'Privilege Escalation', technique: 'Valid Accounts', id: 'T1078' }
    },
    {
        id: 'F-104',
        title: 'Inbound SSH Open to Internet',
        description: 'Security group allows TCP port 22 access from 0.0.0.0/0.',
        severity: 'high',
        resource: 'sg-0a1b2c3d4e5f6',
        resourceType: 'network',
        riskScore: 8.1,
        cvssScore: 6.8,
        status: 'open',
        discoveredAt: '2026-02-23T10:00:00Z',
        framework: ['iso', 'nist'],
        tags: ['network', 'ssh'],
        mitre: { tactic: 'Initial Access', technique: 'External Remote Services', id: 'T1133' }
    }
];

export const threatIntel = [
    { id: 1, type: 'IpAddress', value: '185.220.101.44', reputation: 'malicious', source: 'Tor Exit Node', lastSeen: '2m ago' },
    { id: 2, type: 'Domain', value: 'update-service.cloud', reputation: 'suspicious', source: 'DGA Pattern', lastSeen: '15m ago' },
    { id: 3, type: 'Hash', value: 'e3b0c442...852b855', reputation: 'malicious', source: 'Mirai Variant', lastSeen: '45m ago' },
    { id: 4, type: 'Email', value: 'billing@aws-secure.com', reputation: 'malicious', source: 'Phishing Campaign', lastSeen: '1h ago' },
];

export const complianceSummary = {
    hipaa: { pass: 12, fail: 2, percentage: 85 },
    nist: { pass: 45, fail: 8, percentage: 84 },
    iso: { pass: 30, fail: 5, percentage: 86 }
};

export const riskTrendData = Array.from({ length: 30 }).map((_, i) => ({
    date: `Feb ${i + 1}`,
    critical: Math.floor(Math.random() * 5) + 10,
    high: Math.floor(Math.random() * 10) + 20,
    medium: Math.floor(Math.random() * 15) + 30,
    low: Math.floor(Math.random() * 20) + 40,
}));
