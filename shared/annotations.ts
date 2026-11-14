// Human analyst corrections to RECORDED model output.
//
// The signed model response is historical evidence and is never edited. A note is
// bound to one exact response (its signed SHA-256) and quotes the model text it
// corrects; the demo build fails if the quote is not in the signed output. Notes
// are displayed and exported as clearly separate, unsigned human commentary.

export interface AnalystNote {
  id: string;
  /** SHA-256 of the signed response this note annotates. */
  response_sha256: string;
  /** Exact text from the signed model output that the note corrects. */
  quote: string;
  title: string;
  body: string[];
  author: string;
  date: string;
  references: { label: string; url: string }[];
}

export const ANALYST_NOTES: AnalystNote[] = [
  {
    id: 'quillmark-imds-security-group',
    response_sha256: '3df5ef8e55c916a0beb481b4c947eaf59eadab6e38cdb6e0c662aa35fecdda79',
    quote: 'Block egress traffic to 169.254.169.254 and internal VPC CIDRs from the rendering worker security group.',
    title: 'This containment step would not protect the instance metadata service',
    body: [
      'EC2 security groups (and network ACLs) do not filter traffic to the instance metadata service at 169.254.169.254, so this immediate action would leave the IAM credentials reachable while appearing to fix the issue.',
      'Use controls that sit on the real boundary: require IMDSv2 (HttpTokens=required), which a GET-only SSRF cannot use, and keep the PUT response hop limit at 1 so containers on a bridged network cannot receive a token, or disable the metadata service on rendering hosts that do not need it; block link-local destinations from the renderer itself with host or container network rules (for example nftables/iptables on the host, or a Kubernetes egress policy or egress proxy); validate and allowlist logo URLs after DNS resolution and every redirect; scope the rendering role to least privilege and rotate the credentials if exposure is suspected.',
      'Re-test from the rendering path after each change. The model’s C/I/A “High” impact ratings also assume role permissions the report does not establish; treat the score as provisional until the role’s actual permissions are known.',
    ],
    author: 'PrivateTriage maintainer (human review of a recorded run)',
    date: '2026-11-14',
    references: [
      { label: 'AWS: security groups do not filter instance metadata traffic', url: 'https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html' },
      { label: 'AWS: configure the instance metadata service (IMDSv2, hop limit)', url: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html' },
    ],
  },
];

export function notesFor(responseSha256: string | null | undefined): AnalystNote[] {
  return responseSha256 ? ANALYST_NOTES.filter((n) => n.response_sha256 === responseSha256) : [];
}
