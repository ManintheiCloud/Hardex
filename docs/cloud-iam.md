# Cloud identities and IAM exports

Workload identity federates a Kubernetes service-account token to a cloud identity: an AWS IAM role (EKS IRSA, `eks.amazonaws.com/role-arn`), a Google service account (GKE Workload Identity, `iam.gke.io/gcp-service-account`) or an Azure managed identity (Azure Workload Identity, `azure.workload.identity/client-id`). Hardex finds these bindings in every scan:

- **HX-PATH-002** lists each workload whose token assumes a cloud identity.
- **HX-PATH-001** finds chains *into* those identities from other workloads — for example a pod that escapes to a node where the identity's pods also run.

From the manifests alone Hardex cannot tell a role that writes one S3 prefix from one with `AdministratorAccess`. Give it your IAM data and it can:

```sh
aws iam get-account-authorization-details --output json > aws-iam.json
gcloud projects get-iam-policy my-project --format json > gcp-iam.json
az role assignment list --all --output json > azure-roles.json

hardex scan --cluster --cloud-iam aws-iam.json --cloud-iam gcp-iam.json --cloud-iam azure-roles.json
```

Hardex never calls cloud APIs and needs no cloud credentials: you export with your own tools and permissions, and pass the files explicitly (they are never discovered from scanned content). `hardex monitor` accepts `--cloud-iam` too.

## What changes

Each identity is classified:

| Level | AWS | Google Cloud | Azure |
|---|---|---|---|
| **admin** — controls the account | an unconditional `Allow` of `*` (or `NotAction` not excluding IAM) on `*`, in an inline policy, the default version of an attached customer-managed policy, or `AdministratorAccess` | `roles/owner` or `roles/editor` on the project | `Owner` or `Contributor` at subscription, management-group or root scope |
| **escalation** — can grant itself admin | unconditional IAM write or role-passing actions on `*` (`iam:*`, `iam:PassRole`, `iam:Attach*Policy`, `iam:Put*Policy`, `iam:CreatePolicyVersion`, `sts:AssumeRole`, …), or `IAMFullAccess` | service-account impersonation and IAM admin roles (`iam.serviceAccountTokenCreator`, `iam.serviceAccountUser`, `resourcemanager.projectIamAdmin`, `container.admin`, …) | `User Access Administrator`, `Role Based Access Control Administrator`, `Managed Identity Operator` at broad scope |
| **limited** | anything else | anything else | anything else, including `Owner` of a resource group |

With that:

- HX-PATH-002 becomes **critical** for a workload whose own token is an *admin* identity, and **high** for an *escalation* identity; the finding names the policy or role responsible.
- HX-PATH-001 reports chains from other workloads into an admin or escalation identity as **critical** — *control of the cloud account*.

## Limits

The classification reads unconditional grants only. Conditions (AWS `Condition`, GCP IAM conditions, Azure ABAC conditions) are skipped, and permission boundaries, service control policies, deny policies, resource policies and inherited GCP folder/organisation bindings are not evaluated. So **admin** and **escalation** are reliable; **limited** means "no unconditional admin grant found", not "safe".

- AWS: roles are matched by ARN. AWS-managed policy documents are used when the export includes them; otherwise `AdministratorAccess` and `IAMFullAccess` are recognised by ARN. EKS Pod Identity associations are configured outside Kubernetes and are not visible.
- Google Cloud: one project policy per file; pass one file per project. Users and groups are ignored; only `serviceAccount:` members are workload identities.
- Azure: identities are matched by client ID (`principalName` for service principals in `az role assignment list`) or object ID.
- A `CloudIdentity` object planted in scanned manifests can only raise a severity, never lower one: an identity Hardex knows nothing about is already treated as unrated.
