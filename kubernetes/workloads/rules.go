package workloads

import "github.com/ManintheiCloud/Hardex/core/assessment"

// Rules returns every workload rule.
func Rules() []assessment.Rule {
	return []assessment.Rule{
		privileged, hostNamespaces, hostPathVolumes, privilegeEscalation, runAsNonRoot,
		dangerousCapabilities, minimalCapabilities, seccomp, readOnlyRootFS, resourceLimits,
		mutableImageTag, imageDigest, serviceAccountToken, hostPorts, appArmor, seLinux,
		procMount, unsafeSysctls, volumeTypes, hostProcess,
	}
}
