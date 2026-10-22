// Differential test of Hardex's Pod Security Standards rules against the
// PodSecurity admission controller's own policy package. A separate module
// so that Hardex itself keeps a single dependency; see README.md.
module github.com/ManintheiCloud/Hardex/tools/pss-diff

go 1.26.0

require (
	github.com/ManintheiCloud/Hardex v0.0.0
	k8s.io/api v0.37.1
	k8s.io/apimachinery v0.37.1
	k8s.io/pod-security-admission v0.37.1
)

replace github.com/ManintheiCloud/Hardex => ../..
