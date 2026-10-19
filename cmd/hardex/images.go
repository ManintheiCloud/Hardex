package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"

	"github.com/ManintheiCloud/Hardex/core/cluster"
	"github.com/ManintheiCloud/Hardex/core/imagesig"
	"github.com/ManintheiCloud/Hardex/core/registry"
	"github.com/ManintheiCloud/Hardex/core/resource"
	"github.com/ManintheiCloud/Hardex/integrations/reporting"
)

// imageReport is the outcome for one image reference.
type imageReport struct {
	Image     string           `json:"image"`
	UsedBy    []string         `json:"usedBy"`
	Pinned    bool             `json:"pinned"`
	Digest    string           `json:"digest,omitempty"`
	Pin       string           `json:"pin,omitempty"`
	Signature *imagesig.Result `json:"signature,omitempty"`
	Error     string           `json:"error,omitempty"`
}

// newRegistryClient is replaced in tests.
var newRegistryClient = registry.NewClient

func cmdImages(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("images", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var keys multiFlag
	fs.Var(&keys, "key", "cosign public key to verify signatures with (repeatable)")
	format := fs.String("format", "text", "text or json")
	requireSig := fs.Bool("require-signature", false, "exit 1 unless every image has a signature verified by --key")
	requireDigest := fs.Bool("require-digest", false, "exit 1 if any image is referenced by tag instead of digest")
	offline := fs.Bool("offline", false, "do not contact registries; only report how images are referenced")
	var cf clusterFlags
	cf.register(fs)
	paths, err := parseInterleaved(fs, args)
	if err != nil {
		return exitUsage
	}
	fail := func(err error) int { fmt.Fprintln(stderr, "images:", err); return exitUsage }
	switch {
	case len(paths) == 0 && !cf.active():
		return fail(fmt.Errorf("pass manifest paths or --cluster"))
	case *requireSig && len(keys) == 0:
		return fail(fmt.Errorf("--require-signature needs at least one --key"))
	case *offline && len(keys) > 0:
		return fail(fmt.Errorf("--key requires registry access; drop --offline"))
	}
	var trusted []*imagesig.PublicKey
	for _, k := range keys {
		pk, err := imagesig.LoadPublicKey(k)
		if err != nil {
			return fail(err)
		}
		trusted = append(trusted, pk)
	}

	ctx := context.Background()
	var inv *resource.Inventory
	if cf.active() {
		client, err := cf.connect(cluster.ReadOnly)
		if err != nil {
			return fail(err)
		}
		col, errs, _, err := cf.collect(ctx, client)
		if err != nil {
			return fail(err)
		}
		if len(errs) > 0 {
			fmt.Fprintln(stderr, "images: warning: incomplete collection:", strings.Join(errs, "; "))
		}
		inv = col.Inventory
	} else if inv, err = resource.Load(paths, stdin); err != nil {
		return fail(err)
	}

	usage := map[string]map[string]bool{}
	for _, o := range inv.Objects {
		pod, _ := resource.PodSpec(o)
		for _, c := range resource.Containers(pod) {
			img := resource.String(c.Spec, "image")
			if img == "" {
				continue
			}
			if usage[img] == nil {
				usage[img] = map[string]bool{}
			}
			usage[img][o.Ref()] = true
		}
	}
	images := make([]string, 0, len(usage))
	for img := range usage {
		images = append(images, img)
	}
	sort.Strings(images)

	reports := make([]imageReport, len(images))
	rc := newRegistryClient()
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for i, img := range images {
		var users []string
		for u := range usage[img] {
			users = append(users, u)
		}
		sort.Strings(users)
		reports[i] = imageReport{Image: img, UsedBy: users}
		wg.Add(1)
		go func(r *imageReport) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			checkImage(ctx, rc, r, trusted, *offline)
		}(&reports[i])
	}
	wg.Wait()

	if *format == "json" {
		reporting.JSONValue(stdout, reports)
	} else {
		printImages(stdout, reports, len(trusted) > 0)
	}

	exit := exitOK
	for _, r := range reports {
		switch {
		case *requireDigest && !r.Pinned:
			exit = max(exit, exitFindings)
		case *requireSig && (r.Signature == nil || r.Signature.Status != imagesig.Verified):
			if r.Error != "" || (r.Signature != nil && r.Signature.Status == imagesig.Error) {
				exit = max(exit, exitIncomplete)
			} else {
				exit = max(exit, exitFindings)
			}
		}
	}
	return exit
}

func checkImage(ctx context.Context, rc *registry.Client, r *imageReport, keys []*imagesig.PublicKey, offline bool) {
	ref, err := registry.ParseRef(r.Image)
	if err != nil {
		r.Error = err.Error()
		return
	}
	r.Pinned = ref.Digest != ""
	r.Digest = ref.Digest
	if offline {
		return
	}
	if !r.Pinned {
		m, err := rc.GetManifest(ctx, ref.Registry, ref.Repository, ref.Tag)
		if err != nil {
			r.Error = "resolve tag: " + err.Error()
			return
		}
		r.Digest = m.Digest
		r.Pin = strings.SplitN(r.Image, "@", 2)[0] + "@" + m.Digest
	}
	if len(keys) > 0 {
		res := imagesig.Verify(ctx, rc, ref, r.Digest, keys)
		r.Signature = &res
	}
}

func printImages(w io.Writer, reports []imageReport, verify bool) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	header := "IMAGE\tREFERENCE\tDIGEST"
	if verify {
		header += "\tSIGNATURE"
	}
	fmt.Fprintln(tw, header+"\tUSED BY")
	for _, r := range reports {
		ref := "tag (mutable)"
		if r.Pinned {
			ref = "digest"
		}
		digest := r.Digest
		if r.Error != "" {
			digest = "error: " + r.Error
		} else if digest == "" {
			digest = "-"
		}
		line := fmt.Sprintf("%s\t%s\t%s", reporting.Sanitize(r.Image), ref, reporting.Sanitize(digest))
		if verify {
			sig := "-"
			if r.Signature != nil {
				sig = string(r.Signature.Status)
				if r.Signature.Key != "" {
					sig += " (" + r.Signature.Key + ")"
				}
			}
			line += "\t" + sig
		}
		used := strings.Join(r.UsedBy, ", ")
		if len(r.UsedBy) > 2 {
			used = fmt.Sprintf("%s and %d more", strings.Join(r.UsedBy[:2], ", "), len(r.UsedBy)-2)
		}
		fmt.Fprintln(tw, line+"\t"+reporting.Sanitize(used))
	}
	tw.Flush()
	var pins []string
	for _, r := range reports {
		if r.Pin != "" {
			pins = append(pins, fmt.Sprintf("  %s\n    → %s", reporting.Sanitize(r.Image), reporting.Sanitize(r.Pin)))
		}
	}
	if len(pins) > 0 {
		fmt.Fprintln(w, "\nPin these images by digest (what they resolve to right now):")
		fmt.Fprintln(w, strings.Join(pins, "\n"))
	}
	for _, r := range reports {
		if r.Signature != nil && r.Signature.Detail != "" && r.Signature.Status != imagesig.Verified {
			fmt.Fprintf(w, "%s: %s: %s\n", reporting.Sanitize(r.Image), r.Signature.Status, reporting.Sanitize(r.Signature.Detail))
		}
	}
}
