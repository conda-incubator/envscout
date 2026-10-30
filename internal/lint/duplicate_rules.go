package lint

import (
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/conda-incubator/envscout/internal/evidence"
	gorattler "github.com/conda-incubator/go-rattler"
)

func validMetadataHash(value string, length int) bool {
	if value == "" {
		return true
	}
	_, err := hex.DecodeString(value)
	return err == nil && len(value) == length
}

func duplicateRecords(prefix evidence.Prefix) (map[string]gorattler.PrefixRecord, bool) {
	if prefix.RecordCoverage != evidence.Complete || len(prefix.Records) == 0 {
		return nil, false
	}
	records := map[string]gorattler.PrefixRecord{}
	for _, located := range prefix.Records {
		record := located.Record
		name, valid := canonicalCondaName(record.Name)
		channel, channelValid := localChannel(record)
		_, versionErr := gorattler.CompareVersions(record.Version, record.Version)
		if !valid || !channelValid || versionErr != nil || record.Build == "" || record.Subdir == "" || !validMetadataHash(record.SHA256, 64) || !validMetadataHash(record.MD5, 32) {
			return nil, false
		}
		if _, duplicate := records[name]; duplicate {
			return nil, false
		}
		record.Name, record.Channel = name, channel
		record.SHA256, record.MD5 = strings.ToLower(record.SHA256), strings.ToLower(record.MD5)
		records[name] = record
	}
	return records, true
}

func matchingMetadata(a, b map[string]gorattler.PrefixRecord) (bool, bool) {
	match, known := len(a) == len(b), true
	for _, name := range slices.Sorted(maps.Keys(a)) {
		left := a[name]
		right, present := b[name]
		if !present {
			match = false
			continue
		}
		version := 0
		var err error
		if left.Version != right.Version {
			version, err = gorattler.CompareVersions(left.Version, right.Version)
		}
		if err != nil {
			match, known = false, false
		}
		if left.Build != right.Build || left.BuildNumber != right.BuildNumber || left.Subdir != right.Subdir || left.Channel != right.Channel || version != 0 {
			match = false
		}
		if (left.SHA256 == "") != (right.SHA256 == "") || (left.MD5 == "") != (right.MD5 == "") {
			match, known = false, false
		}
		if left.SHA256 != right.SHA256 || left.MD5 != right.MD5 {
			match = false
		}
	}
	return match, known
}

type duplicateSet struct {
	records map[string]gorattler.PrefixRecord
	valid   bool
}

// prepareDuplicateSets normalizes each prefix once per evaluation, not per pair.
func prepareDuplicateSets(prefixes []evidence.Prefix) map[string]duplicateSet {
	sets := make(map[string]duplicateSet, len(prefixes))
	for _, prefix := range prefixes {
		if _, exists := sets[prefix.Path]; exists {
			continue
		}
		records, valid := duplicateRecords(prefix)
		sets[prefix.Path] = duplicateSet{records: records, valid: valid}
	}
	return sets
}

func checkDuplicates(target evidence.Target, opts RuleOptions, rule Rule) (Outcome, []Finding) {
	return checkPreparedDuplicates(target, opts, rule, prepareDuplicateSets(append(slices.Clone(target.Peers), target.Prefixes...)))
}

func prepareDuplicates(prefixes []evidence.Prefix) func(evidence.Target, RuleOptions, Rule) (Outcome, []Finding) {
	sets := prepareDuplicateSets(prefixes)
	return func(target evidence.Target, opts RuleOptions, rule Rule) (Outcome, []Finding) {
		return checkPreparedDuplicates(target, opts, rule, sets)
	}
}

func checkPreparedDuplicates(target evidence.Target, opts RuleOptions, rule Rule, sets map[string]duplicateSet) (Outcome, []Finding) {
	outcome := localRecordOutcome(target)
	if outcome.Status == NotApplicable {
		return outcome, nil
	}
	if target.Peers == nil {
		outcome.Status, outcome.Reason = Unknown, "cross-prefix conda metadata was not supplied"
		return outcome, nil
	}
	peers := slices.Clone(target.Peers)
	slices.SortFunc(peers, func(a, b evidence.Prefix) int { return strings.Compare(a.Path, b.Path) })
	var findings []Finding
	emitted := map[string]bool{}
	seenPrefix := map[string]bool{}
	for _, prefix := range sortedLocalPrefixes(target) {
		if seenPrefix[prefix.Path] {
			continue
		}
		seenPrefix[prefix.Path] = true
		set := sets[prefix.Path]
		records := set.records
		if !set.valid {
			outcome.Status, outcome.Reason = Unknown, "complete canonical conda identity metadata is unavailable for "+prefix.Path
			continue
		}
		paths := []string{prefix.Path}
		for _, peer := range peers {
			if peer.Path == prefix.Path {
				continue
			}
			other := sets[peer.Path]
			if !other.valid {
				outcome.Status, outcome.Reason = Unknown, "a peer has incomplete canonical conda identity metadata"
				continue
			}
			match, known := matchingMetadata(records, other.records)
			if !known {
				outcome.Status, outcome.Reason = Unknown, "peer metadata lacks a comparable version or reported hash"
			}
			if match {
				paths = append(paths, peer.Path)
			}
		}
		if len(paths) < 2 {
			continue
		}
		f := newFinding(target, rule, opts.Severity, paths, nil)
		// One report per distinct group of paths, keyed by its sorted identity.
		key := strings.Join(f.paths, "\x00")
		if emitted[key] {
			continue
		}
		emitted[key] = true
		f.Evidence.Count = len(f.paths)
		f.Message = fmt.Sprintf("Prefixes %s have matching conda package metadata for %d packages, including version, build, channel, subdir and reported hashes. %s", quotedPaths(f.Evidence.Paths), len(records), rule.Description)
		findings = append(findings, f)
	}
	return outcome, findings
}
