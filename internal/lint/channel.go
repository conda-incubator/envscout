package lint

import (
	"net/url"
	"strings"

	gorattler "github.com/conda-incubator/go-rattler"
)

type channelFamily string

const (
	channelOther        channelFamily = ""
	channelDefaultsMain channelFamily = "defaults-main"
	channelDefaultsR    channelFamily = "defaults-r"
	channelDefaultsMSYS channelFamily = "defaults-msys2"
	channelForge        channelFamily = "conda-forge"
)

type channelFacts struct {
	identity string
	family   channelFamily
}

// Canonicalization removes userinfo but retains query/fragment identity. Remove
// only the explicit subdir; family recognition is narrower than canonicalization.
func condaChannelFacts(record gorattler.PrefixRecord) (channelFacts, bool) {
	channel, err := gorattler.CanonicalChannel(record.Channel)
	if err != nil {
		return channelFacts{}, false
	}
	u, err := url.Parse(channel)
	if err != nil {
		return channelFacts{}, false
	}
	if record.Subdir != "" {
		u.Path = strings.TrimSuffix(strings.TrimSuffix(u.Path, "/"), "/"+record.Subdir)
	}
	u.Path = strings.TrimSuffix(u.Path, "/") + "/"
	facts := channelFacts{identity: u.String(), family: channelOther}
	switch {
	case strings.EqualFold(u.Host, "repo.anaconda.com"):
		switch u.Path {
		case "/pkgs/main/":
			facts.family = channelDefaultsMain
		case "/pkgs/r/":
			facts.family = channelDefaultsR
		case "/pkgs/msys2/":
			facts.family = channelDefaultsMSYS
		}
	case strings.EqualFold(u.Host, "conda.anaconda.org") && u.Path == "/conda-forge/":
		facts.family = channelForge
	}
	return facts, true
}
