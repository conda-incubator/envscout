package evidence

import (
	"bytes"
	"fmt"
	"path"
	"strings"

	"github.com/anchore/stereoscope/pkg/file"
)

var commandDirectories = []string{"/usr/bin", "/bin", "/usr/sbin", "/sbin"}
var osPackageCommands = []string{"apt", "apt-get", "dnf", "dnf5", "yum", "rpm", "dpkg", "apk", "zypper", "pacman"}
var shellCommands = []string{"sh", "bash", "dash", "ash", "ksh", "zsh", "fish", "csh", "tcsh"}

func (c *imageCollector) executable(p string) (*file.Reference, error) {
	resolution, err := c.resolve(p)
	if err != nil {
		return nil, err
	}
	if !resolution.HasReference() {
		return nil, nil
	}
	metadata, err := c.loaded.Image.FileCatalog.Get(*resolution.Reference)
	if err != nil {
		return nil, fmt.Errorf("command metadata is unavailable")
	}
	if metadata.FileInfo == nil || metadata.Type != file.TypeRegular || !metadata.Mode().IsRegular() || metadata.Mode().Perm()&0o111 == 0 {
		return nil, nil
	}
	header, err := c.readReference(*resolution.Reference, 512, false)
	if err != nil {
		return nil, err
	}
	if !bytes.HasPrefix(header, []byte{0x7f, 'E', 'L', 'F'}) && !validShebang(header) {
		return nil, nil
	}
	return resolution.Reference, nil
}

func validShebang(header []byte) bool {
	if !bytes.HasPrefix(header, []byte("#!")) {
		return false
	}
	line := strings.SplitN(string(header[2:]), "\n", 2)[0]
	fields := strings.Fields(line)
	return len(fields) > 0 && path.IsAbs(fields[0]) && len(fields[0]) > 1
}

func (c *imageCollector) collectTools(capability string) error {
	commands, output := osPackageCommands, &c.target.Tools
	if capability == "shell-tools" {
		commands, output = shellCommands, &c.target.Shells
	}
	seen := map[file.ID]bool{}
	for _, command := range commands {
		for _, directory := range commandDirectories {
			if err := c.ctx.Err(); err != nil {
				return err
			}
			p := path.Join(directory, command)
			found, _, err := c.tree.File(file.Path(p))
			if c.ctx.Err() != nil {
				return c.ctx.Err()
			}
			if err != nil {
				c.issue(capability, p, "command path cannot be resolved")
				continue
			}
			if !found {
				continue
			}
			ref, err := c.executable(p)
			if err != nil {
				if c.ctx.Err() != nil {
					return c.ctx.Err()
				}
				c.issue(capability, p, err.Error())
				continue
			}
			if ref == nil || seen[ref.ID()] {
				continue
			}
			if _, err := c.contentReference(*ref); err != nil {
				if c.ctx.Err() != nil {
					return c.ctx.Err()
				}
				c.issue(capability, p, "command is executable, but shared hardlink identity cannot be verified")
			}
			seen[ref.ID()] = true
			c.add(capability, output, Artifact{Path: p, Kind: command, Reference: c.reference(*ref)})
		}
	}
	return nil
}

func (c *imageCollector) collectRuntime(asserted string) error {
	if asserted != "" {
		if !path.IsAbs(asserted) || path.Clean(asserted) != asserted || strings.ContainsAny(asserted, "\\\x00\r\n") {
			return fmt.Errorf("runtime prefix must be a canonical absolute image path")
		}
		found := false
		for _, prefix := range c.prefixes {
			if err := c.ctx.Err(); err != nil {
				return err
			}
			if prefix.Path == asserted {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("runtime prefix is not a recognized final-image conda prefix: %q", asserted)
		}
		c.target.RuntimePrefix = asserted
	}
	if c.loaded.Config == nil {
		c.issue("runtime-config", "image startup", "verified image configuration is unavailable")
		return nil
	}
	config := c.loaded.Config.Config
	bytesRead, entries := 0, 0
	for _, list := range [][]string{config.Entrypoint, config.Cmd, config.Env} {
		for _, value := range list {
			if err := c.ctx.Err(); err != nil {
				return err
			}
			entries++
			bytesRead += len(value)
			if entries > imageEntryLimit || bytesRead > imageMetadataLimit || len(value) > 4096 {
				c.limit("runtime-config", "image startup", "runtime configuration limit exceeded")
				return nil
			}
		}
	}
	command := ""
	if len(config.Entrypoint) > 0 {
		command = config.Entrypoint[0]
	} else if len(config.Cmd) > 0 {
		command = config.Cmd[0]
	}
	if command == "" || strings.ContainsAny(command, "\x00\r\n") {
		return nil
	}
	paths := []string{}
	if path.IsAbs(command) {
		paths = append(paths, path.Clean(command))
	} else if !strings.Contains(command, "/") {
		for _, env := range config.Env {
			if err := c.ctx.Err(); err != nil {
				return err
			}
			if strings.HasPrefix(env, "PATH=") {
				for _, dir := range strings.Split(strings.TrimPrefix(env, "PATH="), ":") {
					if err := c.ctx.Err(); err != nil {
						return err
					}
					if path.IsAbs(dir) {
						paths = append(paths, path.Join(dir, command))
					}
				}
				break
			}
		}
		if len(paths) == 0 {
			for _, dir := range commandDirectories {
				if err := c.ctx.Err(); err != nil {
					return err
				}
				paths = append(paths, path.Join(dir, command))
			}
		}
	}
	for _, candidate := range paths {
		if err := c.ctx.Err(); err != nil {
			return err
		}
		found, _, err := c.tree.File(file.Path(candidate))
		if c.ctx.Err() != nil {
			return c.ctx.Err()
		}
		if err != nil {
			c.issue("runtime-config", "image startup", "runtime command path cannot be resolved")
			continue
		}
		if !found {
			continue
		}
		ref, err := c.executable(candidate)
		if err != nil {
			if c.ctx.Err() != nil {
				return c.ctx.Err()
			}
			c.issue("runtime-config", "image startup", "runtime command evidence could not be inspected")
			continue
		}
		if ref == nil {
			continue
		}
		if c.target.RuntimePrefix == "" && path.IsAbs(candidate) {
			for _, prefix := range c.prefixes {
				if err := c.ctx.Err(); err != nil {
					return err
				}
				if (within(candidate, prefix.Path) || within(string(ref.RealPath), prefix.Path)) && len(prefix.Path) > len(c.target.RuntimePrefix) {
					c.target.RuntimePrefix = prefix.Path
				}
			}
		}
		name := path.Base(command)
		if name == "conda" || name == "mamba" || name == "micromamba" {
			c.target.RuntimeUsesTooling = true
		}
		break
	}
	return c.ctx.Err()
}
