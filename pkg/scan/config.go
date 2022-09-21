package scan

import (
	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
)

func (c Config) GeneratePluginConfig(p plugins.Plugin) plugins.PluginConfig {
	id := plugins.CreatePluginID(p)

	timeout := c.DefaultTimeout
	if t, ok := c.TimeoutOverride[id]; ok {
		timeout = t
	}

	return plugins.PluginConfig{
		Timeout: timeout,
	}
}
