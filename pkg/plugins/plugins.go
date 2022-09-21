package plugins

import "fmt"

var Plugins = make(map[Protocol][]Plugin)
var pluginIDs = make(map[PluginID]bool)

// This function must not be run concurrently.
// This function should only be run once per plugin.
func RegisterPlugin(p Plugin) {
	id := CreatePluginID(p)
	if pluginIDs[id] {
		panic(fmt.Sprintf("plugin: Register called twice for driver %+v\n", id))
	}

	pluginIDs[id] = true

	var pluginList []Plugin
	if list, exists := Plugins[p.Type()]; exists {
		pluginList = list
	} else {
		pluginList = make([]Plugin, 0)
	}

	Plugins[p.Type()] = append(pluginList, p)
}

func (p Protocol) String() (s string) {
	switch p {
	case IP:
		s = "IP"
	case TCP:
		s = "TCP"
	case TCPTLS:
		s = "TCPTLS"
	case UDP:
		s = "UDP"
	default:
		panic("No string name for protocol %d.")
	}

	return
}

func CreatePluginID(p Plugin) PluginID {
	return PluginID{
		name:     p.Name(),
		protocol: p.Type(),
	}
}

func (p PluginID) String() string {
	return fmt.Sprintf("%s/%v", p.protocol, p.name)
}
