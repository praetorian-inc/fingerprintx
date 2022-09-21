package runner

type cliConfig struct {
	outputFile               string
	outputJSON               bool
	outputCSV                bool
	overwriteOutput          bool
	fastMode                 bool
	timeout                  int
	useUDP                   bool
	maxConcurrentConnections uint
	verbose                  bool
	showErrors               bool

	// Experimental mode fields
	packetsPerSecond int
	bitsPerSecond    int
}
