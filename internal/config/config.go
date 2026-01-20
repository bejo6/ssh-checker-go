package config

type Config struct {
	Hosts				[]string
	Port				[]string
	User				[]string
	Password			[]string
	ChunkSize			int
	SSHDelayMs			int
	WorkersCount		int
	WorkersLiveCheck	int
	WorkersLoginCheck	int
}

var (
	LogDebug		bool
	AppConfig		Config
	FormattedOutput	string
)
