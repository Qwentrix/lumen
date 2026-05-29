module github.com/Qwentrix/lumen

go 1.22

require (
	github.com/Qwentrix/lumen-scoring v0.0.0-00010101000000-000000000000
	github.com/spf13/cobra v1.8.1
)

require (
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
)

// Local-dev alias — remove once github.com/Qwentrix/lumen-scoring publishes its first tag.
replace github.com/Qwentrix/lumen-scoring => ../lumen-scoring
