module github.com/Qwentrix/lumen

go 1.22

require (
	github.com/Qwentrix/lumen-scoring v0.0.0-00010101000000-000000000000
	github.com/spf13/cobra v1.8.1
)

require (
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/kr/pretty v0.2.1 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// Local-dev alias — remove once github.com/Qwentrix/lumen-scoring publishes v0.1.0.
// CI implication: build jobs must check out Qwentrix/lumen-scoring into ../lumen-scoring.
replace github.com/Qwentrix/lumen-scoring => ../lumen-scoring
