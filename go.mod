module github.com/Qwentrix/lumen

go 1.24

toolchain go1.24.5

require (
	github.com/Qwentrix/lumen-scoring v0.0.0-00010101000000-000000000000
	github.com/spf13/cobra v1.8.1
	golang.org/x/sys v0.27.0
)

require (
	github.com/aws/aws-sdk-go-v2 v1.41.11
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.12 // indirect
	github.com/aws/aws-sdk-go-v2/config v1.32.22
	github.com/aws/aws-sdk-go-v2/credentials v1.19.21 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.27 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.27 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.27 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.28 // indirect
	github.com/aws/aws-sdk-go-v2/service/cloudtrail v1.56.2
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.305.1
	github.com/aws/aws-sdk-go-v2/service/iam v1.54.2
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.11 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.9.20 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.27 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.19.27 // indirect
	github.com/aws/aws-sdk-go-v2/service/rds v1.119.0
	github.com/aws/aws-sdk-go-v2/service/s3 v1.103.1
	github.com/aws/aws-sdk-go-v2/service/signin v1.1.3 // indirect: transitive dep of the SSO credential provider
	github.com/aws/aws-sdk-go-v2/service/sso v1.31.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.36.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.43.1 // indirect
	github.com/aws/smithy-go v1.27.0
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/kr/pretty v0.2.1 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// Local-dev alias — remove once github.com/Qwentrix/lumen-scoring publishes v0.1.0.
// CI implication: build jobs must check out Qwentrix/lumen-scoring into ../lumen-scoring.
replace github.com/Qwentrix/lumen-scoring => ../lumen-scoring
