package service

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	Role, Port, DatabaseURL, Issuer, Audience, JWKSURL, TemporalAddress, TemporalNamespace, EconomicsURL, EconomicsToken, SignerURL, ExecutorURL, SignerToken, ExecutorToken, PrivateKey, PublicKey, AWSRegion, AWSReadRole, AWSExecutionRole, AWSExternalID, HealthAllowedHosts, WebhookURL, WebhookSecret string
	Fixture                                                                                                                                                                                                                                                                                                 bool
}

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func LoadConfig() Config {
	f, _ := strconv.ParseBool(env("FIXTURE_MODE", "false"))
	if os.Getenv("DATA_MODE") == "fixture" {
		f = true
	}
	return Config{Role: env("APP_ROLE", "api"), Port: env("PORT", "8080"), DatabaseURL: os.Getenv("DATABASE_URL"), Issuer: os.Getenv("OIDC_ISSUER"), Audience: env("OIDC_AUDIENCE", "finops"), JWKSURL: os.Getenv("OIDC_JWKS_URL"), TemporalAddress: env("TEMPORAL_ADDRESS", "temporal:7233"), TemporalNamespace: env("TEMPORAL_NAMESPACE", "default"), EconomicsURL: env("ECONOMICS_URL", "http://economics:8000"), EconomicsToken: os.Getenv("ECONOMICS_TOKEN"), SignerURL: env("SIGNER_URL", "http://signer:8080"), ExecutorURL: env("EXECUTOR_URL", "http://executor:8080"), SignerToken: os.Getenv("SIGNER_TOKEN"), ExecutorToken: os.Getenv("EXECUTOR_TOKEN"), PrivateKey: os.Getenv("SIGNING_PRIVATE_KEY"), PublicKey: os.Getenv("SIGNING_PUBLIC_KEY"), AWSRegion: env("AWS_REGION", "eu-west-1"), AWSReadRole: os.Getenv("AWS_READ_ROLE_ARN"), AWSExecutionRole: os.Getenv("AWS_EXECUTION_ROLE_ARN"), AWSExternalID: os.Getenv("AWS_EXTERNAL_ID"), HealthAllowedHosts: os.Getenv("HEALTH_ALLOWED_HOSTS"), WebhookURL: os.Getenv("WEBHOOK_URL"), WebhookSecret: os.Getenv("WEBHOOK_SECRET"), Fixture: f}
}

const TaskQueue = "finops-execution"
const HTTPTimeout = 30 * time.Second
