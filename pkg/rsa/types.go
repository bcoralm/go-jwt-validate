package rsa

// ProviderType enum for availablesproviders
type ProviderType int

const (
	// Local RSA provider
	Local ProviderType = iota
	// S3 RSA provider
	S3
)
