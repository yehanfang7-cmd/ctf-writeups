// Package appsecrets exposes the project's sensitive strings as opaque,
// AES-GCM-encrypted Secret values. The real content is defined in
// build/secrets.src.json and materialised into secrets_gen.go by securegen;
// no plaintext sensitive string ever appears in a compiled .go file.
//
//go:generate go run ../../tools/securegen
package appsecrets
