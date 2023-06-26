package minileap

import "crypto/ecdh"

// ECDH derives a shared symmetric key using the private half of your
// Curve25519 keypair and the account ID (miniLock ID) of another user
// you are encrypting a miniLeap message/message/blob to.
func ECDH(keyPairPrivate []byte, theirAccountID string) (*[ValidKeyLength]byte, error) {
	if len(keyPairPrivate) != ValidKeyLength {
		return nil, ErrInvalidKey
	}

	curve := ecdh.X25519()

	theirPubkey, err := DecodeAccountID(theirAccountID)
	if err != nil {
		return nil, err
	}
	theirPubX25519, err := curve.NewPublicKey(theirPubkey)
	if err != nil {
		return nil, err
	}

	myPrivX25519, err := curve.NewPrivateKey(keyPairPrivate)
	if err != nil {
		return nil, err
	}

	// Magic :-D
	sharedSecret, err := myPrivX25519.ECDH(theirPubX25519)
	if err != nil {
		return nil, err
	}

	sharedSecret32, err := ConvertKey(sharedSecret)
	if err != nil {
		return nil, err
	}

	return sharedSecret32, nil
}
