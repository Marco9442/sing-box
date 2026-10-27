//go:build with_utls

package tls

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"slices"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/logger"

	utls "github.com/metacubex/utls"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/hkdf"
)

func newRealityHelloClient(t *testing.T, fingerprint string) (*RealityClientConfig, *ecdh.PrivateKey) {
	t.Helper()
	serverKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	config, err := NewRealityClient(context.Background(), logger.NOP(), "example.com", option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: "example.com",
		UTLS:       &option.OutboundUTLSOptions{Enabled: true, Fingerprint: fingerprint},
		Reality: &option.OutboundRealityOptions{
			Enabled:   true,
			PublicKey: base64.RawURLEncoding.EncodeToString(serverKey.PublicKey().Bytes()),
			ShortID:   "0123456789abcdef",
		},
	})
	require.NoError(t, err)
	return config.(*RealityClientConfig), serverKey
}

func readRealityClientHello(t *testing.T, config *RealityClientConfig) ([]byte, *utls.PubClientHelloMsg) {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() { _ = server.Close() })
	go func() {
		defer client.Close()
		_, _ = config.ClientHandshake(context.Background(), client)
	}()
	var header [5]byte
	_, err := io.ReadFull(server, header[:])
	require.NoError(t, err)
	require.Equal(t, byte(22), header[0])
	message := make([]byte, binary.BigEndian.Uint16(header[3:]))
	_, err = io.ReadFull(server, message)
	require.NoError(t, err)
	hello := utls.UnmarshalClientHello(message)
	require.NotNil(t, hello)
	return message, hello
}

func realityKeyShareIndex(hello *utls.PubClientHelloMsg, group utls.CurveID) int {
	return slices.IndexFunc(hello.KeyShares, func(share utls.KeyShare) bool {
		return share.Group == group
	})
}

func realitySpecHasMLKEM(config *RealityClientConfig) (curve bool, share bool) {
	specConn, specPeer := net.Pipe()
	defer specConn.Close()
	defer specPeer.Close()
	spec := utls.UClient(specConn, config.uClient.config.Clone(), config.uClient.id)
	if err := spec.BuildHandshakeState(); err != nil {
		return false, false
	}
	for _, extension := range spec.Extensions {
		switch ext := extension.(type) {
		case *utls.SupportedCurvesExtension:
			curve = common.Contains(ext.Curves, utls.X25519MLKEM768)
		case *utls.KeyShareExtension:
			share = common.Any(ext.KeyShares, func(item utls.KeyShare) bool {
				return item.Group == utls.X25519MLKEM768
			})
		}
	}
	return curve, share
}

// Xray-core since v26.9.8 rejects a chrome ClientHello that lacks an
// X25519MLKEM768 key share ahead of X25519. The session id stays sealed
// with the standalone X25519 share.
func TestRealityClientHelloChromeKeepsX25519MLKEM768(t *testing.T) {
	t.Parallel()
	config, serverKey := newRealityHelloClient(t, "chrome")
	message, hello := readRealityClientHello(t, config)

	curveIndex := slices.Index(hello.SupportedCurves, utls.X25519MLKEM768)
	require.GreaterOrEqual(t, curveIndex, 0)
	require.Less(t, curveIndex, slices.Index(hello.SupportedCurves, utls.X25519))
	mlkemIndex := realityKeyShareIndex(hello, utls.X25519MLKEM768)
	x25519Index := realityKeyShareIndex(hello, utls.X25519)
	require.GreaterOrEqual(t, mlkemIndex, 0)
	require.Less(t, mlkemIndex, x25519Index)

	peerKey, err := ecdh.X25519().NewPublicKey(hello.KeyShares[x25519Index].Data)
	require.NoError(t, err)
	authKey, err := serverKey.ECDH(peerKey)
	require.NoError(t, err)
	_, err = hkdf.New(sha256.New, authKey, hello.Random[:20], []byte("REALITY")).Read(authKey)
	require.NoError(t, err)
	block, err := aes.NewCipher(authKey)
	require.NoError(t, err)
	aead, err := cipher.NewGCM(block)
	require.NoError(t, err)
	additional := slices.Clone(message)
	clear(additional[39:71])
	plaintext, err := aead.Open(nil, hello.Random[20:], hello.SessionId, additional)
	require.NoError(t, err)
	require.Equal(t, []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}, plaintext[8:16])
}

// randomized selects the hybrid group and its key share independently.
// An incomplete pair is removed; a complete pair is kept.
func TestRealityClientHelloRandomizedKeepsPairedX25519MLKEM768(t *testing.T) {
	t.Parallel()
	config, _ := newRealityHelloClient(t, "randomized")
	var kept, stripped int
	for range 48 {
		seed, err := utls.NewPRNGSeed()
		require.NoError(t, err)
		config.uClient.id.Seed = seed
		specCurve, specShare := realitySpecHasMLKEM(config)
		keep := specCurve && specShare

		_, hello := readRealityClientHello(t, config)
		require.Equal(t, keep, common.Contains(hello.SupportedCurves, utls.X25519MLKEM768))
		require.Equal(t, keep, realityKeyShareIndex(hello, utls.X25519MLKEM768) >= 0)
		if keep {
			kept++
		} else {
			stripped++
		}
	}
	require.Positive(t, kept)
	require.Positive(t, stripped)
}
