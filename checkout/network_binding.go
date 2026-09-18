package checkout

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"
)

type networkBinding struct {
	Version   int    `json:"version"`
	Selection string `json:"selection_sha256"`
	Endpoint  string `json:"endpoint_sha256"`
}

func networkDigest(kind, proxy string) string {
	sum := sha256.Sum256([]byte("checkout-network-v1:" + kind + ":" + strings.TrimSpace(proxy)))
	return hex.EncodeToString(sum[:])
}

// WithNetwork returns a new immutable ledger handle sharing the same durable
// attempt guard. Inputs must be the visitor's selected proxy and the validated,
// pinned proxy actually used by the executor; both empty means explicit direct.
// It does not resolve, dial, or validate a proxy. Only digests enter the record.
// The caller must not infer the network from untrusted quote/JSON fields.
func (l *Ledger) WithNetwork(selected, pinned string) *Ledger {
	if l == nil {
		return nil
	}
	return &Ledger{dir: l.dir, network: &networkBinding{Version: 1, Selection: networkDigest("selection", selected), Endpoint: networkDigest("endpoint", pinned)}}
}

func (l *Ledger) recordedNetwork(a Auth, s Session) (*networkBinding, error) {
	record, err := l.readAttempt(a, s)
	if err != nil {
		return nil, err
	}
	n := record.Network
	if n == nil || n.Version != 1 || !validNetworkDigest(n.Selection) || !validNetworkDigest(n.Endpoint) {
		return nil, errors.New("原付款记录缺少可核验的网络绑定；请通过原官方结账页核对，不自动切换网络")
	}
	return n, nil
}

func validNetworkDigest(s string) bool {
	decoded, err := hex.DecodeString(s)
	return err == nil && len(decoded) == sha256.Size && s == strings.ToLower(s)
}

// VerifyNetworkSelection is checked BEFORE resolving a supplied proxy. Missing
// legacy bindings are not presumed direct and must not be silently upgraded.
func (l *Ledger) VerifyNetworkSelection(a Auth, s Session, selected string) error {
	n, err := l.recordedNetwork(a, s)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(n.Selection), []byte(networkDigest("selection", selected))) != 1 {
		return errors.New("恢复查询必须使用创建订单时的原代理配置；原直连订单请留空")
	}
	return nil
}

// VerifyNetworkEndpoint is checked after safe DNS pinning but BEFORE creating
// the outbound client. A changed DNS result fails closed; no alternate IP or
// direct fallback is attempted. This cannot control rotation behind a proxy.
func (l *Ledger) VerifyNetworkEndpoint(a Auth, s Session, pinned string) error {
	n, err := l.recordedNetwork(a, s)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(n.Endpoint), []byte(networkDigest("endpoint", pinned))) != 1 {
		return errors.New("原代理端点已变化，无法保持本单网络；已停止自动恢复查询")
	}
	return nil
}
