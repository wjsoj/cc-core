package browser

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/chromedp/cdproto/browser"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/target"
	"github.com/chromedp/chromedp"
	"github.com/wjsoj/cc-core/checkout"
)

// Config contains deployment configuration, never Session or card data. Proxy
// must be the SAME validated/pinned SOCKS5 URL used by the order's Go client.
// The worker must run as an unprivileged user with Chromium sandbox enabled.
type Config struct {
	Executable string
	Proxy      string
	Locale     string
	Timezone   string
	Lifetime   time.Duration
	Headful    bool
}

// Browser owns one process, one incognito context and one egress bridge. Do not
// pool it across accounts. No raw CDP endpoint or general-purpose JS API is
// exported to public HTTP handlers. Close terminates active actions and tunnels.
type Browser struct {
	ctx             context.Context
	cancel          context.CancelFunc
	allocatorCancel context.CancelFunc
	rootCancel      context.CancelFunc
	tabCancel       context.CancelFunc
	egress          *bridge
	once            sync.Once
	gate            chan struct{}
	owner           string
	session         checkout.Session
	createAttempted bool
	contextID       cdp.BrowserContextID
	cardFrames      map[target.ID]context.Context // guarded by gate; no card data
	cardFilled      bool                          // guarded by gate; no card data
	billingHash     string                        // filled billing binding, not the address itself
	submitAttempted bool                          // once a durable guard is written, never click again
	observer        *paymentObserver
}

func Start(ctx context.Context, config Config) (*Browser, error) {
	dial, err := egressDialer(config.Proxy)
	if err != nil {
		return nil, err
	}
	return start(ctx, config, dial)
}

func start(parent context.Context, config Config, dial dialContext) (*Browser, error) {
	if !filepath.IsAbs(config.Executable) {
		return nil, errors.New("chromium executable must be an absolute path")
	}
	if os.Geteuid() == 0 {
		return nil, errors.New("browser worker must not run as root")
	}
	launcher, err := os.Stat(cleanEnvironmentLauncher)
	if err != nil || !launcher.Mode().IsRegular() || launcher.Mode().Perm()&0111 == 0 {
		return nil, errors.New("browser environment isolation requires /usr/bin/env")
	}
	if config.Locale == "" {
		config.Locale = "en-US"
	}
	if config.Locale != "en-US" && config.Locale != "zh-CN" {
		return nil, errors.New("unsupported browser locale")
	}
	if config.Timezone == "" {
		config.Timezone = "America/New_York"
	}
	if _, err := time.LoadLocation(config.Timezone); err != nil {
		return nil, errors.New("invalid browser timezone")
	}
	if config.Lifetime == 0 {
		config.Lifetime = 15 * time.Minute
	}
	if config.Lifetime < time.Second || config.Lifetime > 20*time.Minute {
		return nil, errors.New("invalid browser lifetime")
	}
	life, cancel := context.WithTimeout(parent, config.Lifetime)
	egress, err := newBridge(life, dial)
	if err != nil {
		cancel()
		return nil, err
	}
	// Use a small explicit option set instead of defaults that disable site
	// isolation. Neither webdriver nor browser security checks are concealed.
	opts := []chromedp.ExecAllocatorOption{
		chromedp.ExecPath(config.Executable), chromedp.NoFirstRun, chromedp.NoDefaultBrowserCheck,
		chromedp.ModifyCmdFunc(func(cmd *exec.Cmd) { isolatedBrowserCommand(cmd, config.Headful) }),
		chromedp.Flag("headless", !config.Headful), chromedp.Flag("no-sandbox", false),
		chromedp.Flag("enable-automation", true), chromedp.Flag("disable-extensions", true),
		chromedp.Flag("disable-background-networking", true), chromedp.Flag("disable-sync", true),
		chromedp.Flag("disable-breakpad", true), chromedp.Flag("disable-crash-reporter", true),
		chromedp.Flag("disable-quic", true), chromedp.Flag("disable-component-update", true),
		chromedp.Flag("force-webrtc-ip-handling-policy", "disable_non_proxied_udp"),
		chromedp.Flag("host-resolver-rules", "MAP * ~NOTFOUND, EXCLUDE 127.0.0.1"),
		chromedp.ProxyServer(egress.address()), chromedp.Flag("proxy-bypass-list", "<-loopback>"),
		chromedp.Flag("lang", config.Locale), chromedp.WindowSize(1280, 900),
		chromedp.Flag("remote-debugging-address", "127.0.0.1"),
	}
	allocator, allocatorCancel := chromedp.NewExecAllocator(life, opts...)
	// Do not enable protocol/console logging: events can contain credentials.
	silent := func(string, ...any) {}
	root, rootCancel := chromedp.NewContext(allocator, chromedp.WithErrorf(silent), chromedp.WithLogf(silent))
	b := &Browser{cancel: cancel, allocatorCancel: allocatorCancel, rootCancel: rootCancel, egress: egress, gate: make(chan struct{}, 1)}
	startup := time.AfterFunc(30*time.Second, cancel)
	defer startup.Stop()
	if err = chromedp.Run(root); err != nil {
		b.Close()
		return nil, errors.New("chromium startup failed; check executable and OS sandbox")
	}
	// Create the first incognito window explicitly. chromedp v0.14.2 sends
	// newWindow=false, which modern Chromium rejects for an empty context.
	executor := cdp.WithExecutor(root, chromedp.FromContext(root).Browser)
	b.contextID, err = target.CreateBrowserContext().WithDisposeOnDetach(true).Do(executor)
	if err != nil {
		b.Close()
		return nil, errors.New("cannot create isolated browser context")
	}
	pageID, err := target.CreateTarget("about:blank").WithBrowserContextID(b.contextID).WithNewWindow(true).Do(executor)
	if err != nil {
		b.Close()
		return nil, errors.New("cannot create isolated browser window")
	}
	b.ctx, b.tabCancel = chromedp.NewContext(root, chromedp.WithTargetID(pageID))
	b.observer = newPaymentObserver(b.ctx)
	b.observer.attach(b.ctx)
	err = chromedp.Run(b.ctx,
		emulation.SetLocaleOverride().WithLocale(config.Locale), emulation.SetTimezoneOverride(config.Timezone),
		observationNetworkEnable(), network.SetCacheDisabled(true),
		chromedp.ActionFunc(func(ctx context.Context) error {
			c := chromedp.FromContext(ctx)
			return browser.SetDownloadBehavior(browser.SetDownloadBehaviorBehaviorDeny).
				WithBrowserContextID(b.contextID).Do(cdp.WithExecutor(ctx, c.Browser))
		}),
	)
	if err != nil {
		b.Close()
		// This is before any credentials or page input have been supplied.
		return nil, fmt.Errorf("browser context initialization failed: %w", err)
	}
	context.AfterFunc(life, b.Close)
	return b, nil
}

// run serializes operations, includes queue time in cancellation and never
// returns raw CDP errors (which can contain input values or page content).
func (b *Browser) run(ctx context.Context, actions ...chromedp.Action) error {
	select {
	case b.gate <- struct{}{}:
		defer func() { <-b.gate }()
	case <-ctx.Done():
		return errors.New("browser operation canceled")
	case <-b.ctx.Done():
		return errors.New("browser session closed")
	}
	op, cancel := context.WithTimeout(b.ctx, 45*time.Second)
	defer cancel()
	stop := context.AfterFunc(ctx, cancel)
	defer stop()
	if err := chromedp.Run(op, actions...); err != nil {
		return errors.New("browser operation failed or timed out")
	}
	return nil
}

func (b *Browser) Close() {
	b.once.Do(func() {
		b.cancel()
		b.egress.close()
		if b.tabCancel != nil {
			b.tabCancel()
		}
		b.rootCancel()
		b.allocatorCancel()
	})
}
