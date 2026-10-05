package setup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bolaum/ghgw/pkg/api"
)

// whoamiTimeout bounds the whole whoami call; the gateway answers it without asking GitHub.
const whoamiTimeout = 30 * time.Second

// maxWhoamiAnswer bounds the answer: a policy with every grant at its limits is far smaller.
const maxWhoamiAnswer = 4 << 20

// Whoami asks the gateway in c whose key c holds and what it may do (SPEC.md section 5.5).
// rt is nil for http.DefaultTransport. Redirects are never followed, so the key goes to the
// gateway only.
func Whoami(ctx context.Context, rt http.RoundTripper, c Config) (api.Whoami, error) {
	ctx, cancel := context.WithTimeout(ctx, whoamiTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL+api.WhoamiPath, nil)
	if err != nil {
		return api.Whoami{}, err
	}
	req.Header.Set("Authorization", "token "+c.Key.Reveal())
	req.Header.Set("Accept", "application/json")
	client := &http.Client{Transport: rt, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return api.Whoami{}, fmt.Errorf("cannot reach the gateway at %s: %w; check the URL, and that this host trusts the gateway's certificate", c.URL, unwrapURLError(err))
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxWhoamiAnswer))
	if err != nil {
		return api.Whoami{}, fmt.Errorf("read the gateway's answer: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		// The gateway's errors are JSON with a message that says what to do; anything else is not
		// a ghgw gateway, and its answer is not shown.
		var m struct{ Message string }
		if json.Unmarshal(body, &m) == nil && strings.HasPrefix(m.Message, "ghgw: ") {
			return api.Whoami{}, fmt.Errorf("the gateway at %s answered %d: %s", c.URL, resp.StatusCode, strings.TrimPrefix(m.Message, "ghgw: "))
		}
		return api.Whoami{}, fmt.Errorf("%s answered %d to %s, not as a ghgw gateway does; check the gateway URL", c.URL, resp.StatusCode, api.WhoamiPath)
	}
	var w api.Whoami
	if err := json.Unmarshal(body, &w); err != nil || w.User == "" {
		return api.Whoami{}, fmt.Errorf("%s answered %s with something that is not a ghgw identity; check the gateway URL", c.URL, api.WhoamiPath)
	}
	return w, nil
}

// unwrapURLError drops the method and URL net/http puts in front of a transport error: the
// message names the gateway already.
func unwrapURLError(err error) error {
	if ue, ok := errors.AsType[*url.Error](err); ok {
		return ue.Err
	}
	return err
}
