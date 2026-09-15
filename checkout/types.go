package checkout

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/mail"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var sessionPattern = regexp.MustCompile(`^(oaics_|cs_live_)[A-Za-z0-9_]{1,200}$`)
var entityPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{1,40}$`)
var tokenPattern = regexp.MustCompile(`^[A-Za-z0-9._~+-]+$`)

func validToken(s string) bool { return len(s) >= 20 && len(s) <= 16384 && tokenPattern.MatchString(s) }

var countries = " AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW MV "
var currencies = " USD AUD CAD GBP EUR CLP JPY INR IDR PKR THB MYR TWD VND PHP NGN ZAR KZT TZS EGP BRL SEK CZK PLN DKK NOK KRW COP MXN PEN HUF QAR RON ILS AED SGD NZD CHF SAR DZD LBP MAD YER "

type Selection struct {
	Plan     string `json:"plan"`
	Country  string `json:"country"`
	Currency string `json:"currency"`
}

func (s Selection) Validate() error {
	switch s.Plan {
	case "chatgptplusplan", "chatgptprolite", "chatgptpro", "chatgptgoplan":
	default:
		return errors.New("订阅计划无效")
	}
	if len(s.Country) != 2 || !strings.Contains(countries, " "+s.Country+" ") || len(s.Currency) != 3 || !strings.Contains(currencies, " "+s.Currency+" ") {
		return errors.New("国家或货币无效")
	}
	return nil
}

type Billing struct {
	Name       string `json:"name"`
	Email      string `json:"email"`
	Line1      string `json:"line1"`
	Line2      string `json:"line2"`
	City       string `json:"city"`
	State      string `json:"state"`
	PostalCode string `json:"postal_code"`
	Country    string `json:"country"`
}

func (b Billing) Validate(country string) error {
	for _, s := range []string{b.Name, b.Email, b.Line1, b.City, b.PostalCode, b.Country} {
		if strings.TrimSpace(s) == "" {
			return errors.New("请填写完整真实账单信息")
		}
	}
	for _, s := range []string{b.Name, b.Email, b.Line1, b.Line2, b.City, b.State, b.PostalCode} {
		if len(s) > 254 || strings.ContainsFunc(s, func(r rune) bool { return r < 32 || r == 127 }) {
			return errors.New("账单字段格式无效")
		}
	}
	m, e := mail.ParseAddress(b.Email)
	if e != nil || m.Address != b.Email || b.Country != country {
		return errors.New("账单邮箱或国家无效")
	}
	return nil
}
func (b Billing) address() map[string]string {
	return map[string]string{"line1": b.Line1, "line2": b.Line2, "city": b.City, "state": b.State, "postal_code": b.PostalCode, "country": b.Country}
}

type Card struct {
	Number string `json:"number"`
	Month  string `json:"month"`
	Year   string `json:"year"`
	CVC    string `json:"cvc"`
}

func (c Card) Validate() error {
	if !regexp.MustCompile(`^[0-9]{12,19}$`).MatchString(c.Number) || !regexp.MustCompile(`^[0-9]{3,4}$`).MatchString(c.CVC) {
		return errors.New("卡号或 CVV 格式无效")
	}
	sum := 0
	for i := len(c.Number) - 1; i >= 0; i-- {
		v := int(c.Number[i] - '0')
		if (len(c.Number)-1-i)%2 == 1 {
			v *= 2
			if v > 9 {
				v -= 9
			}
		}
		sum += v
	}
	m, e := strconv.Atoi(c.Month)
	y, e2 := strconv.Atoi(c.Year)
	now := time.Now().UTC()
	if sum == 0 || sum%10 != 0 || e != nil || e2 != nil || m < 1 || m > 12 || len(c.Year) != 4 || y < now.Year() || y == now.Year() && m < int(now.Month()) || y > now.Year()+30 {
		return errors.New("卡号或有效期无效")
	}
	return nil
}

// Auth is never persisted. Claims are a consistency hint, NOT local JWT
// authentication; every operation authenticates the token with the upstream.
type Auth struct {
	Token     string
	UserID    string
	AccountID string
}

func ParseAuth(raw string) (Auth, error) {
	raw = strings.TrimSpace(raw)
	a := Auth{}
	if strings.HasPrefix(raw, "{") {
		var s struct {
			AccessToken string `json:"accessToken"`
		}
		if len(raw) > 100000 || json.Unmarshal([]byte(raw), &s) != nil {
			return a, errors.New("Session JSON 无效")
		}
		raw = s.AccessToken
	}
	if !validToken(raw) {
		return a, errors.New("Session / accessToken 无效")
	}
	a.Token = raw
	parts := strings.Split(raw, ".")
	if len(parts) == 3 {
		b, e := base64.RawURLEncoding.DecodeString(parts[1])
		if e == nil {
			var claims struct {
				Auth struct {
					User    string `json:"chatgpt_user_id"`
					Account string `json:"chatgpt_account_id"`
				} `json:"https://api.openai.com/auth"`
				Exp int64 `json:"exp"`
			}
			if json.Unmarshal(b, &claims) == nil {
				if claims.Exp > 0 && claims.Exp <= time.Now().Unix() {
					return Auth{}, errors.New("Session 已过期")
				}
				a.UserID = claims.Auth.User
				a.AccountID = claims.Auth.Account
			}
		}
	}
	return a, nil
}
func Owner(a Auth) string { s := sha256.Sum256([]byte(a.Token)); return hex.EncodeToString(s[:]) }

type Session struct {
	ID     string `json:"checkout_session_id"`
	Entity string `json:"processor_entity"`
}

func (s Session) Validate() error {
	if !sessionPattern.MatchString(s.ID) || !entityPattern.MatchString(s.Entity) {
		return errors.New("结账会话标识无效")
	}
	return nil
}
func (s Session) URL() string {
	if s.Validate() != nil {
		return ""
	}
	return "https://chatgpt.com/checkout/" + s.Entity + "/" + s.ID
}

type Snapshot struct {
	Status         string            `json:"status"`
	PaymentStatus  string            `json:"payment_status"`
	Plan           string            `json:"plan_name"`
	PublishableKey string            `json:"publishable_key"`
	Amount         int64             `json:"amount_total"`
	Currency       string            `json:"currency"`
	Expires        int64             `json:"expires_at"`
	Metadata       map[string]string `json:"metadata"`
}

func (s Snapshot) Paid() bool { return s.Status == "complete" && s.PaymentStatus == "paid" }

type Quote struct {
	Session   Session
	Selection Selection
	Billing   Billing
	Amount    int64
	Expires   time.Time
	Key       string
	UserID    string
	AccountID string
}
