// Provides a tool for reCAPTCHA tokens validation.

package recaptcha

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

const (
	// ErrorMissingInputSecret is received when the secret parameter is missing.
	ErrorMissingInputSecret = "missing-input-secret"

	// ErrorInvalidInputSecret is received when the secret parameter is invalid or malformed.
	ErrorInvalidInputSecret = "invalid-input-secret"

	// ErrorMissingInputResponse is received when the response parameter is missing.
	ErrorMissingInputResponse = "missing-input-response"

	// ErrorInvalidInputResponse is received when the response parameter is invalid or malformed.
	ErrorInvalidInputResponse = "invalid-input-response"

	// ErrorBadRequest is received when the request is invalid or malformed.
	ErrorBadRequest = "bad-request"

	siteVerifyAPIBaseURL = "https://www.google.com/recaptcha/api/siteverify"
)

// Request

type httpPostForm func(url string, data url.Values) (*http.Response, error)

// Validator validates reCAPTCHA tokens.
type Validator struct {
	secretKey string
	postForm  httpPostForm
}

// NewReCaptchaValidator returns a newly initialized Validator with the given secret key.
func NewReCaptchaValidator(sk string) (*Validator, error) {
	if sk == "" {
		return nil, errors.New("no secret key given")
	}

	return &Validator{
		secretKey: sk,
		postForm:  http.PostForm,
	}, nil
}

// ValidateToken checks on Google's servers if the given token is valid.
func (v *Validator) ValidateToken(token string) (*ValidationResponse, error) {
	return v.doValidation(token, nil)
}

// ValidateTokenForIP checks on Google's servers if the given token is valid for the given IP.
func (v *Validator) ValidateTokenForIP(token, ipAddress string) (*ValidationResponse, error) {
	return v.doValidation(token, &ipAddress)
}

func (v *Validator) doValidation(token string, ipAddress *string) (*ValidationResponse, error) {
	params := url.Values{}
	params.Add("secret", v.secretKey)
	params.Add("response", token)

	if ipAddress != nil {
		params.Add("remoteip", *ipAddress)
	}

	req, err := v.postForm(siteVerifyAPIBaseURL, params)
	if err != nil {
		return nil, err
	}

	defer req.Body.Close()

	data, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}

	r := &ValidationResponse{}
	err = json.Unmarshal(data, r)
	return r, err
}

// Response objects

// ValidationError is returned when the validation operation fails.
type ValidationError string

// ValidationResponse is returned to a token validation.
type ValidationResponse struct {
	// true if token is valid
	Success bool `json:"success"`

	// timestamp of the challenge load (ISO format yyyy-MM-dd'T'HH:mm:ssZZ)
	ChallengeTimestamp time.Time `json:"-"`

	// the hostname of the site where the reCAPTCHA was solved
	// used for reCAPTCHA V2 and invisible reCAPTCHA
	Hostname string `json:"hostname,omitempty"`

	// the package name of the app where the reCAPTCHA was solved
	// used for reCAPTCHA Android
	PackageName string `json:"apk_package_name,omitempty"`

	// list of errors, optional
	Errors []ValidationError `json:"error-codes,omitempty"`
}

// UnmarshalJSON overwrites the standard JSON unmarshal.
func (r *ValidationResponse) UnmarshalJSON(data []byte) error {
	type Alias ValidationResponse
	auxValidationResponse := &struct {
		*Alias
		ISOChallengeTimestamp string `json:"challenge_ts,omitempty"`
	}{
		Alias: (*Alias)(r),
	}
	if err := json.Unmarshal(data, &auxValidationResponse); err != nil {
		return err
	}

	challengeTimestamp, err := time.Parse(time.RFC3339, auxValidationResponse.ISOChallengeTimestamp)
	if err != nil {
		return err
	}
	r.ChallengeTimestamp = challengeTimestamp

	return nil
}
