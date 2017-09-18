package recaptcha

import (
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

const (
	mockSK            = "mockSecretKey"
	mockToken         = "mockToken"
	mockIPAddress     = "192.168.1.1"
	mockErrorResponse = `{
		"success": false,
		"error-codes": [
			"missing-input-response",
			"missing-input-secret"
		]
	}`
	mockSuccessResponse = `{
		"success": true,
		"challenge_ts": "2017-09-18T22:28:24Z",
		"hostname": "www.example.com"
	}`
)

type mockReadCloser struct {
	reader *strings.Reader
}

func (mrc *mockReadCloser) Read(b []byte) (n int, err error) {
	return mrc.reader.Read(b)
}

func (mrc *mockReadCloser) Close() (err error) {
	return nil
}

type mockHTTPClient struct {
	passedURL    string
	passedParams url.Values

	mockHTTPResponse *http.Response
	mockErr          error
}

func (c *mockHTTPClient) mockPostForm(url string, params url.Values) (*http.Response, error) {
	c.passedURL = url
	c.passedParams = params

	return c.mockHTTPResponse, c.mockErr
}

func TestThatNewReCaptchaValidatorErrorsWhenBlankSecretKeyIsGiven(t *testing.T) {
	_, err := NewReCaptchaValidator("")

	if err == nil {
		t.Fatal("expected error was not received")
	}
}

func TestThatNewReCaptchaValidatorReturnAProperlyInitializedValidator(t *testing.T) {
	v, _ := NewReCaptchaValidator(mockSK)

	if v.secretKey != mockSK {
		t.Fatal("secret key was not set properly")
	}
}

func TestThatURLIsProperlySetWhenValidateTokenIsCalled(t *testing.T) {
	mockClient := &mockHTTPClient{
		mockHTTPResponse: &http.Response{
			Body: &mockReadCloser{
				strings.NewReader(""),
			},
		},
		mockErr: nil,
	}

	v, _ := NewReCaptchaValidator(mockSK)
	v.postForm = mockClient.mockPostForm

	v.ValidateToken(mockToken)

	if mockClient.passedURL != siteVerifyAPIBaseURL {
		t.Fatal("passed URL is different from expected")
	}
}

func TestThatParametersAreProperlySetWhenValidateTokenIsCalled(t *testing.T) {
	mockClient := &mockHTTPClient{
		mockHTTPResponse: &http.Response{
			Body: &mockReadCloser{
				strings.NewReader(""),
			},
		},
		mockErr: nil,
	}

	v, _ := NewReCaptchaValidator(mockSK)
	v.postForm = mockClient.mockPostForm

	// test params on ValidateToken
	v.ValidateToken(mockToken)

	expectedValues := url.Values{}
	expectedValues.Add("secret", mockSK)
	expectedValues.Add("response", mockToken)

	if !reflect.DeepEqual(mockClient.passedParams, expectedValues) {
		t.Fatal("expected parameters not received")
	}

	// test params on ValidateTokenForIP
	v.ValidateTokenForIP(mockToken, mockIPAddress)

	expectedValues = url.Values{}
	expectedValues.Add("secret", mockSK)
	expectedValues.Add("response", mockToken)
	expectedValues.Add("remoteip", mockIPAddress)

	if !reflect.DeepEqual(mockClient.passedParams, expectedValues) {
		t.Fatal("expected parameters not received")
	}
}

func TestThatFailingValidationResponseIsReceivedProperly(t *testing.T) {
	mockClient := &mockHTTPClient{
		mockHTTPResponse: &http.Response{
			Body: &mockReadCloser{
				strings.NewReader(mockErrorResponse),
			},
		},
		mockErr: nil,
	}

	v, _ := NewReCaptchaValidator(mockSK)
	v.postForm = mockClient.mockPostForm

	r, _ := v.ValidateToken(mockToken)
	if r.Success != false || len(r.Errors) != 2 {
		t.Fatal("expected response not received")
	}
}

func TestThatSuccessValidationResponseIsReceivedProperly(t *testing.T) {
	mockClient := &mockHTTPClient{
		mockHTTPResponse: &http.Response{
			Body: &mockReadCloser{
				strings.NewReader(mockSuccessResponse),
			},
		},
		mockErr: nil,
	}

	v, _ := NewReCaptchaValidator(mockSK)
	v.postForm = mockClient.mockPostForm

	expectedTime, _ := time.Parse(time.RFC3339, "2017-09-18T22:28:24Z")

	r, _ := v.ValidateToken(mockToken)
	if r.ChallengeTimestamp != expectedTime || r.Success != true || r.Hostname != "www.example.com" {
		t.Fatal("expected response not received")
	}
}
