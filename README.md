[![CircleCI](https://circleci.com/gh/giefferre/recaptcha/tree/master.svg?style=svg)](https://circleci.com/gh/giefferre/recaptcha/tree/master)

# recaptcha

Provides a tool for reCAPTCHA tokens validation.

## Installation

    go get github.com/giefferre/recaptcha

## Usage

Initialization:

```go
import "github.com/giefferre/recaptcha"

func someMethod() {
    validator, err := recaptcha.NewReCaptchaValidator("yourSecretKey")
    if err != nil {
        log.Fatal(err)
    }

    response, err := validator.ValidateToken("aToken")
    if err != nil {
        log.Fatal(err)
    }

    log.Println(response.Success)
}
```