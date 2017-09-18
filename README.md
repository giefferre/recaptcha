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


}
```