package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	validHeaders := make(http.Header)
	var validContent []string
	validContent = append(validContent, "ApiKey content")
	validHeaders["Authorization"] = validContent
	res, err := GetAPIKey(validHeaders)
	if err != nil {
		t.Error(err)
	}
	if res != "content" {
		t.Errorf("Return incorrect: %v", res)
	}

	emptyHeaders := make(http.Header)
	res, err = GetAPIKey(emptyHeaders)
	if err != ErrNoAuthHeaderIncluded {
		t.Error(err)
	}
	if res != "" {
		t.Errorf("Return incorrect: %v", res)
	}

	bearerHeaders := make(http.Header)
	var bearerContent []string
	bearerContent = append(bearerContent, "Bearer token")
	bearerHeaders["Authorization"] = bearerContent
	res, err = GetAPIKey(bearerHeaders)
	if err.Error() != "malformed authorization header" {
		t.Error(err)
	}
	if res != "" {
		t.Errorf("Return incorrect: %v", res)
	}

	invalidHeaders := make(http.Header)
	var invalidContent []string
	invalidContent = append(invalidContent, "application/json")
	invalidHeaders["Content-Type"] = invalidContent
	res, err = GetAPIKey(invalidHeaders)
	if err != ErrNoAuthHeaderIncluded {
		t.Error(err)
	}
	if res != "" {
		t.Errorf("Return incorrect: %v", res)
	}

	multiHeaders := make(http.Header)
	multiHeaders["Authorization"] = validContent
	multiHeaders["Content-Type"] = invalidContent
	res, err = GetAPIKey(multiHeaders)
	if err != nil {
		t.Error(err)
	}
	if res != "content" {
		t.Errorf("Return incorrect: %v", res)
	}

}
