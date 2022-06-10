package scm

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/golang-jwt/jwt"
)

// Claims extracted from the SCM JWT
type ScmJwt struct {
	Lstate string `json:"Lstate"`
	Lcb    string `json:"Lcb"`
	Lname  string `json:"Lname"`
	jwt.StandardClaims
}

// Claims extracted from the Validation JWT
type ValJwt struct {
	Lstate string `json:"Lstate"`
	Lvurl  string `json:"Lvurl"`
	Lname  string `json:"Lname"`
	jwt.StandardClaims
}

// The JSON type to send to the backend
type ApiJson struct {
	Auth string `json:"auth"`
	Data string `json:"data"`
}

// The JSON type used in parsing responses from the backend
type ApiJsonRes struct {
	Result   string              `json:"result"`
	Error    string              `json:"error"`
	Findings []ApiJsonResFinding `json:"findings"`
}

// Responses may include findings, this is their summary
type ApiJsonResFinding struct {
	Type        string `json:"type"`
	ID          string `json:"id"`
	Title       string `json:"title"`
	Message     string `json:"message"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

// JWT public key PEM
const pubpem = `
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0cjxlhAMct2J6OJfTf6s
cPZGf7wmeJ+LvNsj3G1irZpKFPBn0C3GF74VOADYN2oipQWJo2i0hdyc6rRjMXUV
bUGDOwQKEsr+rLx7WC2L/Jea7s7POgiDLmI0jod47c1C3Ph2GGdQ+n7D2d2n2j9T
ENOMYdVFh3GzqqYXKmSb9C5R5hTjKT50WZGgHKJ8d0egBMveqGt8gVxMHEW48SWC
5CtHl6an7FayzIL96/YEbHRLoWHOlpxJOnHw+fZ17ONa7LpF/KmgM2Wpc4qG6PUV
ezweTW/yLdaLrKxZOj1SUJuQ3oM3FJLc48eQ8lSUy9nsDCdfM/ZDtk9eecX0G+SI
KQIDAQAB
-----END PUBLIC KEY-----`

func (s *Scm) debugLog(msg string) {
	if s.debug {
		log.SetPrefix("labs-validator: ")
		log.SetFlags(log.Lshortfile | log.LstdFlags)
		log.Println(msg)
	}
}

// Scm struct contains URLs and tokens used for parsing and validating
// JWTs
type Scm struct {
	scmUrl    string
	valUrl    string
	authToken string
	pubKey    interface{}
	debug     bool
}

// Generate a new Scm so that labval can validate tokens, and communicate
// with the backend
func NewScm(token string, debug bool) (Scm, error) {
	newScm := Scm{
		authToken: token,
		debug:     debug,
	}

	err := newScm.parsePem(pubpem)
	if err != nil {
		return newScm, err
	}

	return newScm, nil
}

// Send data to the Labs Validator
func (s *Scm) SendData(data []byte) (ApiJsonRes, error) {
	b64 := base64.StdEncoding.EncodeToString(data)
	s.debugLog(fmt.Sprintf("Final b64: %s", b64))

	client := http.Client{
		Timeout: time.Second * 30,
	}

	parsedResults := ApiJsonRes{}

	jsonBody := ApiJson{
		Auth: s.authToken,
		Data: b64,
	}

	body, err := json.Marshal(jsonBody)
	if err != nil {
		return parsedResults, fmt.Errorf("Error: Marshaling json - '%s'", err)
	}

	s.debugLog(fmt.Sprintf("JSON MSG to be send to labs validator: %s", jsonBody))

	req, err := http.NewRequest(http.MethodPost, s.scmUrl, bytes.NewBuffer(body))

	req.Header.Set("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return parsedResults, fmt.Errorf("Error: Sending HTTP request - '%s'", err)
	}

	if res.Body != nil {
		defer res.Body.Close()
	}

	resBody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return parsedResults, fmt.Errorf("Error: Reading HTTP response - '%s'", err)
	}

	s.debugLog("Result body:")
	if s.debug {
		spew.Dump(resBody)
	}

	err = json.Unmarshal(resBody, &parsedResults)
	if err != nil {
		return parsedResults, fmt.Errorf("Error: parsing response json - '%s'", err)
	}

	s.debugLog("Parsed results:")
	if s.debug {
		spew.Dump(parsedResults)
	}

	return parsedResults, nil

}

// Load and decode the JWT PUB key
func (s *Scm) parsePem(in string) error {
	block, _ := pem.Decode([]byte(in))
	if block == nil {
		return fmt.Errorf("Error: No pem")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("Error: Error parsing pem block - '%s'", err)
	}

	s.debugLog("Got a successful rsa pub key:")
	if s.debug {
		spew.Dump(pub)
	}

	s.pubKey = pub
	return nil
}

// Parse a JWT, validate the sig, extract and update the claims
func (s *Scm) getUrlFromClaims(claims jwt.Claims, token string) error {
	tkn, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return s.pubKey, nil
	})
	if err != nil {
		return fmt.Errorf("Error: Parsing claims from jwt - '%s'", err)
	}

	if !tkn.Valid {
		return fmt.Errorf("Error: invalid jwt")
	}

	s.debugLog("Got claims")
	if s.debug {
		spew.Dump(tkn)
		spew.Dump(claims)
	}

	return nil
}

// Validate the supplied JWT Token, and try and extract the callback SCM URL
func (s *Scm) GetUrlFromClaims() error {
	claims := &ScmJwt{}
	err := s.getUrlFromClaims(claims, s.authToken)
	if err != nil {
		return err
	}

	url := ""
	if claims.Lstate == "scm_token" {
		url = claims.Lcb
	}

	s.scmUrl = url

	return nil
}

func (s *Scm) GetValUrlFromClaims(jwtstring string) (string, error) {
	newclaims := &ValJwt{}
	err := s.getUrlFromClaims(newclaims, jwtstring)
	if err != nil {
		return "", err
	}

	validateUrl := ""
	if newclaims.Lstate == "validation_token" {
		validateUrl = newclaims.Lvurl
	}

	b64res := base64.URLEncoding.EncodeToString([]byte(jwtstring))
	return fmt.Sprintf("labs validation success!\nVisit %s?%s or visit %s and enter this token to continue:\n\n%s\n\n", validateUrl, b64res, validateUrl, b64res), nil
}
