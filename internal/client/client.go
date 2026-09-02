package client

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	BaseURL		*url.URL
	HTTPClient	*http.Client
	Email		string
	Token		string
	cryptoEngine *CryptoEngine
}

func NewClient(baseURL *url.URL, email string) *Client {
	return &Client{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: 10*time.Second,
		},
		Email: email,
	}
}

func (c *Client) doRequest(req *http.Request) (*http.Response, error) {
    if c.Token != "" {
        req.Header.Set("Authorization", "Bearer " + c.Token)
    }
    req.Header.Set("Content-Type", "application/json")
    return c.HTTPClient.Do(req)
}

type authRequest struct {
	Email   string  `json:"email"`
	AuthHash []byte `json:"auth_hash"`
}

func (c *Client) Login(masterPassword []byte) error {
	if c.Email == "" {
		return ErrMissingEmail
	}
	
	// TODO - Salt fetch/Generation
	
	// Initialize crypto engine
	crypto, err := NewCryptoEngine(masterPassword, []byte(c.Email))
	if err != nil { return err }
	c.cryptoEngine = crypto

	// Setup
	reqBody, err := json.Marshal(authRequest{
		Email: c.Email,
		AuthHash: c.cryptoEngine.AuthKey(),
	})
	if err != nil { return err }

	endpoint := c.BaseURL.ResolveReference(&url.URL{Path: "/api/v1/login"})

	req, err := http.NewRequest("POST", endpoint.String(), bytes.NewBuffer(reqBody))
	if err != nil { return err }
	
	resp, err := c.doRequest(req)
	if err != nil { return err }
	defer resp.Body.Close()

	// Response
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == http.StatusUnauthorized {
			return fmt.Errorf("%w: %s", ErrUnauthorized, strings.TrimSpace(string(body)))
		}
		return fmt.Errorf("Login failed with status: %v; body: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	type LoginResponse struct {
        Status	string `json:"status"`
        Data	struct {
            Token string `json:"token"`
        } `json:"data"`
    }

	var result LoginResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("Error decoding response: %v", err)
	}

	c.Token = result.Data.Token

	return nil
}

func (c *Client) Register(masterPassword [] byte) error {
	
	if c.Email == "" {
		return ErrMissingEmail
	}

	// TODO - Salt fetch/Generation

	// Initialize crypto engine
	crypto, err := NewCryptoEngine(masterPassword, []byte(c.Email))
	if err != nil { return err }
	c.cryptoEngine = crypto

	// Setup
	reqBody, err := json.Marshal(authRequest{
		Email: c.Email,
		AuthHash: c.cryptoEngine.AuthKey(),
	})
	if err != nil { return err }
	
	// Request
	endpoint := c.BaseURL.ResolveReference(&url.URL{Path: "/api/v1/register"})

	req, err := http.NewRequest("POST", endpoint.String(), bytes.NewBuffer(reqBody))
	if err != nil { return err }
	
	resp, err := c.doRequest(req)
	if err != nil { return err }
	defer resp.Body.Close()

	// Response
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Registration failed with status: %v; body: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	return nil
}

func (c *Client) AddPassword(serviceName string, cred *Credentials) error {

	// Get ServiceIndex and ServiceEncrypted
	serviceIndex:= c.cryptoEngine.ComputeBlindIndex([]byte(serviceName))
	
	serviceCiphertext, err := c.cryptoEngine.Encrypt([]byte(serviceName))
	if err != nil { return err }

	// Credentials encryption
	dataJSON, err := json.Marshal(cred)
	if err != nil { return err }
	defer clear(dataJSON)

	credentialsCiphertext, err := c.cryptoEngine.Encrypt(dataJSON)
	if err != nil { return err }

	// Request
	reqBody, err := json.Marshal(credentialsPayload{
		ServiceIndex: serviceIndex,
		ServiceEncrypted: serviceCiphertext,
		PayloadEncrypted: credentialsCiphertext,
	})

	endpoint := c.BaseURL.ResolveReference(&url.URL{Path: "/api/v1/credentials/"})
	req, err := http.NewRequest("POST", endpoint.String(), bytes.NewBuffer(reqBody))
	if err != nil { return err }

	resp, err := c.doRequest(req)
	if err != nil { return err }
	defer resp.Body.Close()

	// Response
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("Add password failed with status: %v", resp.Status)
	}

	return nil
}

func (c *Client) FetchCredentials(serviceName string) (*Credentials, error) {
	// Service Index
	serviceIndex:= c.cryptoEngine.ComputeBlindIndex([]byte(serviceName))

	// Request
	encodedService := base64.RawURLEncoding.EncodeToString(serviceIndex)
	path := fmt.Sprintf("/api/v1/credentials/%s", encodedService)
	endpoint := c.BaseURL.ResolveReference(&url.URL{Path: path})
	req, err := http.NewRequest("GET", endpoint.String(), nil)
	if err != nil { return nil, err }
	
	resp, err := c.doRequest(req)
	if err != nil { return nil, err }
	defer resp.Body.Close()
	
	// Response
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Get password failed with status: %v", resp.Status)
	}

	var result credentialsPayload
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("Error decoding response: %v", err)
	}

	// Decrypt ciphertext
	dataJSON, err := c.cryptoEngine.Decrypt(result.PayloadEncrypted)
	if err != nil { return nil, err}
	defer clear(dataJSON)

	// Parse credentials
	var credentials Credentials
	if err := json.Unmarshal(dataJSON, &credentials); err != nil { 
		return nil, err 
	}

	return &credentials, nil
}
