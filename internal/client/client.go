package client

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/LeonardoBellan/bassword/internal/shared/crypto"
)

type Client struct {
	BaseURL    *url.URL
	Token      string
	HTTPClient *http.Client
}

func NewClient(baseURL *url.URL, token string) *Client {
	return &Client{
		BaseURL: baseURL,
		Token: token,
		HTTPClient: &http.Client{
			Timeout: 10*time.Second,
		},
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
	Email   string 	`json:"email"`
	AuthHash []byte `json:"auth_hash"`
}

func (c *Client) Login(email string, authHash []byte) error {
	
	// Setup
	reqBody, err := json.Marshal(authRequest{
		Email: email,
		AuthHash: authHash,
	})
	if err != nil { return err }

	endpoint := c.BaseURL.ResolveReference(&url.URL{Path: "/api/v1/login"})

	// Request
	req, err := http.NewRequest("POST", endpoint.String(), bytes.NewBuffer(reqBody))
	if err != nil { return err }
	
	resp, err := c.doRequest(req)
	if err != nil { return err }
	defer resp.Body.Close()

	// Response
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			return ErrUnauthorized
		}
		return fmt.Errorf("Login failed with status: %v", resp.Status)
	}

	type LoginResponse struct {
        Status	string 		`json:"status"`
        Data	struct {
            Token string 	`json:"token"`
        } 					`json:"data"`
    }

	var result LoginResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("Error deconding response: %v", err)
	}

	c.Token = result.Data.Token

	return nil
}

func (c *Client) Register(email string, authHash []byte) error {
	// Setup
	reqBody, err := json.Marshal(authRequest{
		Email: email,
		AuthHash: authHash,
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
		return fmt.Errorf("Registration failed with status: %v", resp.Status)
	}

	return nil
}

func (c *Client) AddPassword(encryptionKey []byte, serviceName string, cred *Credentials) error {

	// Parse JSON
	dataJSON, err := json.Marshal(cred)
	if err != nil { return err }
	defer crypto.Wipe(dataJSON)

	// Encrypt
	ciphertext, err := crypto.Encrypt(dataJSON, encryptionKey)
	if err != nil { return err }

	// Encode Base64URL
	reqBody, err := json.Marshal(credentialsPayload{
		ServiceName: serviceName,
		EncryptedData: base64.URLEncoding.EncodeToString(ciphertext),
	})

	// Request
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

func (c *Client) GetPassword(encryptionKey []byte, serviceName string) (*Credentials, error) {

	// Request
	safeServiceName := url.PathEscape(serviceName)
	path := fmt.Sprintf("/api/v1/credentials/%s", safeServiceName)
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
	
	// Decode base64URL
	ciphertext, err := base64.URLEncoding.DecodeString(result.EncryptedData)
	if err != nil { return nil, err }

	// Decrypt ciphertext
	dataJSON, err := crypto.Decrypt(ciphertext, encryptionKey)
	if err != nil { return nil, err}
	defer crypto.Wipe(dataJSON)

	// Parse credentials
	var credentials Credentials
	if err := json.Unmarshal(dataJSON, &credentials); err != nil { 
		return nil, err 
	}

	return &credentials, nil
}