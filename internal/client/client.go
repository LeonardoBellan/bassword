package client

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/LeonardoBellan/bassword/internal/crypto"
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
	AuthHash string `json:"auth_hash"`
}

type credentialsRequest struct {
	ServiceName   string `json:"service_name"`
    EncryptedData string `json:"encrypted_data"`
}

type secretData struct {
	Username	string	`json:"user"`
	Password	[]byte	`json:"pwd"`
}


func (c *Client) Login(email string, authHash []byte) error {
	
	// Setup
	reqBody, err := json.Marshal(authRequest{
		Email: email,
		AuthHash: string(authHash),
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
		AuthHash: string(authHash),
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

func (c *Client) AddPassword(encryptionKey, plaintext []byte, serviceName, username string) error {
	// Setup
	dataJSON, err := json.Marshal( secretData{
		Username: username,
		Password: plaintext,
	})
	if err != nil { return err }
	defer crypto.Wipe(dataJSON)

	ciphertext, err := crypto.Encrypt(dataJSON, encryptionKey)
	if err != nil { return err }

	reqBody, err := json.Marshal(credentialsRequest{
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

	return nil
}

func (c *Client) GetPassword(encryptionKey []byte, serviceName string) (string, []byte, error) {

	return "", nil, nil
}