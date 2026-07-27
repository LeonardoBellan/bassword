package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
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
		HTTPClient: &http.Client{},
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

func (c *Client) login(email string, authHash []byte) error {
	
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
	fmt.Printf("Obtained JWT: %v", c.Token)

	return nil
}

func (c *Client) register(email string, authHash []byte) error {
	// Setup
	reqBody, err := json.Marshal(authRequest{
		Email: email,
		AuthHash: string(authHash),
	})
	if err != nil { return err }

	endpoint := c.BaseURL.ResolveReference(&url.URL{Path: "/api/v1/register"})

	// Request
	req, err := http.NewRequest("POST", endpoint.String(), bytes.NewBuffer(reqBody))
	if err != nil { return err }
	
	resp, err := c.doRequest(req)
	if err != nil { return err }
	defer resp.Body.Close()

	// Response
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Registration failed with status: %v", resp.Status)
	}

	return nil
}