package auth

import (
	"crypto/tls"
	"errors"
	"fmt"
	"strings"

	ldap "github.com/go-ldap/ldap/v3"
)

//Conn represents an Active Directory connection.
type Conn struct {
	Conn   *ldap.Conn
	Config *Config
}

//Connect returns an open connection to an Active Directory server or an error if one occurred.
func (c *Config) Connect() (*Conn, error) {
	switch c.Security {
	case SecurityNone:
		conn, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", c.Server, c.Port))
		if err != nil {
			return nil, fmt.Errorf("Connection error: %w", err)
		}
		return &Conn{Conn: conn, Config: c}, nil
	case SecurityTLS:
		conn, err := ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", c.Server, c.Port), &tls.Config{ServerName: c.Server, RootCAs: c.RootCAs})
		if err != nil {
			return nil, fmt.Errorf("Connection error: %w", err)
		}
		return &Conn{Conn: conn, Config: c}, nil
	case SecurityStartTLS:
		conn, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", c.Server, c.Port))
		if err != nil {
			return nil, fmt.Errorf("Connection error: %w", err)
		}
		err = conn.StartTLS(&tls.Config{ServerName: c.Server, RootCAs: c.RootCAs})
		if err != nil {
			return nil, fmt.Errorf("Connection error: %w", err)
		}
		return &Conn{Conn: conn, Config: c}, nil
	case SecurityInsecureTLS:
		conn, err := ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", c.Server, c.Port), &tls.Config{ServerName: c.Server, InsecureSkipVerify: true})
		if err != nil {
			return nil, fmt.Errorf("Connection error: %w", err)
		}
		return &Conn{Conn: conn, Config: c}, nil
	case SecurityInsecureStartTLS:
		conn, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", c.Server, c.Port))
		if err != nil {
			return nil, fmt.Errorf("Connection error: %w", err)
		}
		err = conn.StartTLS(&tls.Config{ServerName: c.Server, InsecureSkipVerify: true})
		if err != nil {
			return nil, fmt.Errorf("Connection error: %w", err)
		}
		return &Conn{Conn: conn, Config: c}, nil
	default:
		return nil, errors.New("Configuration error: invalid SecurityType")
	}
}

//Bind authenticates the connection with the given userPrincipalName and password
//and returns the result or an error if one occurred.
func (c *Conn) Bind(upn, password string) (bool, error) {
	if password == "" {
		return false, nil
	}

	err := c.Conn.Bind(upn, password)
	if err != nil {
		if e, ok := err.(*ldap.Error); ok {
			if e.ResultCode == ldap.LDAPResultInvalidCredentials {
				var msg string
				s := err.Error()
				if strings.Contains(s, "52e") {
					msg = "账号或密码不正确"
				} else if strings.Contains(s, "773") {
					msg = "该账号必须修改密码后才能使用"
				} else if strings.Contains(s, "775") {
					msg = "该账号已锁定, 请联系管理员解锁!"
				} else if strings.Contains(s, "532") {
					msg = "密码已过有效期,请联系管理员重置!"
				} else if strings.Contains(s, "533") {
					msg = "该账号已禁用,请联系管理员!"
				} else if strings.Contains(s, "701") {
					msg = "该账号已过期,请联系管理员!"
				} else {
					msg = s
				}
				return false, errors.New(msg)
			}
		}
		return false, fmt.Errorf("Bind error (%s): %w", upn, err)
	}

	return true, nil
}
