package models

import "time"

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type RefreshToken struct {
	ID        string    `db:"id"`
	UserID    string    `db:"user_id"`
	Token     string    `db:"token"` // bcrypt hash of the refresh token
	IP        string    `db:"ip"`
	IssuedAt  time.Time `db:"issued_at"`
	ExpiresAt time.Time `db:"expires_at"`
	Used      bool      `db:"used"`
}

type TokenClaims struct {
	UserID string `json:"user_id"`
	IP     string `json:"ip"`
}
