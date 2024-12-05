package auth

import (
	"auth-service/internal/models"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidToken     = errors.New("invalid token")
	ErrTokenExpired     = errors.New("token expired")
	ErrTokenReused      = errors.New("refresh token reused")
	ErrIPAddressChanged = errors.New("ip address changed")
)

type TokenRepository interface {
	StoreRefreshToken(token *models.RefreshToken) error
	GetRefreshToken(tokenID string) (*models.RefreshToken, error)
	MarkTokenAsUsed(tokenID string) error
}

type EmailService interface {
	SendIPChangeAlert(email, ip string) error
}

type AuthService struct {
	tokenRepo    TokenRepository
	emailService EmailService
	config       struct {
		accessSecret  string
		refreshSecret string
		accessTTL     time.Duration
		refreshTTL    time.Duration
	}
}

func NewAuthService(tokenRepo TokenRepository, emailService EmailService, accessSecret, refreshSecret string, accessTTL, refreshTTL time.Duration) *AuthService {
	return &AuthService{
		tokenRepo:    tokenRepo,
		emailService: emailService,
		config: struct {
			accessSecret  string
			refreshSecret string
			accessTTL     time.Duration
			refreshTTL    time.Duration
		}{
			accessSecret:  accessSecret,
			refreshSecret: refreshSecret,
			accessTTL:     accessTTL,
			refreshTTL:    refreshTTL,
		},
	}
}

func (s *AuthService) GenerateTokenPair(userID string, ip string) (*models.TokenPair, error) {
	// Generate Access Token
	accessToken, err := s.generateAccessToken(userID, ip)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate Refresh Token
	refreshToken, hash, err := s.generateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Store refresh token in database
	err = s.tokenRepo.StoreRefreshToken(&models.RefreshToken{
		ID:        refreshToken[:36], // Use first 36 chars as UUID
		UserID:    userID,
		Token:     hash,
		IP:        ip,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(s.config.refreshTTL),
		Used:      false,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	return &models.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (s *AuthService) RefreshTokens(refreshToken string, ip string) (*models.TokenPair, error) {
	// Extract token ID (first 36 chars)
	if len(refreshToken) < 36 {
		return nil, ErrInvalidToken
	}
	tokenID := refreshToken[:36]

	// Get stored refresh token
	storedToken, err := s.tokenRepo.GetRefreshToken(tokenID)
	if err != nil {
		return nil, fmt.Errorf("failed to get refresh token: %w", err)
	}

	// Check if token is used
	if storedToken.Used {
		return nil, ErrTokenReused
	}

	// Check if token is expired
	if time.Now().After(storedToken.ExpiresAt) {
		return nil, ErrTokenExpired
	}

	// Verify token hash
	err = bcrypt.CompareHashAndPassword([]byte(storedToken.Token), []byte(refreshToken))
	if err != nil {
		return nil, ErrInvalidToken
	}

	// Check IP address
	if storedToken.IP != ip {

		// Send email alert (async)
		go s.emailService.SendIPChangeAlert("user@example.com", ip) // In real app, get email from user service
		return nil, ErrIPAddressChanged
	}

	// Mark current token as used
	err = s.tokenRepo.MarkTokenAsUsed(tokenID)
	if err != nil {
		return nil, fmt.Errorf("failed to mark token as used: %w", err)
	}

	// Generate new token pair
	return s.GenerateTokenPair(storedToken.UserID, ip)
}

func (s *AuthService) generateAccessToken(userID string, ip string) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"ip":      ip,
		"exp":     time.Now().Add(s.config.accessTTL).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	return token.SignedString([]byte(s.config.accessSecret))
}

func (s *AuthService) generateRefreshToken() (string, string, error) {
	// Generate random bytes (32 bytes is sufficient for security)
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}

	// Create a token that includes a UUID-like format for the first part
	// and base64 encoded random bytes for the second part
	token := fmt.Sprintf("%x-%x-%x-%x-%x.%s",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16],
		base64.RawURLEncoding.EncodeToString(b[16:]))

	// Hash the token for storage
	hash, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	if err != nil {
		return "", "", err
	}

	return token, string(hash), nil
}
