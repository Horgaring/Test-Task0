package database

import (
	"fmt"
	"auth-service/internal/models"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

type PostgresDB struct {
	db *sqlx.DB
}

func NewPostgresDB(host, port, user, password, dbname string) (*PostgresDB, error) {
	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)
	
	db, err := sqlx.Connect("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	return &PostgresDB{db: db}, nil
}

func (p *PostgresDB) StoreRefreshToken(token *models.RefreshToken) error {
	query := `
		INSERT INTO refresh_tokens (id, user_id, token, ip, issued_at, expires_at, used)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`
	
	_, err := p.db.Exec(query,
		token.ID,
		token.UserID,
		token.Token,
		token.IP,
		token.IssuedAt,
		token.ExpiresAt,
		token.Used,
	)
	
	if err != nil {
		return fmt.Errorf("failed to store refresh token: %w", err)
	}
	
	return nil
}

func (p *PostgresDB) GetRefreshToken(tokenID string) (*models.RefreshToken, error) {
	var token models.RefreshToken
	
	query := `
		SELECT id, user_id, token, ip, issued_at, expires_at, used
		FROM refresh_tokens
		WHERE id = $1`
	
	err := p.db.Get(&token, query, tokenID)
	if err != nil {
		return nil, fmt.Errorf("failed to get refresh token: %w", err)
	}
	
	return &token, nil
}

func (p *PostgresDB) MarkTokenAsUsed(tokenID string) error {
	query := `
		UPDATE refresh_tokens
		SET used = true
		WHERE id = $1`
	
	_, err := p.db.Exec(query, tokenID)
	if err != nil {
		return fmt.Errorf("failed to mark token as used: %w", err)
	}
	
	return nil
}

// InitSchema creates the necessary database schema
func (p *PostgresDB) InitSchema() error {
	schema := `
		CREATE TABLE IF NOT EXISTS refresh_tokens (
			id UUID PRIMARY KEY,
			user_id UUID NOT NULL,
			token TEXT NOT NULL,
			ip TEXT NOT NULL,
			issued_at TIMESTAMP NOT NULL,
			expires_at TIMESTAMP NOT NULL,
			used BOOLEAN NOT NULL DEFAULT FALSE
		);
		
		CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id);
	`
	
	_, err := p.db.Exec(schema)
	if err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}
	
	return nil
}
