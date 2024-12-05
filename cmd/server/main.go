package main

import (
	"log"
	"net/http"
	"time"

	"auth-service/configs"
	"auth-service/internal/auth"
	"auth-service/internal/database"
	"auth-service/internal/email"
	
	"github.com/caarlos0/env/v6"
)

func main() {
	// Load configuration
	cfg := configs.Config{}
	if err := env.Parse(&cfg); err != nil {
		log.Fatalf("Failed to parse config: %v", err)
	}

	// Initialize database
	db, err := database.NewPostgresDB(
		cfg.Database.Host,
		cfg.Database.Port,
		cfg.Database.User,
		cfg.Database.Password,
		cfg.Database.Name,
	)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	// Initialize schema
	if err := db.InitSchema(); err != nil {
		log.Fatalf("Failed to initialize schema: %v", err)
	}

	// Initialize services
	emailService := email.NewMockEmailService()
	authService := auth.NewAuthService(
		db,
		emailService,
		cfg.JWT.AccessTokenSecret,
		cfg.JWT.RefreshTokenSecret,
		time.Duration(cfg.JWT.AccessTokenTTL)*time.Minute,
		time.Duration(cfg.JWT.RefreshTokenTTL)*time.Minute,
	)

	// Initialize handlers
	handler := auth.NewHandler(authService)

	// Setup routes
	http.HandleFunc("/auth/tokens", handler.GenerateTokens)
	http.HandleFunc("/auth/refresh", handler.RefreshTokens)

	// Start server
	log.Printf("Starting server on port %s", cfg.Server.Port)
	if err := http.ListenAndServe(":"+cfg.Server.Port, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
