package configs

type Config struct {
	Server struct {
		Port string `env:"SERVER_PORT" envDefault:"8080"`
	}
	Database struct {
		Host     string `env:"DB_HOST" envDefault:"localhost"`
		Port     string `env:"DB_PORT" envDefault:"5432"`
		User     string `env:"DB_USER" envDefault:"postgres"`
		Password string `env:"DB_PASSWORD" envDefault:"postgres"`
		Name     string `env:"DB_NAME" envDefault:"auth_db"`
	}
	JWT struct {
		AccessTokenSecret  string `env:"JWT_ACCESS_SECRET" envDefault:"your-access-secret-key"`
		RefreshTokenSecret string `env:"JWT_REFRESH_SECRET" envDefault:"your-refresh-secret-key"`
		AccessTokenTTL     int    `env:"JWT_ACCESS_TTL" envDefault:"15"`     // minutes
		RefreshTokenTTL    int    `env:"JWT_REFRESH_TTL" envDefault:"10080"` // 7 days in minutes
	}
	Email struct {
		From     string `env:"EMAIL_FROM" envDefault:"noreply@example.com"`
		Host     string `env:"EMAIL_HOST" envDefault:"smtp.example.com"`
		Port     int    `env:"EMAIL_PORT" envDefault:"587"`
		Username string `env:"EMAIL_USERNAME" envDefault:""`
		Password string `env:"EMAIL_PASSWORD" envDefault:""`
	}
}
