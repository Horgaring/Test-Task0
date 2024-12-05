package email

import (
	"log"
)

type MockEmailService struct{}

func NewMockEmailService() *MockEmailService {
	return &MockEmailService{}
}

func (m *MockEmailService) SendIPChangeAlert(email, ip string) error {
	log.Printf("MOCK: Sending IP change alert to %s for IP: %s", email, ip)
	return nil
}
