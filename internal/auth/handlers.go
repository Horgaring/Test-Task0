package auth

import (
	"encoding/json"
	"net/http"
)

type Handler struct {
	service *AuthService
}

func NewHandler(service *AuthService) *Handler {
	return &Handler{service: service}
}

type generateTokensRequest struct {
	UserID string `json:"user_id"`
}

type refreshTokensRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func (h *Handler) GenerateTokens(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req generateTokensRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "Invalid request body"})
		return
	}

	ip := getClientIP(r)
	tokens, err := h.service.GenerateTokenPair(req.UserID, ip)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, tokens)
}

func (h *Handler) RefreshTokens(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req refreshTokensRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "Invalid request body"})
		return
	}

	ip := getClientIP(r)
	tokens, err := h.service.RefreshTokens(req.RefreshToken, ip)
	if err != nil {
		status := http.StatusInternalServerError
		switch err {
		case ErrInvalidToken, ErrTokenReused:
			status = http.StatusUnauthorized
		case ErrTokenExpired:
			status = http.StatusUnauthorized
		case ErrIPAddressChanged:
			status = http.StatusForbidden
		}
		writeJSON(w, status, errorResponse{Error: err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, tokens)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first
	forwardedFor := r.Header.Get("X-Forwarded-For")
	if forwardedFor != "" {
		return forwardedFor
	}

	// Fall back to RemoteAddr
	return r.RemoteAddr
}
