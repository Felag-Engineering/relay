package enroll

import (
	"context"
	"sync"
)

// MemoryRepository is an in-memory Repository implementation. It is safe for
// concurrent use. All returned Tokens are deep copies so callers cannot corrupt
// stored state through pointer mutation.
type MemoryRepository struct {
	mu     sync.RWMutex
	tokens map[string]*Token
}

// NewMemoryRepository creates an empty MemoryRepository.
func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{tokens: make(map[string]*Token)}
}

// Create inserts a copy of t. Returns an error if a token with the same ID already
// exists.
func (r *MemoryRepository) Create(_ context.Context, t *Token) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.tokens[t.ID]; exists {
		return ErrInvalidToken
	}
	r.tokens[t.ID] = cloneToken(t)
	return nil
}

// ByID returns a deep copy of the stored token or ErrNotFound.
func (r *MemoryRepository) ByID(_ context.Context, id string) (*Token, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	t, ok := r.tokens[id]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneToken(t), nil
}

// Save overwrites the stored token with a copy of t. Returns ErrNotFound if no
// token with that ID exists.
func (r *MemoryRepository) Save(_ context.Context, t *Token) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.tokens[t.ID]; !ok {
		return ErrNotFound
	}
	r.tokens[t.ID] = cloneToken(t)
	return nil
}

// cloneToken returns a deep copy of t, duplicating the SecretHash and Scope slices
// so mutations by callers do not affect stored state.
func cloneToken(t *Token) *Token {
	c := *t
	c.SecretHash = append([]byte(nil), t.SecretHash...)
	c.Scope = append([]string(nil), t.Scope...)
	return &c
}
