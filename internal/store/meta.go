package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
)

// InstanceID is this Gate's own ID, made on first use and kept with the
// database: a Gate restarted or upgraded on the same data stays the same Gate.
func (s *Store) InstanceID(ctx context.Context) (string, error) {
	var id string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = 'instance'`).Scan(&id)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	if _, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO meta (key, value) VALUES ('instance', ?)`, hex.EncodeToString(b)); err != nil {
		return "", err
	}
	err = s.db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = 'instance'`).Scan(&id)
	return id, err
}
