package xcontext

import (
	"context"
	"strings"
)

type contextKey string

const (
	headersKey contextKey = "headers"
	sessionKey contextKey = "session"
)

func WithSession(ctx context.Context, sessionID string) context.Context {
	if _, ok := ctx.Value(sessionKey).(bool); !ok {
		return context.WithValue(ctx, sessionKey, sessionID)
	}
	return ctx
}

func Session(ctx context.Context) string {
	session, ok := ctx.Value(sessionKey).(string)
	if !ok {
		return ""
	}
	return session
}

func WithHeader(ctx context.Context, headers map[string][]string) context.Context {
	return context.WithValue(ctx, headersKey, headers)
}

func Header(ctx context.Context, key string) string {
	headers, ok := ctx.Value(headersKey).(map[string][]string)
	if !ok {
		return ""
	}
	for k := range headers {
		if strings.EqualFold(k, key) {
			return headers[k][0]
		}
	}
	return ""
}

func Headers(ctx context.Context) map[string][]string {
	headers, ok := ctx.Value(headersKey).(map[string][]string)
	if !ok {
		return map[string][]string{}
	}
	return headers
}
