package logger

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type ZapLogger struct {
	log *zap.Logger
}

func NewZapLogger(level string) Logger {
	cfg := zap.NewProductionConfig()

	switch level {
	case "debug":
		cfg.Level = zap.NewAtomicLevelAt(zapcore.DebugLevel)
	case "info":
		cfg.Level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
	case "warn":
		cfg.Level = zap.NewAtomicLevelAt(zapcore.WarnLevel)
	case "error":
		cfg.Level = zap.NewAtomicLevelAt(zapcore.ErrorLevel)
	default:
		cfg.Level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
	}

	log, _ := cfg.Build()
	return &ZapLogger{log: log}
}

func (z *ZapLogger) Debug(msg string, fields map[string]any) {
	z.log.Debug(msg, toZapFields(fields)...)
}

func (z *ZapLogger) Info(msg string, fields map[string]any) {
	z.log.Info(msg, toZapFields(fields)...)
}

func (z *ZapLogger) Warn(msg string, fields map[string]any) {
	z.log.Warn(msg, toZapFields(fields)...)
}

func (z *ZapLogger) Error(msg string, fields map[string]any) {
	z.log.Error(msg, toZapFields(fields)...)
}

func toZapFields(m map[string]any) []zap.Field {
	fields := make([]zap.Field, 0, len(m))
	for k, v := range m {
		fields = append(fields, zap.Any(k, v))
	}
	return fields
}
