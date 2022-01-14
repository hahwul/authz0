package logger

import (
	nested "github.com/antonfisher/nested-logrus-formatter"
	"github.com/sirupsen/logrus"
)

func GetLogger(debug bool) *logrus.Logger {
	log := logrus.New()
	log.SetFormatter(&nested.Formatter{
		HideKeys:    true,
		FieldsOrder: []string{"index", "type", "status", "role", "alias", "url"},
	})
	if debug {
		log.Level = logrus.DebugLevel
	}
	return log
}
