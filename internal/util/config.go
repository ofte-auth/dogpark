package util

import (
	"github.com/spf13/viper"
)

// Config is an alias for the config package.
type Config = *viper.Viper

// InitConfig initializes the config system.
func InitConfig() {
	viper.SetEnvPrefix("ofte")
	viper.AutomaticEnv()
}
