package wallet

import (
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/0chain/gosdk/zcnbridge/chain"

	"github.com/0chain/errors"
	"github.com/0chain/gosdk/core/logger"
	"github.com/0chain/gosdk/zcnbridge/config"
	"github.com/0chain/gosdk/zcncore"
)

func SetupZCNWallet() (*Wallet, error) {
	var (
		err     error
		dirname string
	)

	dirname, err = os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	file := filepath.Join(dirname, *config.Client.KeyFileDir, *config.Client.KeyFile)

	f, err := os.Open(file)
	if err != nil {
		return nil, errors.Wrap(err, "error opening the wallet "+file)
	}

	clientBytes, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, errors.Wrap(err, "error reading the wallet")
	}

	clientConfig := string(clientBytes)

	wallet, err := AssignWallet(clientConfig)
	if err != nil {
		return nil, errors.Wrap(err, "failed to assign the wallet")
	}

	err = wallet.RegisterToMiners()
	if err != nil {
		return nil, errors.Wrap(err, "failed to register to miners")
	}

	return wallet, nil
}

// SetupSDK runs zcncore.SetLogFile, zcncore.SetLogLevel and zcncore.InitZCNSDK using provided Config.
// If an error occurs during execution, the program terminates with code 2 and the error will be written in os.Stderr.
// setupZCNSDK should be used only once while application is starting.
func SetupSDK(cfg Config) error {
	var logName = cfg.LogDir() + "/zsdk.log"
	zcncore.SetLogFile(logName, false)
	zcncore.SetLogLevel(logLevelFromStr(cfg.LogLvl()))
	err := zcncore.InitZCNSDK(
		cfg.BlockWorker(),
		cfg.SignatureScheme(),
		zcncore.WithChainID(chain.GetServerChain().ID),
		zcncore.WithEthereumNode(config.Bridge.EthereumNodeURL),
	)

	return err
}

// logLevelFromStr converts string log level to gosdk logger level int value.
func logLevelFromStr(level string) int {
	switch level {
	case "none":
		return logger.NONE
	case "fatal":
		return logger.FATAL
	case "error":
		return logger.ERROR
	case "info":
		return logger.INFO
	case "debug":
		return logger.DEBUG

	default:
		return -1
	}
}
