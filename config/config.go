package config

import (
	"math/rand"
	"time"
)

type Config struct {
	// RPC URL for the blockchain
	RpcURL string

	DelayBetweenAccounts DelayRange
	DelayBetweenModules  DelayRange

	DelegateAddresses []string
}

type DelayRange struct {
	Min time.Duration
	Max time.Duration
}

// Default configuration
var DefaultConfig = Config{
	RpcURL: "https://rpc.ankr.com/base", // base rpc
	DelayBetweenAccounts: DelayRange{ // задержка между аккаунтами(менять цифру слева от звездочки)
		Min: 1 * time.Minute,
		Max: 3 * time.Minute,
	},
	DelayBetweenModules: DelayRange{ // задержка между модулями(менять цифру слева от звездочки)
		Min: 5 * time.Second,
		Max: 15 * time.Second,
	},
	DelegateAddresses: []string{ // адреса кому делегировать, можно добавить ниже например "0xадрес", и тд.
		"0x09A900eB2ff6e9AcA12d4d1a396DdC9bE0307661",
		"0x66582D24FEaD72555adaC681Cc621caCbB208324",
	},
}

func (r DelayRange) GetRandomDelay() time.Duration {
	delta := r.Max - r.Min
	if delta <= 0 {
		return r.Min
	}

	randomDuration := time.Duration(rand.Int63n(int64(delta)))
	return r.Min + randomDuration
}

func (r DelayRange) Sleep() {
	time.Sleep(r.GetRandomDelay())
}

func (c Config) GetRandomDelegateAddress() string {
	if len(c.DelegateAddresses) == 0 {
		return ""
	}
	return c.DelegateAddresses[rand.Intn(len(c.DelegateAddresses))]
}
