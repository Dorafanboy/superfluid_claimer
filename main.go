package main

import (
	"bufio"
	"crypto/ecdsa"
	"fmt"
	"log"
	"math/rand"
	"os"
	"strings"
	"time"

	"superfluid_soft/blockchain"
	"superfluid_soft/config"

	"github.com/ethereum/go-ethereum/crypto"
)

const (
	maxRetries = 3 // Maximum number of retry attempts
)

func main() {
	rand.Seed(time.Now().UnixNano())

	client := blockchain.NewClient(config.DefaultConfig)

	file, err := os.Open("private_keys.txt")
	if err != nil {
		log.Fatal("Error opening private_keys.txt:", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		privateKey := strings.TrimSpace(scanner.Text())
		if privateKey == "" || strings.HasPrefix(privateKey, "#") {
			continue
		}

		key, err := crypto.HexToECDSA(strings.TrimPrefix(privateKey, "0x"))
		if err != nil {
			log.Printf("Error parsing private key: %v", err)
			continue
		}

		publicKey := key.Public()
		publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			log.Printf("Error casting public key to ECDSA")
			continue
		}

		address := crypto.PubkeyToAddress(*publicKeyECDSA).Hex()

		log.Println("\n=== Starting Eligibility Check Module ===")
		var claimResponse *blockchain.ClaimResponse
		var eligibilitySuccess bool

		// Try to check eligibility with retries
		for attempt := 1; attempt <= maxRetries; attempt++ {
			log.Printf("Eligibility check attempt %d/%d for address %s", attempt, maxRetries, address)
			claimResponse, err = client.CheckEligibility(address)
			if err == nil {
				eligibilitySuccess = true
				break
			}
			log.Printf("❌ Attempt %d: Error checking eligibility for address %s: %v", attempt, address, err)

			if attempt < maxRetries {
				retryDelay := time.Duration(2*attempt) * time.Second
				log.Printf("Retrying in %v...", retryDelay)
				time.Sleep(retryDelay)
			}
		}

		if !eligibilitySuccess {
			log.Printf("❌ All attempts failed for eligibility check. Moving to next account.")
			waitAndMoveToNextAccount()
			continue
		}

		fmt.Println(claimResponse)

		if !claimResponse.CanClaim {
			log.Printf("❌ Address %s is not eligible", address)
			waitAndMoveToNextAccount()
			continue
		}

		log.Printf("✅ Address %s is eligible", address)

		// Try to send transaction with retries
		log.Println("\n=== Starting Claim Transaction Module ===")
		var transactionSuccess bool
		for attempt := 1; attempt <= maxRetries; attempt++ {
			log.Printf("Send transaction attempt %d/%d for address %s", attempt, maxRetries, address)
			err = client.SendTransaction(privateKey)
			if err == nil {
				transactionSuccess = true
				break
			}
			log.Printf("❌ Attempt %d: Error sending transaction for address %s: %v", attempt, address, err)

			if attempt < maxRetries {
				retryDelay := time.Duration(2*attempt) * time.Second
				log.Printf("Retrying in %v...", retryDelay)
				time.Sleep(retryDelay)
			}
		}

		if !transactionSuccess {
			log.Printf("❌ All attempts failed for transaction. Moving to next account.")
			waitAndMoveToNextAccount()
			continue
		}

		// Try to set delegate with retries
		log.Println("\n=== Starting Delegate Setting Module ===")
		var delegateSuccess bool
		for attempt := 1; attempt <= maxRetries; attempt++ {
			log.Printf("Set delegate attempt %d/%d for address %s", attempt, maxRetries, address)
			err = client.SetDelegate(privateKey)
			if err == nil {
				delegateSuccess = true
				break
			}
			log.Printf("❌ Attempt %d: Error setting delegate for address %s: %v", attempt, address, err)

			if attempt < maxRetries {
				retryDelay := time.Duration(2*attempt) * time.Second
				log.Printf("Retrying in %v...", retryDelay)
				time.Sleep(retryDelay)
			}
		}

		if !delegateSuccess {
			log.Printf("❌ All attempts failed for delegate setting. Moving to next account.")
			waitAndMoveToNextAccount()
			continue
		}

		// Try to send claim transaction with retries
		log.Println("\n=== Starting Claim Transaction Reward Module ===")
		var claimSuccess bool
		for attempt := 1; attempt <= maxRetries; attempt++ {
			log.Printf("Send claim transaction attempt %d/%d for address %s", attempt, maxRetries, address)
			err = client.SendClaimTransaction(privateKey, claimResponse)
			if err == nil {
				claimSuccess = true
				break
			}
			log.Printf("❌ Attempt %d: Error sending claim transaction for address %s: %v", attempt, address, err)

			if attempt < maxRetries {
				retryDelay := time.Duration(2*attempt) * time.Second
				log.Printf("Retrying in %v...", retryDelay)
				time.Sleep(retryDelay)
			}
		}

		if !claimSuccess {
			log.Printf("❌ All attempts failed for claim transaction. Moving to next account.")
			waitAndMoveToNextAccount()
			continue
		}

		log.Printf("✅ Successfully claimed for address %s", address)
		log.Printf("✅ Successfully completed all operations for address %s", address)

		waitAndMoveToNextAccount()
	}

	if err := scanner.Err(); err != nil {
		log.Fatal("Error reading private_keys.txt:", err)
	}
}

// Helper function to wait between accounts
func waitAndMoveToNextAccount() {
	log.Println("\n=== Starting Delay Between Accounts ===")
	delay := config.DefaultConfig.DelayBetweenAccounts.GetRandomDelay()
	log.Printf("Waiting for %v before processing next account...", delay)
	config.DefaultConfig.DelayBetweenAccounts.Sleep()
	log.Println("=== End of Account Processing ===\n")
}
