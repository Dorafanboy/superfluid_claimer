package blockchain

import (
	"context"
	"crypto/ecdsa"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"strings"
	"superfluid_soft/config"

	http_tls "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

const (
	ContractAddress   = "0xA6694cAB43713287F7735dADc940b555db9d39D9"
	FunctionSignature = "0x5add19b4"

	DelegateContractAddress = "0x469788fE6E9E9681C6ebF3bF78e7Fd26Fc015446"
	SetDelegateSignature    = "0x96be3d1d"
	DelegateID              = "0x7375706572666c7569642e657468000000000000000000000000000000000000"

	ClaimSignature = "0x6548b7ae"
)

type ClaimResponse struct {
	CanClaim           bool   `json:"canClaim"`
	AccountAddress     string `json:"accountAddress,omitempty"`
	LockerAddress      string `json:"lockerAddress,omitempty"`
	ProgramPointStates []struct {
		ProgramID         string `json:"programId"`
		OffchainPoints    string `json:"offchainPoints"`
		OnchainPoints     string `json:"onchainPoints"`
		IsOnchainOutdated bool   `json:"isOnchainOutdated"`
	} `json:"programPointStates,omitempty"`
	ClaimTransaction struct {
		Type              string `json:"type"`
		ProgramId         string `json:"programId"`
		TotalProgramUnits string `json:"totalProgramUnits"`
		Nonce             string `json:"nonce"`
		StackSignature    string `json:"stackSignature"`
	} `json:"claimTransaction,omitempty"`
}

type Client struct {
	config config.Config
}

func NewClient(cfg config.Config) *Client {
	return &Client{
		config: cfg,
	}
}

func (c *Client) SendTransaction(privateKeyHex string) error {
	client, err := ethclient.Dial(c.config.RpcURL)
	if err != nil {
		return err
	}

	privateKeyHex = strings.TrimPrefix(privateKeyHex, "0x")

	privateKey, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		return err
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("error casting public key to ECDSA")
	}

	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		return err
	}

	head, err := client.HeaderByNumber(context.Background(), nil)
	if err != nil {
		return err
	}

	baseFee := head.BaseFee

	tipCap, err := client.SuggestGasTipCap(context.Background())
	if err != nil {
		return err
	}

	feeCap := new(big.Int).Add(
		tipCap,
		new(big.Int).Mul(baseFee, big.NewInt(2)),
	)

	toAddress := common.HexToAddress(ContractAddress)
	data := common.FromHex(FunctionSignature)

	gasLimit, err := client.EstimateGas(context.Background(), ethereum.CallMsg{
		From: fromAddress,
		To:   &toAddress,
		Data: data,
	})
	if err != nil {
		gasLimit = uint64(100000)
	}

	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		return err
	}

	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     nonce,
		GasTipCap: tipCap,
		GasFeeCap: feeCap,
		Gas:       gasLimit,
		To:        &toAddress,
		Value:     big.NewInt(0),
		Data:      data,
	})

	signedTx, err := types.SignTx(tx, types.LatestSignerForChainID(chainID), privateKey)
	if err != nil {
		return err
	}

	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		return err
	}

	log.Printf("Transaction sent: https://basescan.org/tx/%s", signedTx.Hash().Hex())
	log.Printf("Gas limit: %d, Tip cap: %s, Fee cap: %s", gasLimit, tipCap.String(), feeCap.String())

	delay := c.config.DelayBetweenModules.GetRandomDelay()
	log.Printf("Waiting for %v before next operation...", delay)
	c.config.DelayBetweenModules.Sleep()

	return nil
}

func (c *Client) SetDelegate(privateKeyHex string) error {
	client, err := ethclient.Dial(c.config.RpcURL)
	if err != nil {
		return err
	}

	privateKeyHex = strings.TrimPrefix(privateKeyHex, "0x")

	privateKey, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		return err
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("error casting public key to ECDSA")
	}

	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		return err
	}

	head, err := client.HeaderByNumber(context.Background(), nil)
	if err != nil {
		return err
	}

	baseFee := head.BaseFee

	tipCap, err := client.SuggestGasTipCap(context.Background())
	if err != nil {
		return err
	}

	feeCap := new(big.Int).Add(
		tipCap,
		new(big.Int).Mul(baseFee, big.NewInt(2)),
	)

	delegateAddress := c.config.GetRandomDelegateAddress()
	if delegateAddress == "" {
		return fmt.Errorf("no delegate addresses configured")
	}

	data := make([]byte, 0)
	data = append(data, common.FromHex(SetDelegateSignature)...)
	data = append(data, common.FromHex(DelegateID)...)

	delegateBytes := common.HexToAddress(delegateAddress).Bytes()
	paddedAddress := make([]byte, 32)
	copy(paddedAddress[32-len(delegateBytes):], delegateBytes)
	data = append(data, paddedAddress...)

	toAddress := common.HexToAddress(DelegateContractAddress)

	gasLimit, err := client.EstimateGas(context.Background(), ethereum.CallMsg{
		From: fromAddress,
		To:   &toAddress,
		Data: data,
	})
	if err != nil {
		gasLimit = uint64(100000)
	}

	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		return err
	}

	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     nonce,
		GasTipCap: tipCap,
		GasFeeCap: feeCap,
		Gas:       gasLimit,
		To:        &toAddress,
		Value:     big.NewInt(0),
		Data:      data,
	})

	signedTx, err := types.SignTx(tx, types.LatestSignerForChainID(chainID), privateKey)
	if err != nil {
		return err
	}

	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		return err
	}

	log.Printf("SetDelegate transaction sent: https://basescan.org/tx/%s", signedTx.Hash().Hex())
	log.Printf("Delegate address: %s", delegateAddress)
	log.Printf("Gas limit: %d, Tip cap: %s, Fee cap: %s", gasLimit, tipCap.String(), feeCap.String())

	delay := c.config.DelayBetweenModules.GetRandomDelay()
	log.Println("\n=== Module Delay ===")
	log.Printf("⏳ Waiting for %v before next operation...", delay)
	c.config.DelayBetweenModules.Sleep()
	log.Println("=== End Module Delay ===\n")

	return nil
}

func (c *Client) SendClaimTransaction(privateKeyHex string, claimResponse *ClaimResponse) error {
	privateKeyHex = strings.TrimPrefix(privateKeyHex, "0x")
	privateKey, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		return err
	}
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("error casting public key to ECDSA")
	}
	address := crypto.PubkeyToAddress(*publicKeyECDSA).Hex()

	jar := tls_client.NewCookieJar()
	options := []tls_client.HttpClientOption{
		tls_client.WithTimeoutSeconds(30),
		tls_client.WithClientProfile(profiles.Chrome_120),
		tls_client.WithNotFollowRedirects(),
		tls_client.WithCookieJar(jar),
	}

	client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), options...)
	if err != nil {
		return fmt.Errorf("error creating tls client: %v", err)
	}

	requestData := strings.NewReader(fmt.Sprintf(`["%s"]`, address))

	tlsRequest, err := http_tls.NewRequest(http_tls.MethodPost, "https://claim.superfluid.org/claim", requestData)
	if err != nil {
		return err
	}

	tlsRequest.Header.Set("accept", "text/x-component")
	tlsRequest.Header.Set("accept-language", "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7")
	tlsRequest.Header.Set("baggage", "sentry-environment=vercel-production,sentry-release=9532e46cd892a8d7f6038960d00ea337cfb04dfb,sentry-public_key=9fd35ff6b93f02bf12db94dc3334a22d,sentry-trace_id=0eb18dff3bf87962ba2cbf1e92611827")
	tlsRequest.Header.Set("cache-control", "no-cache")
	tlsRequest.Header.Set("content-type", "text/plain;charset=UTF-8")
	tlsRequest.Header.Set("next-action", "4082a9b315b936c8b18ae2bbfd0ec6d2511d48f898")
	tlsRequest.Header.Set("next-router-state-tree", "%5B%22%22%2C%7B%22children%22%3A%5B%22claim%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%2C%22%2Fclaim%22%2C%22refresh%22%5D%7D%5D%7D%2Cnull%2Cnull%2Ctrue%5D")
	tlsRequest.Header.Set("origin", "https://claim.superfluid.org")
	tlsRequest.Header.Set("pragma", "no-cache")
	tlsRequest.Header.Set("priority", "u=1, i")
	tlsRequest.Header.Set("referer", "https://claim.superfluid.org/claim")
	tlsRequest.Header.Set("sec-ch-ua", `"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"`)
	tlsRequest.Header.Set("sec-ch-ua-mobile", "?0")
	tlsRequest.Header.Set("sec-ch-ua-platform", `"Windows"`)
	tlsRequest.Header.Set("sec-fetch-dest", "empty")
	tlsRequest.Header.Set("sec-fetch-mode", "cors")
	tlsRequest.Header.Set("sec-fetch-site", "same-origin")
	tlsRequest.Header.Set("sentry-trace", "0eb18dff3bf87962ba2cbf1e92611827-82b7aef938e6b698")
	tlsRequest.Header.Set("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36")
	tlsRequest.Header.Set("cookie", `__Host-next-auth.csrf-token=9c6246b1a922b998b2928a3138c95bb773c631c8e123e4600d7c07a51e11658a%7C5d0373762d817ded802b0b1a3e3543fa06958a1d9cb0c871fe08356b4bb040fc; __Secure-next-auth.callback-url=https%3A%2F%2Fclaim.superfluid.org; _hjSessionUser_5278509=eyJpZCI6IjI1OTRhZGY1LTRmZTgtNWRiMy04ODhjLTA0Y2NhMTcwODNjZCIsImNyZWF0ZWQiOjE3Mzk5ODg2NjA0MzMsImV4aXN0aW5nIjp0cnVlfQ==; _pk_id.11.31f7=4f30c7b1800aaa96.1739988661.; wagmi.recentConnectorId="io.metamask"; ajs_anonymous_id=730f28bf-d230-4e4c-b1ec-44bd886eab07; ajs_user_id=0xdc3467dfb4cf1BE8c8901260deE0572509D52AB9; _pk_ses.11.31f7=1; _hjSession_5278509=eyJpZCI6ImFkZGQ0MmVmLTZlZGMtNDFiNi1iNjVkLWM2NmVmZjYyYjEwNCIsImMiOjE3NDA1MDY2MjEwNTMsInMiOjEsInIiOjEsInNiIjowLCJzciI6MCwic2UiOjAsImZzIjowLCJzcCI6MH0=; wagmi.store={"state":{"connections":{"__type":"Map","value":[["9c2d27cc3a8",{"accounts":["0xdc3467dfb4cf1BE8c8901260deE0572509D52AB9"],"chainId":8453,"connector":{"id":"io.metamask","name":"MetaMask","type":"injected","uid":"9c2d27cc3a8"}}]]},"chainId":8453,"current":"9c2d27cc3a8"},"version":2}`)

	resp, err := client.Do(tlsRequest)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	bodyText, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	responseLines := strings.Split(string(bodyText), "\n")
	var freshResponse *ClaimResponse
	var jsonLine string

	for _, line := range responseLines {
		if strings.Contains(line, `"canClaim"`) || strings.Contains(line, `"accountAddress"`) {
			jsonLine = line
			break
		}
	}

	if jsonLine != "" {
		if idx := strings.Index(jsonLine, "{"); idx != -1 {
			jsonLine = jsonLine[idx:]

			if endIdx := strings.LastIndex(jsonLine, "}"); endIdx != -1 {
				jsonLine = jsonLine[:endIdx+1]
			}

			var response ClaimResponse
			if err := json.Unmarshal([]byte(jsonLine), &response); err != nil {
				return fmt.Errorf("error parsing response: %v, response: %s", err, jsonLine)
			}

			freshResponse = &response
		}
	}

	if freshResponse == nil {
		return fmt.Errorf("failed to get fresh claim data")
	}

	if !freshResponse.CanClaim {
		return fmt.Errorf("address is not eligible to claim")
	}

	txRequestData := strings.NewReader(fmt.Sprintf(`["%s"]`, address))
	txTlsRequest, err := http_tls.NewRequest(http_tls.MethodPost, "https://claim.superfluid.org/api/claimTransaction", txRequestData)
	if err != nil {
		return err
	}

	txTlsRequest.Header.Set("accept", "text/x-component")
	txTlsRequest.Header.Set("accept-language", "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7")
	txTlsRequest.Header.Set("baggage", "sentry-environment=vercel-production,sentry-release=9532e46cd892a8d7f6038960d00ea337cfb04dfb,sentry-public_key=9fd35ff6b93f02bf12db94dc3334a22d,sentry-trace_id=305a42d755ea847a849dcbc29efdc29f")
	txTlsRequest.Header.Set("cache-control", "no-cache")
	txTlsRequest.Header.Set("content-type", "text/plain;charset=UTF-8")
	txTlsRequest.Header.Set("next-action", "40489d89d2fd362e6eff4664fcb7a9e540e85b761f")
	txTlsRequest.Header.Set("next-router-state-tree", "%5B%22%22%2C%7B%22children%22%3A%5B%22claim%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%2C%22%2Fclaim%22%2C%22refresh%22%5D%7D%5D%7D%2Cnull%2Cnull%2Ctrue%5D")
	txTlsRequest.Header.Set("origin", "https://claim.superfluid.org")
	txTlsRequest.Header.Set("pragma", "no-cache")
	txTlsRequest.Header.Set("priority", "u=1, i")
	txTlsRequest.Header.Set("referer", "https://claim.superfluid.org/claim")
	txTlsRequest.Header.Set("sec-ch-ua", `"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"`)
	txTlsRequest.Header.Set("sec-ch-ua-mobile", "?0")
	txTlsRequest.Header.Set("sec-ch-ua-platform", `"Windows"`)
	txTlsRequest.Header.Set("sec-fetch-dest", "empty")
	txTlsRequest.Header.Set("sec-fetch-mode", "cors")
	txTlsRequest.Header.Set("sec-fetch-site", "same-origin")
	txTlsRequest.Header.Set("sentry-trace", "305a42d755ea847a849dcbc29efdc29f-87ef94b564a499a2")
	txTlsRequest.Header.Set("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36")
	txTlsRequest.Header.Set("cookie", `__Host-next-auth.csrf-token=9c6246b1a922b998b2928a3138c95bb773c631c8e123e4600d7c07a51e11658a%7C5d0373762d817ded802b0b1a3e3543fa06958a1d9cb0c871fe08356b4bb040fc; __Secure-next-auth.callback-url=https%3A%2F%2Fclaim.superfluid.org; _hjSessionUser_5278509=eyJpZCI6IjI1OTRhZGY1LTRmZTgtNWRiMy04ODhjLTA0Y2NhMTcwODNjZCIsImNyZWF0ZWQiOjE3Mzk5ODg2NjA0MzMsImV4aXN0aW5nIjp0cnVlfQ==; _pk_id.11.31f7=4f30c7b1800aaa96.1739988661.; wagmi.recentConnectorId="io.metamask"; ajs_anonymous_id=730f28bf-d230-4e4c-b1ec-44bd886eab07; ajs_user_id=0xdc3467dfb4cf1BE8c8901260deE0572509D52AB9; wagmi.store={"state":{"connections":{"__type":"Map","value":[["a03275c78ca",{"accounts":["0xdc3467dfb4cf1BE8c8901260deE0572509D52AB9"],"chainId":8453,"connector":{"id":"io.metamask","name":"MetaMask","type":"injected","uid":"a03275c78ca"}}]]},"chainId":8453,"current":"a03275c78ca"},"version":2}`)

	txResp, err := client.Do(txTlsRequest)
	if err != nil {
		return err
	}
	defer txResp.Body.Close()

	claimTxBody, err := io.ReadAll(txResp.Body)
	if err != nil {
		return err
	}

	claimTxResponseLines := strings.Split(string(claimTxBody), "\n")
	var claimTxJsonLine string

	for _, line := range claimTxResponseLines {
		if strings.Contains(line, `"claimTransaction"`) {
			claimTxJsonLine = line
			break
		}
	}

	if claimTxJsonLine == "" {
		return fmt.Errorf("could not find claim transaction data in response")
	}

	if idx := strings.Index(claimTxJsonLine, "{"); idx != -1 {
		claimTxJsonLine = claimTxJsonLine[idx:]

		if endIdx := strings.LastIndex(claimTxJsonLine, "}"); endIdx != -1 {
			claimTxJsonLine = claimTxJsonLine[:endIdx+1]
		}
	}

	var claimTxResponse struct {
		CanClaim         bool `json:"canClaim"`
		ClaimTransaction struct {
			Type           string `json:"type"`
			ProgramId      string `json:"programId"`
			ProgramUnits   string `json:"totalProgramUnits"`
			Nonce          string `json:"nonce"`
			StackSignature string `json:"stackSignature"`
		} `json:"claimTransaction"`
	}

	if err := json.Unmarshal([]byte(claimTxJsonLine), &claimTxResponse); err != nil {
		return fmt.Errorf("error parsing claim transaction data: %v", err)
	}

	claimTxData := claimTxResponse.ClaimTransaction
	log.Printf("Claim transaction data: %+v", claimTxData)

	// Now connect to Ethereum
	ethClient, err := ethclient.Dial(c.config.RpcURL)
	if err != nil {
		return err
	}

	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
	nonce, err := ethClient.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		return err
	}

	head, err := ethClient.HeaderByNumber(context.Background(), nil)
	if err != nil {
		return err
	}

	baseFee := head.BaseFee

	tipCap, err := ethClient.SuggestGasTipCap(context.Background())
	if err != nil {
		return err
	}

	feeCap := new(big.Int).Add(
		tipCap,
		new(big.Int).Mul(baseFee, big.NewInt(2)),
	)

	// Use locker address from API response
	var toAddress common.Address
	if freshResponse.LockerAddress != "" {
		toAddress = common.HexToAddress(freshResponse.LockerAddress)
		log.Printf("Using locker address from API response: %s", freshResponse.LockerAddress)
	} else {
		return fmt.Errorf("no locker address found in API response")
	}

	// Create function call data
	functionSelector := common.FromHex(ClaimSignature)
	txData := make([]byte, 0)
	txData = append(txData, functionSelector...)

	// Add param1 - programId (remove $n prefix if present)
	programId := strings.TrimPrefix(claimTxData.ProgramId, "$n")
	param1Int := new(big.Int)
	param1Int.SetString(programId, 10)
	param1Bytes := make([]byte, 32)
	param1Int.FillBytes(param1Bytes)
	txData = append(txData, param1Bytes...)

	// Add param2 - totalProgramUnits
	totalUnits := strings.TrimPrefix(claimTxData.ProgramUnits, "$n")
	param2Int := new(big.Int)
	param2Int.SetString(totalUnits, 10)
	param2Bytes := make([]byte, 32)
	param2Int.FillBytes(param2Bytes)
	txData = append(txData, param2Bytes...)

	nonceStr := strings.TrimPrefix(claimTxData.Nonce, "$n")
	param3Int := new(big.Int)
	param3Int.SetString(nonceStr, 10)
	param3Bytes := make([]byte, 32)
	param3Int.FillBytes(param3Bytes)
	txData = append(txData, param3Bytes...)

	offsetBytes := make([]byte, 32)
	offsetBytes[31] = 0x80
	txData = append(txData, offsetBytes...)

	signature := claimTxData.StackSignature
	signatureData := common.FromHex(signature)

	log.Printf("Using transaction data: programId=%s, units=%s, nonce=%s", programId, totalUnits, nonceStr)
	log.Printf("Signature: %s", signature)

	lengthBytes := make([]byte, 32)
	binary.BigEndian.PutUint64(lengthBytes[24:32], uint64(len(signatureData)))
	txData = append(txData, lengthBytes...)

	txData = append(txData, signatureData...)
	if padding := 32 - (len(signatureData) % 32); padding < 32 {
		txData = append(txData, make([]byte, padding)...)
	}

	log.Printf("Transaction data: 0x%x", txData)

	gasLimit, err := ethClient.EstimateGas(context.Background(), ethereum.CallMsg{
		From: fromAddress,
		To:   &toAddress,
		Data: txData,
	})
	if err != nil {
		log.Printf("Error estimating gas: %v, using default 100000", err)
		gasLimit = uint64(100000)
	}

	chainID, err := ethClient.NetworkID(context.Background())
	if err != nil {
		return err
	}

	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     nonce,
		GasTipCap: tipCap,
		GasFeeCap: feeCap,
		Gas:       gasLimit,
		To:        &toAddress,
		Value:     big.NewInt(0),
		Data:      txData,
	})

	signedTx, err := types.SignTx(tx, types.LatestSignerForChainID(chainID), privateKey)
	if err != nil {
		return err
	}

	err = ethClient.SendTransaction(context.Background(), signedTx)
	if err != nil {
		return err
	}

	log.Printf("Claim transaction sent: https://basescan.org/tx/%s", signedTx.Hash().Hex())
	log.Printf("Program ID: %s, Points: %s", programId, totalUnits)
	log.Printf("Gas limit: %d, Tip cap: %s, Fee cap: %s", gasLimit, tipCap.String(), feeCap.String())

	delay := c.config.DelayBetweenModules.GetRandomDelay()
	log.Println("\n=== Module Delay ===")
	log.Printf("⏳ Waiting for %v before next operation...", delay)
	c.config.DelayBetweenModules.Sleep()
	log.Println("=== End Module Delay ===\n")

	return nil
}

func (c *Client) CheckEligibility(address string) (*ClaimResponse, error) {
	jar := tls_client.NewCookieJar()

	options := []tls_client.HttpClientOption{
		tls_client.WithTimeoutSeconds(30),
		tls_client.WithClientProfile(profiles.Chrome_120),
		tls_client.WithNotFollowRedirects(),
		tls_client.WithCookieJar(jar),
	}

	client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), options...)
	if err != nil {
		return nil, fmt.Errorf("error creating tls client: %v", err)
	}

	data := strings.NewReader(fmt.Sprintf(`["%s"]`, address))

	tlsRequest, err := http_tls.NewRequest(http_tls.MethodPost, "https://claim.superfluid.org/claim", data)
	if err != nil {
		return nil, err
	}

	tlsRequest.Header.Set("accept", "text/x-component")
	tlsRequest.Header.Set("accept-language", "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7")
	tlsRequest.Header.Set("baggage", "sentry-environment=vercel-production,sentry-release=9efbcccf61c3f6bcd67bf406cea533b37062bbb2,sentry-public_key=9fd35ff6b93f02bf12db94dc3334a22d,sentry-trace_id=862c5bedb06031130ce18a75f61b1e95")
	tlsRequest.Header.Set("cache-control", "no-cache")
	tlsRequest.Header.Set("content-type", "text/plain;charset=UTF-8")
	tlsRequest.Header.Set("next-action", "40489d89d2fd362e6eff4664fcb7a9e540e85b761f")
	tlsRequest.Header.Set("next-router-state-tree", "%5B%22%22%2C%7B%22children%22%3A%5B%22claim%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%2C%22%2Fclaim%22%2C%22refresh%22%5D%7D%5D%7D%2Cnull%2Cnull%2Ctrue%5D")
	tlsRequest.Header.Set("origin", "https://claim.superfluid.org")
	tlsRequest.Header.Set("pragma", "no-cache")
	tlsRequest.Header.Set("priority", "u=1, i")
	tlsRequest.Header.Set("referer", "https://claim.superfluid.org/claim")
	tlsRequest.Header.Set("sec-ch-ua", `"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"`)
	tlsRequest.Header.Set("sec-ch-ua-mobile", "?0")
	tlsRequest.Header.Set("sec-ch-ua-platform", `"Windows"`)
	tlsRequest.Header.Set("sec-fetch-dest", "empty")
	tlsRequest.Header.Set("sec-fetch-mode", "cors")
	tlsRequest.Header.Set("sec-fetch-site", "same-origin")
	tlsRequest.Header.Set("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36")
	tlsRequest.Header.Set("cookie", `__Host-next-auth.csrf-token=9c6246b1a922b998b2928a3138c95bb773c631c8e123e4600d7c07a51e11658a%7C5d0373762d817ded802b0b1a3e3543fa06958a1d9cb0c871fe08356b4bb040fc; __Secure-next-auth.callback-url=https%3A%2F%2Fclaim.superfluid.org; _hjSessionUser_5278509=eyJpZCI6IjI1OTRhZGY1LTRmZTgtNWRiMy04ODhjLTA0Y2NhMTcwODNjZCIsImNyZWF0ZWQiOjE3Mzk5ODg2NjA0MzMsImV4aXN0aW5nIjp0cnVlfQ==; _pk_id.11.31f7=4f30c7b1800aaa96.1739988661.; wagmi.recentConnectorId="io.metamask"; _pk_ses.11.31f7=1; _hjSession_5278509=eyJpZCI6ImExMTQ1MWM1LTM0MjctNGFhMi05MmFjLThjMWZiMGY2Njg3NyIsImMiOjE3NDAzODIzNDgxNjQsInMiOjEsInIiOjEsInNiIjowLCJzciI6MCwic2UiOjAsImZzIjowLCJzcCI6MH0=; ajs_anonymous_id=730f28bf-d230-4e4c-b1ec-44bd886eab07; ajs_user_id=0xdc3467dfb4cf1BE8c8901260deE0572509D52AB9; wagmi.store={"state":{"connections":{"__type":"Map","value":[["493edd58961",{"accounts":["0xdc3467dfb4cf1BE8c8901260deE0572509D52AB9"],"chainId":8453,"connector":{"id":"io.metamask","name":"MetaMask","type":"injected","uid":"493edd58961"}}]]},"chainId":8453,"current":"493edd58961"},"version":2}`)

	resp, err := client.Do(tlsRequest)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyText, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	responseLines := strings.Split(string(bodyText), "\n")

	if len(responseLines) > 1 {
		var jsonLine string
		for _, line := range responseLines {
			if strings.Contains(line, `"canClaim"`) || strings.Contains(line, `"claimTransaction"`) {
				jsonLine = line
				break
			}
		}

		if jsonLine != "" {
			if idx := strings.Index(jsonLine, "{"); idx != -1 {
				jsonLine = jsonLine[idx:]

				if endIdx := strings.LastIndex(jsonLine, "}"); endIdx != -1 {
					jsonLine = jsonLine[:endIdx+1]
				}

				var claimResponse ClaimResponse
				if err := json.Unmarshal([]byte(jsonLine), &claimResponse); err != nil {
					return nil, fmt.Errorf("error parsing response: %v, response: %s", err, jsonLine)
				}

				delay := c.config.DelayBetweenModules.GetRandomDelay()
				log.Println("\n=== Module Delay ===")
				log.Printf("⏳ Waiting for %v before next operation...", delay)
				c.config.DelayBetweenModules.Sleep()
				log.Println("=== End Module Delay ===\n")

				return &claimResponse, nil
			}
		}
	}

	return nil, fmt.Errorf("invalid response format: %s", string(bodyText))
}
