package lnwire

import (
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"io"
)

type FundingRequest struct {
	ChannelType uint8

	FundingAmount btcutil.Amount
	ReserveAmount btcutil.Amount
	MinFeePerKb   btcutil.Amount

	//Should double-check the total funding later
	MinTotalFundingAmount btcutil.Amount

	//CLTV/CSV lock-time to use
	LockTime uint32

	//Who pays the fees
	//0: (default) channel initiator
	//1: split
	//2: channel responder
	FeePayer uint8

	RevocationHash   [20]byte
	Pubkey           *btcec.PublicKey
	DeliveryPkScript PkScript //*MUST* be either P2PKH or P2SH
	ChangePkScript   PkScript //*MUST* be either P2PKH or P2SH

	Inputs []*wire.TxIn
}

func (c *FundingRequest) Decode(r io.Reader, pver uint32) error {
	//Channel Type (0/1)
	//Funding Amount (1/8)
	//Channel Minimum Capacity (9/8)
	//Revocation Hash (17/20)
	//Commitment Pubkey (37/32)
	//Reserve Amount (69/8)
	//Minimum Transaction Fee Per Kb (77/8)
	//LockTime (85/4)
	//FeePayer (89/1)
	//DeliveryPkScript (final delivery)
	//	First byte length then pkscript
	//ChangePkScript (change for extra from inputs)
	//	First byte length then pkscript
	//Inputs: Create the TxIns
	//	First byte is number of inputs
	//	For each input, it's 32bytes txin & 4bytes index
	err := readElements(r, false,
		&c.ChannelType,
		&c.FundingAmount,
		&c.MinTotalFundingAmount,
		&c.RevocationHash,
		&c.Pubkey,
		&c.ReserveAmount,
		&c.MinFeePerKb,
		&c.LockTime,
		&c.FeePayer,
		&c.DeliveryPkScript,
		&c.ChangePkScript,
		&c.Inputs)
	if err != nil {
		return err
	}

	return nil
}

//Creates a new FundingRequest
func NewFundingRequest() *FundingRequest {
	return &FundingRequest{}
}

//Serializes the item from the FundingRequest struct
//Writes the data to w
func (c *FundingRequest) Encode(w io.Writer, pver uint32) error {
	//Channel Type
	//Funding Amont
	//Channel Minimum Capacity
	//Revocation Hash
	//Commitment Pubkey
	//Reserve Amount
	//Minimum Transaction Fee Per KB
	//LockTime
	//FeePayer
	//DeliveryPkScript
	//ChangePkScript
	//Inputs: Append the actual Txins
	err := writeElements(w, false,
		c.ChannelType,
		c.FundingAmount,
		c.MinTotalFundingAmount,
		c.RevocationHash,
		c.Pubkey,
		c.ReserveAmount,
		c.MinFeePerKb,
		c.LockTime,
		c.FeePayer,
		c.DeliveryPkScript,
		c.ChangePkScript,
		c.Inputs)
	if err != nil {
		return err
	}

	return nil
}

func (c *FundingRequest) Command() uint32 {
	return CmdFundingRequest
}

func (c *FundingRequest) MaxPayloadLength(uint32) uint32 {
	//90 (base size) + 26 (pkscript) + 26 (pkscript) + 1 (numTxes) + 127*36(127 inputs * sha256+idx)
	return 4715
}

//Makes sure the struct data is valid (e.g. no negatives or invalid pkscripts)
func (c *FundingRequest) Validate() error {
	var err error

	//No negative values
	if c.FundingAmount < 0 {
		return fmt.Errorf("FundingAmount cannot be negative")
	}

	if c.ReserveAmount < 0 {
		return fmt.Errorf("ReserveAmount cannot be negative")
	}

	if c.MinFeePerKb < 0 {
		return fmt.Errorf("MinFeePerKb cannot be negative")
	}
	if c.MinTotalFundingAmount < 0 {
		return fmt.Errorf("MinTotalFundingAmount cannot be negative")
	}

	//DeliveryPkScript is either P2SH or P2PKH
	err = ValidatePkScript(c.DeliveryPkScript)
	if err != nil {
		return err
	}

	//ChangePkScript is either P2SH or P2PKH
	err = ValidatePkScript(c.ChangePkScript)
	if err != nil {
		return err
	}

	//We're good!
	return nil
}

func (c *FundingRequest) String() string {
	var inputs string
	for i, in := range c.Inputs {
		inputs += fmt.Sprintf("\n     Slice\t%d\n", i)
		inputs += fmt.Sprintf("\tHash\t%s\n", in.PreviousOutPoint.Hash)
		inputs += fmt.Sprintf("\tIndex\t%d\n", in.PreviousOutPoint.Index)
	}
	return fmt.Sprintf("\n--- Begin FundingRequest ---\n") +
		fmt.Sprintf("ChannelType:\t\t%x\n", c.ChannelType) +
		fmt.Sprintf("FundingAmount:\t\t%s\n", c.FundingAmount.String()) +
		fmt.Sprintf("ReserveAmount:\t\t%s\n", c.ReserveAmount.String()) +
		fmt.Sprintf("MinFeePerKb:\t\t%s\n", c.MinFeePerKb.String()) +
		fmt.Sprintf("MinTotalFundingAmount\t%s\n", c.MinTotalFundingAmount.String()) +
		fmt.Sprintf("LockTime\t\t%d\n", c.LockTime) +
		fmt.Sprintf("FeePayer\t\t%x\n", c.FeePayer) +
		fmt.Sprintf("RevocationHash\t\t%x\n", c.RevocationHash) +
		fmt.Sprintf("Pubkey\t\t\t%x\n", c.Pubkey.SerializeCompressed()) +
		fmt.Sprintf("DeliveryPkScript\t%x\n", c.DeliveryPkScript) +
		fmt.Sprintf("Inputs:") +
		inputs +
		fmt.Sprintf("--- End FundingRequest ---\n")
}
