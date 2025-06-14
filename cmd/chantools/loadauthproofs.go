package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/lightninglabs/chantools/lnd"
	"github.com/lightningnetwork/lnd/graph/db/models"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/spf13/cobra"
)

type loadAuthProofsCommand struct {
	ChannelDB string
	Source    string

	Overwrite bool

	cmd *cobra.Command
}

type ChannelAuthProofData struct {
	NodeSig1Bytes    string `json:"node_sig_1"`
	NodeSig2Bytes    string `json:"node_sig_2"`
	BitcoinSig1Bytes string `json:"bitcoin_sig_1"`
	BitcoinSig2Bytes string `json:"bitcoin_sig_2"`
}

func newLoadAuthProofsCommand() *cobra.Command {
	cc := &loadAuthProofsCommand{}
	cc.cmd = &cobra.Command{
		Use:   "loadauthproofs",
		Short: "Load auth proofs from an external file into the graph DB",
		Long:  ``,
		RunE:  cc.Execute,
	}
	cc.cmd.Flags().StringVar(
		&cc.ChannelDB, "channeldb", "", "lnd channel.db file to load "+
			"the auth proofs into",
	)
	cc.cmd.Flags().StringVar(
		&cc.Source, "source", "", "JSON file which contains "+
			"the auth proofs",
	)
	cc.cmd.Flags().BoolVar(
		&cc.Overwrite, "overwrite", false, "overwrite the auth proofs",
	)

	return cc.cmd
}

func (c *loadAuthProofsCommand) Execute(_ *cobra.Command, _ []string) error {
	// Check that we have a channel DB.
	if c.ChannelDB == "" {
		return errors.New("channel DB is required")
	}
	channelDB, graphDB, err := lnd.OpenDB(c.ChannelDB, false)
	if err != nil {
		return fmt.Errorf("error opening channel DB: %w", err)
	}
	defer func() { _ = channelDB.Close() }()

	if c.Source == "" {
		return errors.New("source file is required")
	}

	f, err := os.Open(c.Source)
	if err != nil {
		return fmt.Errorf("error opening source file %s: %w", c.Source, err)
	}
	defer f.Close()

	var rawChannelAuthProofsData map[string]ChannelAuthProofData
	decoder := json.NewDecoder(f)
	if err := decoder.Decode(&rawChannelAuthProofsData); err != nil {
		return fmt.Errorf("error decoding source file %s: %w", c.Source, err)
	}

	channelAuthProofsToInsert := make(map[uint64]models.ChannelAuthProof)

	log.Info("Scanning current graph for missing auth proofs...")
	err = graphDB.KVStore.ForEachChannel(func(info *models.ChannelEdgeInfo,
		policy1, policy2 *models.ChannelEdgePolicy) error {

		proofData, ok := rawChannelAuthProofsData[fmt.Sprintf("%d", info.ChannelID)]
		if !ok {
			return nil
		}

		nodeSig1, err := hex.DecodeString(proofData.NodeSig1Bytes)
		if err != nil {
			return fmt.Errorf("Error decoding node_sig_1 for channel %d: %v", info.ChannelID, err)
		}
		nodeSig2, err := hex.DecodeString(proofData.NodeSig2Bytes)
		if err != nil {
			return fmt.Errorf("Error decoding node_sig_2 for channel %d: %v", info.ChannelID, err)
		}
		bitcoinSig1, err := hex.DecodeString(proofData.BitcoinSig1Bytes)
		if err != nil {
			return fmt.Errorf("Error decoding bitcoin_sig_1 for channel %d: %v", info.ChannelID, err)
		}
		bitcoinSig2, err := hex.DecodeString(proofData.BitcoinSig2Bytes)
		if err != nil {
			return fmt.Errorf("Error decoding bitcoin_sig_2 for channel %d: %v", info.ChannelID, err)
		}

		authProof := models.ChannelAuthProof{
			NodeSig1Bytes:    nodeSig1,
			NodeSig2Bytes:    nodeSig2,
			BitcoinSig1Bytes: bitcoinSig1,
			BitcoinSig2Bytes: bitcoinSig2,
		}

		if info.AuthProof == nil {
			channelAuthProofsToInsert[info.ChannelID] = authProof
		} else if c.Overwrite {
			channelAuthProofsToInsert[info.ChannelID] = authProof
		} else {
			log.Infof("channel %v already has an auth proof, skipping", info.ChannelID)

			if !bytes.Equal(info.AuthProof.NodeSig1Bytes, authProof.NodeSig1Bytes) || !bytes.Equal(info.AuthProof.NodeSig2Bytes, authProof.NodeSig2Bytes) || !bytes.Equal(info.AuthProof.BitcoinSig1Bytes, authProof.BitcoinSig1Bytes) || !bytes.Equal(info.AuthProof.BitcoinSig2Bytes, authProof.BitcoinSig2Bytes) {
				log.Infof("channel %v auth proof differs between graph and source. To overwrite the auth proof in the graph, pass --overwrite to the command", info.ChannelID)
			}
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("error loading auth proofs: %w", err)
	}

	log.Infof("Inserting %d authentication proofs into the graph DB", len(channelAuthProofsToInsert))

	for chanID, proof := range channelAuthProofsToInsert {
		shortChanID := lnwire.NewShortChanIDFromInt(chanID)
		err := graphDB.AddEdgeProof(shortChanID, &proof)
		if err != nil {
			log.Infof("Error adding proof for channel %v: %v", chanID, err)
		} else {
			log.Infof("Successfully added proof for channel %v", chanID)
		}
	}

	return nil
}
