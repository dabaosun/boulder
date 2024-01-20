package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os/user"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/privatekey"
	sapb "github.com/letsencrypt/boulder/sa/proto"
)

// subcommandBlockKey encapsulates the "admin block-key" command.
func (a *admin) subcommandBlockKey(ctx context.Context, args []string) error {
	subflags := flag.NewFlagSet("block-key", flag.ExitOnError)
	privKey := subflags.String("private-key", "", "Block issuance for the pubkey corresponding to this private key")
	comment := subflags.String("comment", "", "Additional context to add to database comment column")
	_ = subflags.Parse(args)

	if *privKey == "" {
		return errors.New("the -private-key flag is required")
	}

	spkiHash, err := a.spkiHashFromPrivateKey(*privKey)
	if err != nil {
		return err
	}

	err = a.blockSPKIHash(ctx, spkiHash, *comment)
	if err != nil {
		return err
	}

	return nil
}

func (a *admin) spkiHashFromPrivateKey(keyFile string) ([]byte, error) {
	_, publicKey, err := privatekey.Load(keyFile)
	if err != nil {
		return nil, fmt.Errorf("loading private key file: %w", err)
	}

	spkiHash, err := core.KeyDigest(publicKey)
	if err != nil {
		return nil, fmt.Errorf("computing SPKI hash: %w", err)
	}

	return spkiHash[:], nil
}

func (a *admin) blockSPKIHash(ctx context.Context, spkiHash []byte, comment string) error {
	var count int
	err := a.dbMap.SelectOne(ctx, &count, "SELECT COUNT(*) as count FROM keyHashToSerial WHERE keyHash = ? AND certNotAfter > NOW()", spkiHash[:])
	if err != nil {
		return fmt.Errorf("counting affected certificates: %w", err)
	}
	a.log.Infof("Found %d certificates matching the provided key", count)

	u, err := user.Current()
	if err != nil {
		return fmt.Errorf("getting admin username: %w", err)
	}

	req := &sapb.AddBlockedKeyRequest{
		KeyHash:   spkiHash[:],
		Added:     timestamppb.New(a.clk.Now()),
		Source:    "admin-revoker",
		Comment:   fmt.Sprintf("%s: %s", u.Username, comment),
		RevokedBy: 0,
	}

	if a.dryRun {
		a.log.Infof("dry-run: %v", req)
		return nil
	}

	_, err = a.sac.AddBlockedKey(ctx, req)
	if err != nil {
		return fmt.Errorf("blocking key: %w", err)
	}

	return nil
}
