package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/spf13/cobra"

	"github.com/nucleuscloud/seacrypt"
)

var (
	fileParam                string
	keyFileParam             string
	deletePrivateKeyAfterUse bool
)

var execEnvCmd = &cobra.Command{
	Use:   "exec-env",
	Short: "",
	Long:  "",
	RunE: func(cmd *cobra.Command, args []string) error {
		file, err := cmd.Flags().GetString("file")
		if err != nil {
			return err
		}

		file, err = filepath.Abs(file)
		if err != nil {
			return err
		}

		keyFile, err := cmd.Flags().GetString("key")
		if err != nil {
			return err
		}

		ctx := context.Background()
		kmsClient, err := seacrypt.GetKmsClient(ctx)
		if err != nil {
			return err
		}

		return execEnv(ctx, kmsClient, file, keyFile, deletePrivateKeyAfterUse, args...)
	},
}

func init() {
	rootCmd.AddCommand(execEnvCmd)
	execEnvCmd.Flags().StringVarP(&fileParam, "file", "f", "", "the secrets file to read (required)")
	_ = execEnvCmd.MarkFlagRequired("file")
	execEnvCmd.Flags().StringVarP(&keyFileParam, "key", "k", "", "the private key file to read")
	execEnvCmd.Flags().BoolVarP(&deletePrivateKeyAfterUse, "delete-private-key-after-use", "d", false, "deletes the private key locally after use")
}

func execEnv(ctx context.Context, kmsClient *kms.Client, filePath string, keyFile string, deletePrivateKeyAfterUse bool, command ...string) error {
	cmd, err := buildCommandForExecEnv(ctx, kmsClient, filePath, keyFile, deletePrivateKeyAfterUse, command...)
	if err != nil {
		return err
	}

	return cmd.Run()
}

func buildCommandForExecEnv(ctx context.Context, kmsClient *kms.Client, filePath string, keyFile string, deletePrivateKeyAfterUse bool, command ...string) (*exec.Cmd, error) {
	// decrypt subtree in file
	st, err := decrypt(ctx, kmsClient, filePath, keyFile, deletePrivateKeyAfterUse)
	if err != nil {
		return nil, err
	}

	// set secrets into env
	env, err := getEnvWithSecrets(st)
	if err != nil {
		return nil, err
	}

	// // start child process
	return prepareCommand(command, env), nil
}

func decrypt(ctx context.Context, kmsClient *kms.Client, filePath string, keyFile string, deletePrivateKeyAfterUse bool) (map[string]string, error) {
	kmsKey, err := getKey(keyFile, deletePrivateKeyAfterUse)
	if err != nil {
		return nil, err
	}

	// if no file with encrypted secrets exists,
	// just return an empty map
	fi, err := os.Stat(filePath)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]string{}, nil
	} else if fi.IsDir() {
		return nil, fmt.Errorf("provided path is a directory but must be a file[%s]", filePath)
	} else if err != nil {
		return nil, err
	}

	contents, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	var secretMap map[string]string
	err = json.Unmarshal(contents, &secretMap)
	if err != nil {
		return nil, err
	}

	for k, value := range secretMap {
		// todo: this should be done concurrently
		decryptedValue, err := seacrypt.DecryptSecrets(ctx, kmsClient, kmsKey, value)
		if err != nil {
			return nil, err
		}
		secretMap[k] = decryptedValue
	}
	return secretMap, nil
}

func getEnvWithSecrets(st map[string]string) ([]string, error) {
	env := os.Environ()
	for key, value := range st {
		env = append(env, fmt.Sprintf("%s=%s", seacrypt.ToScreamingSnake(key), value))
	}
	return env, nil
}

func prepareCommand(command []string, env []string) *exec.Cmd {
	var args []string
	args = append(args, "-c")
	args = append(args, command...)
	cmd := exec.Command("/bin/sh", args...)

	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd
}

func getKey(path string, deletePrivateKeyAfterUse bool) (string, error) {
	if deletePrivateKeyAfterUse {
		defer func() {
			if path != "" {
				_ = os.Remove(path)
			}
		}()
	}

	if path == "" {
		return "", fmt.Errorf("cannot find key id")
	}
	contents, err := ioutil.ReadFile(path)
	if err != nil {
		return "", err
	}
	stringContents := string(contents)
	if stringContents == "" {
		return "", fmt.Errorf("length of key must be greater than 0")
	}
	return strings.TrimSpace(stringContents), nil
}
