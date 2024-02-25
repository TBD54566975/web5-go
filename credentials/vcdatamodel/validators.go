package vcdatamodel

import (
	"errors"
	"fmt"
)

func validateContext(c []URI) error {
	err := errors.New(fmt.Sprintf("@context is missing default context %s", DefaultContext))
	for _, v := range c {
		if v == DefaultContext {
			return nil
		}
	}

	return err
}

func validateVCType(t []string) error {
	err := errors.New(fmt.Sprintf("type is missing default %s", DefaultVCType))
	for _, v := range t {
		if v == DefaultVCType {
			return nil
		}
	}

	return err
}

func validateCredentialSubject(cs []CredentialSubject) error {
	err := errors.New("credentialSubject must not be empty")

	if len(cs) >= 1 {
		return nil
	}

	return err
}
