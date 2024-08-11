package go_bcrypt

import (
	"golang.org/x/crypto/bcrypt"
)

type BcryptHasher interface {
	Hash(password string) (string, error)
	Valid(hashed string, password string) bool
}

type Bcrypt struct {
	cost int
}

type BcryptConfigFunc func(b *Bcrypt) error

func NewBcrypt(cfgFuncs ...BcryptConfigFunc) (BcryptHasher, error) {
	b := setDefaults()

	for _, cfgFunc := range cfgFuncs {
		if err := cfgFunc(b); err != nil {
			return nil, err
		}
	}

	return b, nil
}

// Hash takes an argument of string and will return a string of the hashed version or an error
func (b *Bcrypt) Hash(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), b.cost)

	return string(bytes), err
}

// Valid takes two arguments of string, first argument is the hashed password and the second is the value to check against
// a bool is returned as the answer
func (b *Bcrypt) Valid(hashed string, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(password))

	return err == nil
}

// WithCustomCost takes an argument of int and sets the bcrypt cost, if the value passed is out of bounds an error is returned
func WithCustomCost(cost int) BcryptConfigFunc {
	return func(b *Bcrypt) error {
		if err := checkCost(cost); err != nil {
			return err
		}

		b.cost = cost

		return nil
	}
}

func checkCost(cost int) error {
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		return bcrypt.InvalidCostError(cost)
	}

	return nil
}

func setDefaults() *Bcrypt {
	return &Bcrypt{
		cost: bcrypt.DefaultCost,
	}
}
