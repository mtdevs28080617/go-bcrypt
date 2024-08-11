package go_bcrypt

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestBcrypt(t *testing.T) {
	_assert := assert.New(t)

	b, err := NewBcrypt()
	_assert.Nil(err)

	enc, err := b.Hash("mypassword")
	_assert.Nil(err)

	valid := b.Valid(enc, "mypassword")
	_assert.True(valid)

	valid = b.Valid(enc, "invalidpassword")
	_assert.False(valid)
}

func TestBcrypt_WithCustom(t *testing.T) {
	_assert := assert.New(t)

	b, err := NewBcrypt(WithCustomCost(32))
	_assert.EqualError(err, "crypto/bcrypt: cost 32 is outside allowed range (4,31)")
	_assert.Nil(b)

	b, err = NewBcrypt(WithCustomCost(11))
	_assert.Nil(err)

	enc, err := b.Hash("mypassword")
	_assert.Nil(err)

	valid := b.Valid(enc, "mypassword")
	_assert.True(valid)

	valid = b.Valid(enc, "invalidpassword")
	_assert.False(valid)
}
