// Code generated by mockery v0.0.0-dev. DO NOT EDIT.

package zcncore

import (
	mock "github.com/stretchr/testify/mock"
)

// TransactionCallback is an autogenerated mock type for the TransactionCallback type
type MockTransactionCallback struct {
	mock.Mock
}

// OnAuthComplete provides a mock function with given fields: t, status
func (_m MockTransactionCallback) OnAuthComplete(t *Transaction, status int) {
	_m.Called(t, status)
}

// OnTransactionComplete provides a mock function with given fields: t, status
func (_m MockTransactionCallback) OnTransactionComplete(t *Transaction, status int) {
	_m.Called(t, status)
}

// OnVerifyComplete provides a mock function with given fields: t, status
func (_m MockTransactionCallback) OnVerifyComplete(t *Transaction, status int) {
	_m.Called(t, status)
}
