// Code generated by mockery v2.14.0. DO NOT EDIT.

package mocks

import mock "github.com/stretchr/testify/mock"

// GetInfoCallback is an autogenerated mock type for the GetInfoCallback type
type GetInfoCallback struct {
	mock.Mock
}

// OnInfoAvailable provides a mock function with given fields: op, status, info, err
func (_m *GetInfoCallback) OnInfoAvailable(op int, status int, info string, err string) {
	_m.Called(op, status, info, err)
}

type mockConstructorTestingTNewGetInfoCallback interface {
	mock.TestingT
	Cleanup(func())
}

// NewGetInfoCallback creates a new instance of GetInfoCallback. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewGetInfoCallback(t mockConstructorTestingTNewGetInfoCallback) *GetInfoCallback {
	mock := &GetInfoCallback{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
