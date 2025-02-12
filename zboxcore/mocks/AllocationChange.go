// Code generated by mockery v2.14.0. DO NOT EDIT.

package mocks

import (
	fileref "github.com/0chain/gosdk/zboxcore/fileref"
	mock "github.com/stretchr/testify/mock"
)

// AllocationChange is an autogenerated mock type for the AllocationChange type
type AllocationChange struct {
	mock.Mock
}

// GetAffectedPath provides a mock function with given fields:
func (_m *AllocationChange) GetAffectedPath() []string {
	ret := _m.Called()

	var r0 []string
	if rf, ok := ret.Get(0).(func() []string); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]string)
		}
	}

	return r0
}

// GetSize provides a mock function with given fields:
func (_m *AllocationChange) GetSize() int64 {
	ret := _m.Called()

	var r0 int64
	if rf, ok := ret.Get(0).(func() int64); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(int64)
	}

	return r0
}

// ProcessChange provides a mock function with given fields: rootRef, fileIDMeta
func (_m *AllocationChange) ProcessChange(rootRef *fileref.Ref, fileIDMeta map[string]string) error {
	ret := _m.Called(rootRef, fileIDMeta)

	var r0 error
	if rf, ok := ret.Get(0).(func(*fileref.Ref, map[string]string) error); ok {
		r0 = rf(rootRef, fileIDMeta)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

type mockConstructorTestingTNewAllocationChange interface {
	mock.TestingT
	Cleanup(func())
}

// NewAllocationChange creates a new instance of AllocationChange. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewAllocationChange(t mockConstructorTestingTNewAllocationChange) *AllocationChange {
	mock := &AllocationChange{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
