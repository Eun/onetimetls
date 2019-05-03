package timebox

import (
	"fmt"
	"reflect"
	"time"
)

// NotAFunctionError will be returned if the passed parameter for Timebox is not a function
type NotAFunctionError struct{}

func (NotAFunctionError) Error() string {
	return "not a function"
}

// IsNotAFunctionError tests if a error is an NotAFunctionError
func IsNotAFunctionError(err error) bool {
	_, ok := err.(NotAFunctionError)
	return ok
}

// TimeoutError will be returned if the timeout exceeds
type TimeoutError struct{}

func (TimeoutError) Error() string {
	return "timeout"
}

// IsTimeoutError tests if a error is an TimeoutError
func IsTimeoutError(err error) bool {
	_, ok := err.(TimeoutError)
	return ok
}

// Timebox timeboxes a function to a specific timeout, if the timeout exceeds the err will be an instance of TimeoutError
// Specify 0 as timeout to wait infinitely
func Timebox(timeout time.Duration, fn interface{}, arguments ...interface{}) (returns []interface{}, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("%v", e)
		}
	}()
	v := reflect.ValueOf(fn)
	if v.Kind() != reflect.Func {
		return nil, NotAFunctionError{}
	}

	var args []reflect.Value
	if size := len(arguments); size > 0 {
		args = make([]reflect.Value, size)
		for i, arg := range arguments {
			args[i] = reflect.ValueOf(arg)
		}
	}

	returnChan := make(chan []reflect.Value)
	go func() {
		defer func() {
			if e := recover(); e != nil {
				err = fmt.Errorf("%v", e)
				returnChan <- nil
			}
		}()
		returnChan <- v.Call(args)
	}()

	var timeChan <-chan time.Time
	if timeout > 0 {
		timeChan = time.After(timeout)
	}

	select {
	case <-timeChan:
		return nil, TimeoutError{}
	case returnValues := <-returnChan:
		if size := len(returnValues); size > 0 {
			returns = make([]interface{}, size)
			for i, val := range returnValues {
				returns[i] = val.Interface()
			}
			return returns, nil
		}
	}

	return nil, err
}
