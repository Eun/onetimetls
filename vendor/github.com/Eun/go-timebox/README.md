# go-timebox [![Travis](https://img.shields.io/travis/Eun/go-timebox.svg)](https://travis-ci.org/Eun/go-timebox) [![Codecov](https://img.shields.io/codecov/c/github/Eun/go-timebox.svg)](https://codecov.io/gh/Eun/go-timebox) [![GoDoc](https://godoc.org/github.com/Eun/go-timebox?status.svg)](https://godoc.org/github.com/Eun/go-timebox) [![go-report](https://goreportcard.com/badge/github.com/Eun/go-timebox)](https://goreportcard.com/report/github.com/Eun/go-timebox)
timebox a go function

```go
func ExampleDetail() {
	result, err := timebox.Timebox(time.Second, func() (int, error) {
		// Some heavy operation
		return 42, nil
	})
	// check if Timebox() has an error
	if err != nil {
		panic(err)
	}
	// check if the function has an error
	if result[1] != nil {
		panic(result[1])
	}
	fmt.Printf("The answer is %d\n", result[0].(int))
}
```