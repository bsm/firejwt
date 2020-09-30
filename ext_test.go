package firejwt

// Mocked creates a validator with a mock URL
func Mocked(url string) (*Validator, error) {
	return newValidator("mock-project", url)
}
