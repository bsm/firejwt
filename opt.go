package firejwt

// Options contains optional configuration for the Validator.
type Options struct {
	// Custom KID URL
	URL string
}

func (o *Options) norm() *Options {
	var o2 Options
	if o != nil {
		o2 = *o
	}

	if o2.URL == "" {
		o2.URL = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"
	}

	return &o2
}
