package githubwebhook

type Option func(*Attestor)

func WithBody(body []byte) Option {
	return func(a *Attestor) {
		a.body = body
	}
}

func WithSecret(secret []byte) Option {
	return func(a *Attestor) {
		a.secret = secret
	}
}

func WithRecievedSignature(recievedSig string) Option {
	return func(a *Attestor) {
		a.receivedSig = recievedSig
	}
}

func WithEvent(event string) Option {
	return func(a *Attestor) {
		a.Event = event
	}
}
