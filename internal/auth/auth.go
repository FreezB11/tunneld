package auth
// this defines how the server(aws now) authenticates connecting client

import "context"
 
//Identity describes an authenticated client.
type Identity struct {
	//ClientName is the name the client reported. not trusted for
	//authorization decisions by itself, only for logging - the token
	//(or whatever credential was used) is what actually gates access.
	ClientName string
}
 
//Authenticator validates a credential presented by a connecting client.
//implementations must be safe for concurrent use.
type Authenticator interface {
	//this checks the given token/credential string. it returns
	//the resulting Identity on success, or an error describing why
	//authentication failed. the error message may be sent back to the
	//client, so it must not leak secrets.
	Authenticate(ctx context.Context, credential string, clientName string) (Identity, error)
}