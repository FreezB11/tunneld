```bash
tunnel/
├── go.mod
├── cmd/
│   ├── tunneld/main.go      # server entrypoint
│   └── tunnel/main.go       # client entrypoint
├── internal/
│   ├── config/              # yaml loading + validation for both configs
│   │   ├── server.go
│   │   └── client.go
│   ├── auth/                # pluggable Authenticator interface
│   │   ├── auth.go
│   │   └── token.go
│   ├── protocol/            # control-plane message types (register, ack, error)
│   │   └── messages.go
│   ├── server/               # tunneld core: listener mgmt, ACL, stream routing
│   │   └── server.go
│   └── client/               # tunnel core: dial, register, proxy loop
│       └── client.go
├── server.example.yml
├── client.example.yml
└── README.md
```