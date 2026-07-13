# tunneld
tunneld is a tunnel service that use aws(`t3.micro`) for helping you get your project or site to the public, tho we dont yet have custom domain or smtg but you can use the public ip of aws instance.

the plan is that we have `.yml` for both `t_server` and `t_client` configuration
we have the tree of file that i will follow now [tree](tree.md)


### The basic idea for `tunneld`
```bash
┌─────────────────┐         control conn (TLS+yamux)           ┌──────────────────┐
│  local machine  │ ───────────────────────────────────────▶  │   EC2 t3.micro   │
│                 │         (client dials out, auth)           │                  │
│  tunnel (client)│                                            │  tunneld (server)│
│                 │◀── new stream per incoming conn ──────────│                  │
│  proxies to     │                                            │  listens on      │
│  127.0.0.1:PORT │                                            │  0.0.0.0:REMOTE  │
└─────────────────┘                                            └──────────────────┘
                                                                          ▲
                                                                          │
                                                                   internet traffic
```

thing to note b4 running the ec2 instance is setup the security group add these two inbound rules (in addition to whatever SSH/Instance-Connect rule is already there):

Type         | Protocol  |    Port range               |   Source
-------------|-----------|-----------------------------|----------
Custom TCP   | TCP       |    7000                     |   0.0.0.0/0
Custom TCP   | TCP       |    8000-9000                |   0.0.0.0/0

(7000 = control port, 8000-9000 = the tunnel port range from your config)

### On the EC2 instance
```bash
sudo dnf install -y golang git
go version

git clone https://github.com/<this_repo>.git
cd <this-repo>

go build -o tunneld ./cmd/tunneld
ls -la tunneld
```

if that throws a error for the version then you can do this
```bash
go mod edit -go=1.21
go build -o tunneld ./cmd/tunneld
```
this shud work with no issues

**Step1** - generate a auth token
```bash
openssl rand -hex 32 # copy this to your local machine
cp server.example.yml tunneld.yml
vim/nano tunneld.yml
```
set the auth token that was generated\
and you can also set your port range by default it is at 8000-9000\
leave the tls.cert_file and tls.key_file blank it will self-assign

now run the process
```bash
./tunneld -config tunneld.yml
```

you shud see smthg like this 
```bash
tunneld: starting (config: tunneld.yml)
tunneld: generated self-signed TLS certificate
tunneld: fingerprint (put this in client config as server_fingerprint): <hex string>
tunneld: control listener on 0.0.0.0:7000
```

### On Client side
```bash
cp client.example.yml tunnel.yml
```

edit the `.yml` so you have 
```yaml
server: "<EC2_PUBLIC_IP>:7000"
auth_token: "<the openssl rand -hex 32 token you set on the server>"
client_name: "my-laptop"
server_fingerprint: "991fd4945aa66a04d05349ccdad2ee6e9ec242ba4825c765d0abb9303aa8f7a6"
insecure_skip_verify: false

tunnels:
  - name: web
    type: http
    local_addr: 127.0.0.1:3000
    remote_port: 8080
```
start whatever local service you'r tunneling
```
./tunnel -config tunnel.yml
```

you shud see
```
tunnel: connected to <EC2_IP>:7000
tunnel: registered "web" -> server port 8080
```