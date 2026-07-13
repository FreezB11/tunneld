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
