# Honeypot
**A honeypot framework designed to measure drive-by internet attacks**

This project contains a lightweight Go service designed to act as a honeypot
for various drive-by internet attacks on common protocols. It is designed to
make adding new protocols extremely easy, while keeping track of various
indicators of an attack.

## Supported Protocols

| Protocol   | Port  | Emulation   |
|------------|-------|-------------|
| SSH        | 22    | Full        |
| Telnet     | 23    | Full        |
| HTTP       | 80    | Full        |
| Redis      | 6379  | Full        |
| RDP        | 3369  | Basic (TCP) |
| VNC        | 5900  | Basic (TCP) |
| MongoDB    | 27017 | Basic (TCP) |
| PostgreSQL | 5432  | Basic (TCP) |
| MySQL      | 3306  | Basic (TCP) |

## Deployment
This project can be deployed using Kubernetes. To do so, you should do the
following:

```bash
kubectl create namespace honeypot-demo
kubectl apply --namespace honeypot-demo \
    -f https://raw.githubusercontent.com/SierraSoftworks/honeypot/master/.deploy/deployment.yml \
    -f https://raw.githubusercontent.com/SierraSoftworks/honeypot/master/.deploy/service.yml
```

This will deploy the latest version of the honeypot on your Kubernetes cluster and expose it
using a dedicated Service (`type: LoadBalancer`). It will also create a new service called
`honeypot-server` which hosts the API on its `http` port. To access this, you can create an
ingress or use `kubectl proxy`.
