# Cert-Mon
1. Create a configuration file named `config.toml` in the `/etc/cert-mon/` directory

2. Run the program

```
go run cert-mon.go -c config.toml
```

3. Install as a service

```
sudo systemctl enable cert-checker.service
sudo systemctl start cert-checker.service
```