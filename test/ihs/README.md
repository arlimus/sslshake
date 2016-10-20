Create an IBM Apache HTTPServer w/ SSL cert

```bash
docker build --tag myihs .
docker run -it -p 8008:8008 -p:8443:8443 myihs
```

No app is deployed, so you get 403, but SSL works.
SSL handshake is giving `SSL Alert`
