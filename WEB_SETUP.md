# Web Setup

```bash
docker run -p 5432:5432 --name some-postgres -e POSTGRES_PASSWORD=mysecretpassword -d postgres
cd v2/cmd/nuclei-server/nuclei-server
go build
./nuclei-server
```


```bash
cd v2/cmd/nuclei-server/nuclei-client
go build
./nuclei-client
```