# pcaf
PCAP to struct, simplified

## Usage

```go
package main

import "github.com/B00TK1D/pcaf"

func main() {
	streams, err := pcaf.Parse("example.pcap", pcaf.Options{DestinationIP: "127.0.0.1"})

	if err != nil {
		panic(err)
	}

	for _, stream := range streams {
		for _, exchange := range stream.Exchanges {
			println("Request:", string(exchange.Request.Data))
			println("Response:", string(exchange.Response.Data))
		}
	}
}
```
