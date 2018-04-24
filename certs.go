package goproxy

import (
	"crypto/tls"
	"crypto/x509"
)

func init() {
	if goproxyCaErr != nil {
		panic("Error parsing builtin CA " + goproxyCaErr.Error())
	}
	var err error
	if GoproxyCa.Leaf, err = x509.ParseCertificate(GoproxyCa.Certificate[0]); err != nil {
		panic("Error parsing builtin CA " + err.Error())
	}
}

var tlsClientSkipVerify = &tls.Config{InsecureSkipVerify: true}

var defaultTLSConfig = &tls.Config{
	InsecureSkipVerify: true,
}

var CA_CERT = []byte(`-----BEGIN CERTIFICATE-----
MIICgzCCAewCCQDAU5nGJpwnXzANBgkqhkiG9w0BAQsFADCBhTELMAkGA1UEBhMC
SUwxETAPBgNVBAgMCFRlbCBBdml2MQ0wCwYDVQQHDARjaXR5MQ4wDAYDVQQKDAVK
ZnJvZzEQMA4GA1UECwwHc2VjdGlvbjESMBAGA1UEAwwJbG9jYWxob3N0MR4wHAYJ
KoZIhvcNAQkBFg95b2F6bUBqZnJvZy5jb20wHhcNMTgwNDI0MDg0ODU1WhcNMjMw
NDIzMDg0ODU1WjCBhTELMAkGA1UEBhMCSUwxETAPBgNVBAgMCFRlbCBBdml2MQ0w
CwYDVQQHDARjaXR5MQ4wDAYDVQQKDAVKZnJvZzEQMA4GA1UECwwHc2VjdGlvbjES
MBAGA1UEAwwJbG9jYWxob3N0MR4wHAYJKoZIhvcNAQkBFg95b2F6bUBqZnJvZy5j
b20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBANUsarxw36pNXeNX+TaqrePp
roVGNKjFSEEbxa7s/En3Ad/HII2cyA36hJ2hJIoF5AYnpEohyQSTxUQeQfCpOZpX
e+pFhuOhBNOk5IPsjaUuC+kWVg3fhUd6NEU85V4lIzBSStnRS4Ap/rT7Q3q5pyFh
B5QkfRqI+Rzt+sy11ubvAgMBAAEwDQYJKoZIhvcNAQELBQADgYEAsPKoqOTxIjj6
If0QZXyDRvKbSku9lDc8KFZ6GLYWg5yv+ohmDFVmH8kfDScC2hqMQYhDnXONIr/b
iOQQ3dZrSky0J+svk3N7EuRMcTjAE36IQPn7c562XmFFDealZ2IZgRw7lzYRmIVC
EAKYALdaqAs7bqu0uUd/7DPpuwdsD3Y=
-----END CERTIFICATE-----`)

var CA_KEY = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQDVLGq8cN+qTV3jV/k2qq3j6a6FRjSoxUhBG8Wu7PxJ9wHfxyCN
nMgN+oSdoSSKBeQGJ6RKIckEk8VEHkHwqTmaV3vqRYbjoQTTpOSD7I2lLgvpFlYN
34VHejRFPOVeJSMwUkrZ0UuAKf60+0N6uachYQeUJH0aiPkc7frMtdbm7wIDAQAB
AoGAE72iQMMfI1E40ZXTAUn7AnEgdT0UIVDrqQPeYZ2Wm27hYIy7KgIL0KeTYlmK
3bE/9YX0Q90vFVpt2SoIJzY0nDgRVatlbregFF+QAI1R1u+lZUprbAKW+wZp5wSJ
szsd/QJ+ahiI6u8WN186kmPuhL7dUMMO4AZxvbcfGMaEhGkCQQDz1BaBxaUHoRcz
MlpBfmRivdmWkvYpkRQigdmoo7GDF8lp5NfzbzA/12K/0qWg0afspzvNKxi+lMIP
FVsqCKrDAkEA39CV8BVZjP8s34VccPWC9OHIeRwJEsD3V/7K+axG5hL9Q8m96gzt
gT3ed5gTzL3+LxHGzIQdfYwKhUSxot3YZQJBALe1mmeYZKkE5Jf8XihudHA5HpHm
lHXpC0SclUQMYZil+WlBtLuDkNTpEUv6CDTNAjq6HcKNsA0Xw8bdjlxzP0UCQFRd
zCcz5Q3BIqkfHDl4UmT8txTv/HuVQadp5Bk5V4BiqBVldrFDLkQJjlKGgPAsriQQ
D2AIbRVmNJEH0+4QsgECQBxG55dZa+bhmMml5wkd/L/b6WCSBDevo6MDEb2sznME
5DPvgiL1zxDGM1oao8I6oFD4GPQGwWdFgXu7f3mzNKw=
-----END RSA PRIVATE KEY-----`)

var GoproxyCa, goproxyCaErr = tls.X509KeyPair(CA_CERT, CA_KEY)
