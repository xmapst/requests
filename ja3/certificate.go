package ja3

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"time"
)

var rootKey *ecdsa.PrivateKey
var rootCrt *x509.Certificate

func init() {
	var err error
	rootKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	var rootCsr = &x509.Certificate{
		Version:      3,
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			Country:            []string{"Golang"},
			Province:           []string{"Golang"},
			Locality:           []string{"Golang"},
			Organization:       []string{"Golang"},
			OrganizationalUnit: []string{"Golang"},
			CommonName:         "Golang CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1000, 0, 0),
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		MaxPathLenZero:        false,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDer, err := x509.CreateCertificate(rand.Reader, rootCsr, rootCsr, rootKey.Public(), rootKey)
	if err != nil {
		panic(err)
	}

	rootCrt, err = x509.ParseCertificate(rootDer)
	if err != nil {
		panic(err)
	}
}

func getHosts(addrTypes ...int) []net.IP {
	var addrType int
	if len(addrTypes) > 0 {
		addrType = addrTypes[0]
	}
	var result []net.IP
	lls, err := net.InterfaceAddrs()
	if err != nil {
		return result
	}
	for _, ll := range lls {
		mm, ok := ll.(*net.IPNet)
		if ok && mm.IP.IsPrivate() {
			if addrType == 0 || parseIp(mm.IP) == addrType {
				result = append(result, mm.IP)
			}
		}
	}
	return result
}

func parseHost(host string) (net.IP, int) {
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return ip4, 4
		} else if ip6 := ip.To16(); ip6 != nil {
			return ip6, 6
		}
	}
	return nil, 0
}

func parseIp(ip net.IP) int {
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return 4
		} else if ip6 := ip.To16(); ip6 != nil {
			return 6
		}
	}
	return 0
}

func getCertWithCN(commonName string) (*x509.Certificate, error) {
	csr := &x509.Certificate{
		Version:      3,
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			Country:            []string{"Golang"},
			Province:           []string{"Golang"},
			Locality:           []string{"Golang"},
			Organization:       []string{"Golang"},
			OrganizationalUnit: []string{"Golang"},
		},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1000, 0, 0),
		BasicConstraintsValid: true,
		IsCA:                  false,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	csr.IPAddresses = getHosts()
	if commonName != "" {
		if ip, ipType := parseHost(commonName); ipType == 0 {
			csr.Subject.CommonName = commonName
			csr.DNSNames = []string{commonName}
		} else {
			csr.IPAddresses = append(csr.IPAddresses, ip)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, csr, rootCrt, rootKey.Public(), rootKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}
func getCertWithCert(preCert *x509.Certificate) (*x509.Certificate, error) {
	csr := &x509.Certificate{
		Version:               3,
		SerialNumber:          big.NewInt(time.Now().Unix()),
		Subject:               preCert.Subject,
		DNSNames:              preCert.DNSNames,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1000, 0, 0),
		BasicConstraintsValid: true,
		IsCA:                  false,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, csr, rootCrt, rootKey.Public(), rootKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func getProxyCertWithName(serverName string) (tlsCert tls.Certificate, err error) {
	cert, err := getCertWithCN(serverName)
	if err != nil {
		return tlsCert, err
	}
	return getTlsCert(cert)
}

func getProxyCertWithCert(preCert *x509.Certificate) (tlsCert tls.Certificate, err error) {
	cert, err := getCertWithCert(preCert)
	if err != nil {
		return tlsCert, err
	}
	return getTlsCert(cert)
}

func getTlsCert(cert *x509.Certificate) (tls.Certificate, error) {
	keyFile, err := getCertKeyData()
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(getCertData(cert), keyFile)
}

func getCertData(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func getCertKeyData() ([]byte, error) {
	keyDer, err := x509.MarshalECPrivateKey(rootKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDer}), nil
}
