package scanner

// services maps well-known TCP ports to their usual service names.
var services = map[int]string{
	21:    "ftp",
	22:    "ssh",
	23:    "telnet",
	25:    "smtp",
	53:    "dns",
	80:    "http",
	110:   "pop3",
	111:   "rpcbind",
	135:   "msrpc",
	139:   "netbios-ssn",
	143:   "imap",
	443:   "https",
	445:   "smb",
	465:   "smtps",
	587:   "submission",
	993:   "imaps",
	995:   "pop3s",
	1433:  "mssql",
	1521:  "oracle",
	3306:  "mysql",
	3389:  "rdp",
	5432:  "postgresql",
	5900:  "vnc",
	6379:  "redis",
	8000:  "http-alt",
	8080:  "http-proxy",
	8443:  "https-alt",
	8888:  "http-alt",
	9200:  "elasticsearch",
	27017: "mongodb",
}

// TopPorts is the default list of commonly exposed ports.
var TopPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587,
	993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443,
	8888, 9200, 27017,
}

// Ports where we send an HTTP request to provoke a banner.
var httpPorts = map[int]bool{80: true, 8000: true, 8080: true, 8888: true}

// Ports where the service speaks TLS immediately.
var tlsPorts = map[int]bool{443: true, 465: true, 993: true, 995: true, 8443: true}

// ServiceName returns the conventional service name for a port,
// or "unknown" if the port is not in the table.
func ServiceName(port int) string {
	if s, ok := services[port]; ok {
		return s
	}
	return "unknown"
}
