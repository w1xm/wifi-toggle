package main

import (
	"encoding/asn1"
	"flag"
	"html/template"
	"log"
	"net/http"
	"net/http/cgi"
	"strconv"
	"strings"
	"time"

	"github.com/soniah/gosnmp"
)

var (
	target = flag.String("target", "w1xm-exp-1.mit.edu", "target host")
	user   = flag.String("user", "w1xm", "username")
)

func handler(w http.ResponseWriter, r *http.Request) {
	if err := handlerErr(w, r); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func stringToObjectIdentifier(oid string) asn1.ObjectIdentifier {
	// Encode the oid
	oid = strings.Trim(oid, ".")
	oidParts := strings.Split(oid, ".")
	oidBytes := make([]int, len(oidParts))

	// Convert the string OID to an array of integers
	for i := 0; i < len(oidParts); i++ {
		var err error
		oidBytes[i], err = strconv.Atoi(oidParts[i])
		if err != nil {
			return nil
		}
	}
	return asn1.ObjectIdentifier(oidBytes)
}

var indexTmpl = template.Must(template.New("index").Parse(`
<!DOCTYPE html>
<html>
<head>
<title>W1XM WiFi Toggle</title>
</head>
<body>
<h1>W1XM WiFi Toggle</h1>
<form method="post">
Password: <input type="password" name="password" value="{{.Password}}"/> <input type="submit" value="Login" />
{{with .Result}}
<h2>Result</h2>
<pre>
{{.}}
</pre>
{{end}}
<h2>Scripts</h2>
<ul>
{{range $index, $name := .Scripts}}
<li><button type="submit" name="execute" value="{{$index}}">{{$name}}</button></li>
{{end}}
</ul>
</form>
</body>
</html>
`))

func handlerErr(w http.ResponseWriter, r *http.Request) error {
	password := r.FormValue("password")
	scripts := make(map[int]string)
	var result string
	if password != "" {
		client := &gosnmp.GoSNMP{
			Target:        *target,
			Port:          161,
			Version:       gosnmp.Version3,
			SecurityModel: gosnmp.UserSecurityModel,
			SecurityParameters: &gosnmp.UsmSecurityParameters{
				UserName:                 *user,
				AuthenticationProtocol:   gosnmp.SHA,
				AuthenticationPassphrase: password,
				PrivacyProtocol:          gosnmp.NoPriv,
			},

			Timeout: 1 * time.Second,
			Retries: 3,
			MaxOids: gosnmp.MaxOids,
		}
		err := client.Connect()
		if err != nil {
			return err
		}

		if err := client.Walk("1.3.6.1.4.1.14988.1.1.8.1.1.2", func(pdu gosnmp.SnmpPDU) error {
			oid := stringToObjectIdentifier(pdu.Name)
			scripts[oid[len(oid)-1]] = string(pdu.Value.([]byte))
			return nil
		}); err != nil {
			return err
		}

		execute := r.FormValue("execute")
		if execute != "" {
			res, err := client.Get([]string{"1.3.6.1.4.1.14988.1.1.18.1.1.2." + execute})
			if err != nil {
				return err
			}
			if len(res.Variables) > 0 {
				result = string(res.Variables[0].Value.([]byte))
			}
		}
	}
	return indexTmpl.Execute(w, struct {
		Password string
		Scripts  map[int]string
		Result   string
	}{
		password,
		scripts,
		result,
	})
}

func main() {
	if err := cgi.Serve(http.HandlerFunc(handler)); err != nil {
		log.Fatal(err)
	}
}
