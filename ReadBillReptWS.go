package main

import (
	"bytes"
	"encoding/xml"
	"errors"
	//"flag"
	"fmt"
	"io"
	//"io/ioutil"
	//"crypto/tls"
	//"crypto/x509"
	"encoding/base64"
	//"log"
	//"net"
	"net/http"
	"os"
	"time"

	//"strings"
	//	"unicode/utf8"
	//"math/big"
	//"code.google.com/p/go.text/encoding/charmap"
	//"code.google.com/p/go.text/transform"
	//"github.com/axgle/mahonia"
	"code.google.com/p/mahonia"
)

//const entrustCert = `-----BEGIN CERTIFICATE-----
//...
//-----END CERTIFICATE-----`

type SoapEnvelope struct {
	XMLName xml.Name   `xml:"soapenv:Envelope"`
	SoapEnv string     `xml:"xmlns:soapenv,attr"`
	Urn     string     `xml:"xmlns:urn,attr"`
	Header  SoapHeader `xml:"soapenv:Header"`
	Body    SoapBody   `xml:"soapenv:Body"`
}

type SoapHeader struct {
	Security Security `xml:"wsse:Security"`
}

type SoapBody struct {
	ReadBillReptWS interface{}
}

type ReadBillReptWS struct {
	XMLName   xml.Name `xml:"ReadBillReptWS"`
	USER_CODE string   `xml:"urn:inbuf>USER_CODE"`
	GRUP_CODE string   `xml:"urn:inbuf>GRUP_CODE"`
	CUST_NUMB string   `xml:"urn:inbuf>CUST_NUMB"`
	SUBR_NUMB string   `xml:"urn:inbuf>SUBR_NUMB"`
	GRUP_TYPE string   `xml:"urn:inbuf>GRUP_TYPE"`
	TRNS_PERD string   `xml:"urn:inbuf>TRNS_PERD"`
	BLPD_INDC string   `xml:"urn:inbuf>BLPD_INDC"`
}

type Security struct {
	XMLName        xml.Name      `xml:"wsse:Security"`
	MustUnderstand string        `xml:"soapenv:mustUnderstand,attr"`
	Wsse           string        `xml:"xmlns:wsse,attr"`
	UsernameToken  UsernameToken `xml:"wsse:UsernameToken"`
}

type UsernameToken struct {
	XMLName  xml.Name              `xml:"wsse:UsernameToken"`
	Id       string                `xml:"wsu:Id,attr"`
	Wsu      string                `xml:"xmlns:wsu,attr"`
	Username string                `xml:"wsse:Username"`
	Password PasswordUsernameToken `xml:"wsse:Password"`
	Nonce    NonceUsernameToken    `xml:"wsse:Nonce"`
	Created  string                `xml:"wsse:Created"`
}

type PasswordUsernameToken struct {
	XMLName  xml.Name `xml:""`
	Password string   `xml:",chardata"`
	Type     string   `xml:",attr"`
}
type NonceUsernameToken struct {
	XMLName      xml.Name `xml:""`
	Nonce        string   `xml:",chardata"`
	EncodingType string   `xml:",attr"`
}

type SoapEnvelopeResponse struct {
	XMLName xml.Name         `xml:"SOAP-ENV:Envelope"`
	SoapEnv string           `xml:"xmlns:SOAP-ENV,attr"`
	Tuxedo  string           `xml:"xmlns:tuxedo,attr"`
	Header  string           `xml:"SOAP-ENV:Header"`
	Body    SoapBodyResponse `xml:"SOAP-ENV:Body"`
}

type SoapBodyResponse struct {
	ReadBillReptWSResponse interface{}
	//readBillReptWSResponseArray ReadBillReptWSResponseArray `xml:"ReadBillReptWSResponse>outbuf,innerxml"`
}

type ReadBillReptWSResponse struct {
	XMLName        xml.Name `xml:"ReadBillReptWSResponse"`
	SRVC_TYPE      []string `xml:"outbuf>SRVC_TYPE"`
	SRVC_DESC      []string `xml:"outbuf>SRVC_DESC"`
	ARTM_TYPE_UNIT []string `xml:"outbuf>ARTM_TYPE_UNIT"`
	TOTL_AMNT      []string `xml:"outbuf>TOTL_AMNT"`
	TOTL_USGE      []string `xml:"outbuf>TOTL_USGE"`
	TBL_OCCR       string   `xml:"outbuf>TBL_OCCR"`
	SLED_TOTL_AMNT string   `xml:"outbuf>SLED_TOTL_AMNT"`
	TAX_AMNT       string   `xml:"outbuf>TAX_AMNT"`
}

//type ReadBillReptWSResponseArray struct {
//	TuxFieldList []TuxField `xml:",any"`
//}

//type TuxField struct {
//	XMLName       xml.Name `xml:""`
//	TuxFieldValue string   `xml:",chardata"`
//}

type FaultResponseList struct {
	XMLName      xml.Name `xml:""`
	Nonce        string   `xml:",chardata"`
	EncodingType string   `xml:",attr"`
}

type FaultResponse struct {
	XMLName     xml.Name     `xml:"Fault"`
	Faultcode   string       `xml:"faultcode"`
	Faultstring string       `xml:"faultstring"`
	Detail      DetailStruct `xml:"detail"`
}

type DetailStruct struct {
	XMLName             xml.Name                  `xml:"detail"`
	ReadBillReptWSFault ReadBillReptWSFaultStruct `xml:"ReadBillReptWSFault"`
}

type ReadBillReptWSFaultStruct struct {
	XMLName xml.Name     `xml:"ReadBillReptWSFault"`
	Errbuf  ErrbufStruct `xml:"errbuf"`
}

type ErrbufStruct struct {
	XMLName          xml.Name `xml:"errbuf"`
	MESSAGE_TEXT_ENG string   `xml:"MESSAGE_TEXT_ENG"`
	MESSAGE_TEXT_THA string   `xml:"MESSAGE_TEXT_THA"`
	MESSAGE_SQLCODE  string   `xml:"MESSAGE_SQLCODE"`
	MESSAGE_NATURE   string   `xml:"MESSAGE_NATURE"`
}

type Encryption struct {
	Username string
	Password string
}

func (encrypt Encryption) GetEncrypted() string {
	authen := []byte(encrypt.Username + ":" + encrypt.Password)
	encPass := &bytes.Buffer{}
	encrypted := base64.NewEncoder(base64.StdEncoding, encPass)
	encrypted.Write(authen)
	encrypted.Close()

	return string(encPass.Bytes())
}

func (readBillReptWS ReadBillReptWS) CreateSoapEnvelope(encrypt Encryption) *SoapEnvelope {
	const layout = "2006-01-02T15:04:05.999Z"
	t := time.Now()

	retval := &SoapEnvelope{}
	retval.SoapEnv = "http://schemas.xmlsoap.org/soap/envelope/"
	retval.Urn = "urn:pack.INReadBillReptWS_typedef.salt11"
	retval.Body.ReadBillReptWS = readBillReptWS // ReadBillReptWS{USER_CODE: "LLTHUNYADAP", GRUP_CODE: "0", CUST_NUMB: "536672462", SUBR_NUMB: "66900010040", GRUP_TYPE: "N", TRNS_PERD: "2014-02", BLPD_INDC: "PCN"}
	passwordUsernameToken := PasswordUsernameToken{Password: encrypt.Password, Type: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText"}
	nonceUsernameToken := NonceUsernameToken{Nonce: encrypt.GetEncrypted(), EncodingType: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"}
	userToken := UsernameToken{Id: "UsernameToken-20", Wsu: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", Username: encrypt.Username, Password: passwordUsernameToken, Nonce: nonceUsernameToken, Created: t.UTC().Format(layout)}
	retval.Header.Security = Security{MustUnderstand: "1", Wsse: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", UsernameToken: userToken}
	return retval
}

func PrintRequest(requestEnvelope *SoapEnvelope) {
	enc := xml.NewEncoder(os.Stdout)
	enc.Indent("  ", "    ")
	if err := enc.Encode(requestEnvelope); err != nil {
		fmt.Printf("error: %v\n", err)
	}
}

type RequestInformation struct {
	BufferOfRequest io.Reader
	Endpoint        string
	SoapAction      string
}

func (requestInfo RequestInformation) GetResponse() *http.Response {
	var resp *http.Response
	var err error //iso-8859-1
	if resp, err = http.Post(requestInfo.Endpoint, "application/soap+xml; charset=\"UTF-8\"; action="+requestInfo.SoapAction, requestInfo.BufferOfRequest); err != nil {
		println(err.Error())
		return nil
	}
	return resp
}

func main() {

	buffer := new(bytes.Buffer) //&bytes.Buffer{}

	var encrypt = Encryption{Username: "LLCALLCENTER", Password: "ae1234"}
	var readBillReptWS = ReadBillReptWS{USER_CODE: "NCCAUSER", GRUP_CODE: "0", CUST_NUMB: "502321581", SUBR_NUMB: "66813020882", GRUP_TYPE: "N", TRNS_PERD: "2013-02", BLPD_INDC: "PCN"}
	requestEnvelope := readBillReptWS.CreateSoapEnvelope(encrypt)

	encoder := xml.NewEncoder(buffer)
	err := encoder.Encode(requestEnvelope)
	if err != nil {
		println("Error encoding document:", err.Error())
		//return
	}

	PrintRequest(requestEnvelope)

	var resp *http.Response

	//http://DTH2732042T01:8088/mockINSaveSpkdAddWS_Binding
	//http://athena13:9582/SaveSpkdAddWS
	var reqInfo = RequestInformation{BufferOfRequest: buffer, Endpoint: "http://10.89.75.44:9582/ReadBillReptWS", SoapAction: "ReadBillReptWS"}
	resp = reqInfo.GetResponse()

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		println("\nSoap Error:", resp.Status)
	}

	//bs, err := ioutil.ReadAll(resp.Body)
	//tr := string(bs)
	//println(tr)

	bodyElement, faultElement, err := DecodeResponseBody(resp.Body)

	var state string
	if err != nil {
		//if strings.ContainsAny(err.Error(), "encoding") {
		//	println("Error decoding: ", err.Error())
		//} else {
		//	println("Error: ", err.Error())
		//}
		state = "error"
		//return
	}

	if faultElement != nil {
		//println("This request is fault but we don't know why. We promise you can know this in the future. See you soon.")
		state = "fault"

		enc := xml.NewEncoder(os.Stdout)
		enc.Indent("  ", "    ")
		if err := enc.Encode(faultElement); err != nil {
			fmt.Printf("error: %v\n", err)
		}
	}

	if bodyElement != nil {
		state = "body"

		//fmt.Printf("\nTux Body: %#v\n", bodyElement)

		enc := xml.NewEncoder(os.Stdout)
		enc.Indent("  ", "    ")
		if err := enc.Encode(bodyElement); err != nil {
			fmt.Printf("error: %v\n", err)
		}

		//println("\n\n", bodyElement.ARTM_TYPE_UNIT[2])

	}

	//return bodyElement, faultElement, err, state
	println(state)
}

func DecodeResponseBody(body io.Reader) (*ReadBillReptWSResponse, *FaultResponse, error) {
	//decoder := xml.NewDecoder(body)

	charset := mahonia.NewDecoder("UTF-8")
	if charset == nil {
		println("panic: UTF-8")
	}

	r := charset.NewReader(body)
	decoder := xml.NewDecoder(r)

	//decoder.CharsetReader = func(charset string, input io.Reader) (io.Reader, error) {
	//	if charset == "TIS-620" {
	//		charset := mahonia.NewDecoder("TIS-620")
	//		rr := charset.NewReader(body)
	//		return rr, nil //transform.NewReader(body, charmap.ISO8859_10.NewDecoder()), nil
	//	}
	//	return nil, fmt.Errorf("unsupported charset: %q", charset)
	//}

	nextElementIsBody := false
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		} else if err != nil {
			println(err.Error())
			return nil, nil, err
		}
		switch startElement := token.(type) {
		case xml.StartElement:
			if nextElementIsBody {
				responseBody := ReadBillReptWSResponse{}
				err = decoder.DecodeElement(&responseBody, &startElement)
				if err != nil {
					responseFault := FaultResponse{}

					err = decoder.DecodeElement(&responseFault, &startElement)
					if err != nil {
						println("decode fault error!")
						return nil, nil, err
					} else {
						return nil, &responseFault, nil
					}

					return nil, nil, err
				}
				return &responseBody, nil, nil
			}
			if startElement.Name.Space == "http://schemas.xmlsoap.org/soap/envelope/" && startElement.Name.Local == "Body" {
				nextElementIsBody = true
			}
		}
	}

	println("Did not find SOAP body element!")
	return nil, nil, errors.New("Did not find SOAP body element")
}
