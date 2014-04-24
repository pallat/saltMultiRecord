package salt

import (
	"bytes"
	"code.google.com/p/mahonia"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"time"
)

type Tuxedo struct {
	Username  string
	Password  string
	Operation string
}

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

type FaultResponse struct {
	XMLName     xml.Name           `xml:"Fault"`
	Faultcode   string             `xml:"faultcode"`
	Faultstring string             `xml:"faultstring"`
	Detail      *FaultDetailStruct `xml:"detail"`
}

type WSFaultStruct struct {
	XMLName xml.Name      `xml:""`
	Errbuf  *ErrbufStruct `xml:"errbuf"`
}

type ErrbufStruct struct {
	XMLName          xml.Name `xml:"errbuf"`
	MESSAGE_TEXT_ENG string   `xml:"MESSAGE_TEXT_ENG"`
	MESSAGE_TEXT_THA string   `xml:"MESSAGE_TEXT_THA"`
	MESSAGE_SQLCODE  string   `xml:"MESSAGE_SQLCODE"`
	MESSAGE_NATURE   string   `xml:"MESSAGE_NATURE"`
}

type RequestInformation struct {
	BufferOfRequest io.Reader
	Endpoint        string
	Charset         string
	SoapAction      string
}

func (tux Tuxedo) GetEncrypted() string {
	authen := []byte(tux.Username + ":" + tux.Password)
	encPass := &bytes.Buffer{}
	encrypted := base64.NewEncoder(base64.StdEncoding, encPass)
	encrypted.Write(authen)
	encrypted.Close()

	return string(encPass.Bytes())
}

func (tux Tuxedo) IsBasicAuthen() bool {
	isBasicAuthentication := false
	if tux.Username != "" && tux.Password != "" {
		isBasicAuthentication = true
	}

	return isBasicAuthentication
}

func (tux Tuxedo) InsertSoapHeader(soap *SoapEnvelope) {
	if tux.IsBasicAuthen() {
		const layout = "2006-01-02T15:04:05.999Z"
		t := time.Now()
		passwordUsernameToken := PasswordUsernameToken{Password: tux.Password, Type: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText"}
		nonceUsernameToken := NonceUsernameToken{Nonce: tux.GetEncrypted(), EncodingType: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"}
		userToken := UsernameToken{Id: "UsernameToken-20", Wsu: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", Username: tux.Username, Password: passwordUsernameToken, Nonce: nonceUsernameToken, Created: t.UTC().Format(layout)}
		soap.Header.Security = Security{MustUnderstand: "1", Wsse: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", UsernameToken: userToken}
	}
}

func (tux Tuxedo) CreateSoapEnvelope() *SoapEnvelope {
	soapMsg := &SoapEnvelope{}
	soapMsg.SoapEnv = "http://schemas.xmlsoap.org/soap/envelope/"
	soapMsg.Urn = "urn:pack.IN" + tux.Operation + "_typedef.salt11"

	tux.InsertSoapHeader(soapMsg)

	return soapMsg
}

func (requestInfo RequestInformation) GetResponse() *http.Response {
	var resp *http.Response
	var err error
	if resp, err = http.Post(requestInfo.Endpoint, "application/soap+xml; charset="+requestInfo.Charset+"; action="+requestInfo.SoapAction, requestInfo.BufferOfRequest); err != nil {
		println(err.Error())
		return nil
	}
	return resp
}

func (requestInfo RequestInformation) DecodeResponseBody(body io.Reader) (*SaltResponse, error) {
	charset := mahonia.NewDecoder(requestInfo.Charset)
	if charset == nil {
		return nil, errors.New("charset is null.")
	}

	r := charset.NewReader(body)
	decoder := xml.NewDecoder(r)

	decoder.CharsetReader = CharsetReader

	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		switch startElement := token.(type) {
		case xml.StartElement:
			if startElement.Name.Space == "http://schemas.xmlsoap.org/soap/envelope/" && startElement.Name.Local == "Body" {
				//nextElementIsBody = true
				responseBody := SaltResponse{}
				err = decoder.DecodeElement(&responseBody, &startElement)

				if err != nil {

					return nil, err

				}
				return &responseBody, nil
			}
		}
	}

	return nil, errors.New("Did not find SOAP body element")
}

// -----> Dynamic Structure <----- //

type SoapBody struct {
	ReadBillReptWS *ReadBillReptWSRequest `xml:ReadBillReptWS",omitempty"`
	SaveSpkdAddWS  *SaveSpkdAddWSRequest  `xml:SaveSpkdAddWS",omitempty"`
}

type FaultDetailStruct struct {
	XMLName             xml.Name       `xml:"detail"`
	ReadBillReptWSFault *WSFaultStruct `xml:"ReadBillReptWSFault,omitempty"`
	SaveSpkdAddWSFault  *WSFaultStruct `xml:"SaveSpkdAddWSFault,omitempty"`
}

type SaltResponse struct {
	XMLName                xml.Name                `xml:"Body"`
	FaultResponse          *FaultResponse          `xml:"Fault,omitempty"`
	ReadBillReptWSResponse *ReadBillReptWSResponse `xml:"ReadBillReptWSResponse,omitempty"`
	SaveSpkdAddWSResponse  *SaveSpkdAddWSResponse  `xml:"SaveSpkdAddWSResponse,omitempty"`
}

type ReadBillReptWSRequest struct {
	XMLName   xml.Name `xml:"ReadBillReptWS"`
	USER_CODE string   `xml:"urn:inbuf>USER_CODE,omitempty"`
	GRUP_CODE string   `xml:"urn:inbuf>GRUP_CODE,omitempty"`
	CUST_NUMB string   `xml:"urn:inbuf>CUST_NUMB,omitempty"`
	SUBR_NUMB string   `xml:"urn:inbuf>SUBR_NUMB,omitempty"`
	GRUP_TYPE string   `xml:"urn:inbuf>GRUP_TYPE,omitempty"`
	TRNS_PERD string   `xml:"urn:inbuf>TRNS_PERD,omitempty"`
	BLPD_INDC string   `xml:"urn:inbuf>BLPD_INDC,omitempty"`
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

type SaveSpkdAddWSRequest struct {
	XMLName                xml.Name `xml:"SaveSpkdAddWS"`
	USER_CODE              string   `xml:"urn:inbuf>USER_CODE"`
	BLPD_INDC              string   `xml:"urn:inbuf>BLPD_INDC"`
	CS_SPKD_PCN__CUST_NUMB string   `xml:"urn:inbuf>CS_SPKD_PCN__CUST_NUMB"`
	CS_SPKD_PCN__SUBR_NUMB string   `xml:"urn:inbuf>CS_SPKD_PCN__SUBR_NUMB"`
	CS_SPKD_PCN__PACK_CODE string   `xml:"urn:inbuf>CS_SPKD_PCN__PACK_CODE"`
	//CS_SUBR_PCN__SUBR_TYPE string   `xml:"urn:inbuf>CS_SUBR_PCN__SUBR_TYPE"`
	RD_TELP__TELP_TYPE string `xml:"urn:inbuf>RD_TELP__TELP_TYPE"`
	SAVE_FLAG          string `xml:"urn:inbuf>SAVE_FLAG"`
}

type SaveSpkdAddWSResponse struct {
	XMLName                      xml.Name `xml:"SaveSpkdAddWSResponse"`
	CS_SPKD_PCN__PACK_CODE       string   `xml:"outbuf>CS_SPKD_PCN__PACK_CODE"`
	CS_PKPL_PCN__PACK_DESC       string   `xml:"outbuf>CS_PKPL_PCN__PACK_DESC"`
	CS_PACK_TYPE__PACK_TYPE_DESC string   `xml:"outbuf>CS_PACK_TYPE__PACK_TYPE_DESC"`
	CS_SPKD_PCN__PACK_STRT_DTTM  string   `xml:"outbuf>CS_SPKD_PCN__PACK_STRT_DTTM"`
	CS_SPKD_PCN__PACK_END_DTTM   string   `xml:"outbuf>CS_SPKD_PCN__PACK_END_DTTM"`
	CS_SPKD_PCN__DISC_CODE       string   `xml:"outbuf>CS_SPKD_PCN__DISC_CODE"`
	TBL_OCCR                     string   `xml:"outbuf>TBL_OCCR"`
}
