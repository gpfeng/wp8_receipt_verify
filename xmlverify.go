// refernces:
//   https://code.msdn.microsoft.com/windowsapps/In-app-purchase-receipt-c3e0bce4
//   https://github.com/amdonov/xmlsig
//   http://seepiagames.blogspot.com/2013/10/cloud-service-windows-phone-application.html
//   https://code.google.com/p/go/issues/detail?id=8265

package main

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"sort"
)

const DIGEST_VALUE_TAG = "DigestValue"
const SIGNATURE_VALUE_TAG = "SignatureValue"
const SIGNATURE_TAG = "Signature"
const SIGNEDINFO_TAG = "SignedInfo"
const SIGNEDINFO_XMLNS = "http://www.w3.org/2000/09/xmldsig#"

// Taken largely from an example in "Programming In Go"
// Keeping it separate from my stuff
type stack []interface{}

func (s *stack) Len() int {
	return len(*s)
}

func (s *stack) Push(x interface{}) {
	*s = append(*s, x)
}

func (s *stack) Top() (interface{}, error) {
	if len(*s) == 0 {
		return nil, errors.New("Empty stack")
	}
	return (*s)[s.Len()-1], nil
}

func (s *stack) Pop() (interface{}, error) {
	theStack := *s
	if len(theStack) == 0 {
		return nil, errors.New("Empty stack")
	}
	x := theStack[len(theStack)-1]
	*s = theStack[:len(theStack)-1]
	return x, nil
}

type canonAtt []xml.Attr

func (att canonAtt) Len() int {
	return len(att)
}

func (att canonAtt) Swap(i, j int) {
	att[i], att[j] = att[j], att[i]
}

func (att canonAtt) Less(i, j int) bool {
	iName := att[i].Name.Local
	jName := att[j].Name.Local
	if iName == "xmlns" {
		return true
	}
	if jName == "xmlns" {
		return false
	}
	return att[i].Name.Local < att[j].Name.Local
}

// An XML Signature.
type Signature struct {
	XMLName        xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# Signature"`
	SignedInfo     SignedInfo
	SignatureValue string `xml:"http://www.w3.org/2000/09/xmldsig# SignatureValue"`
	KeyInfo        KeyInfo
}

// An algorithm used when creating the signature.
type Algorithm struct {
	Algorithm string `xml:",attr"`
}

// Information about the Signature used for verification.
type SignedInfo struct {
	XMLName                xml.Name  `xml:"http://www.w3.org/2000/09/xmldsig# SignedInfo"`
	CanonicalizationMethod Algorithm `xml:"http://www.w3.org/2000/09/xmldsig# CanonicalizationMethod"`
	SignatureMethod        Algorithm `xml:"http://www.w3.org/2000/09/xmldsig# SignatureMethod"`
	Reference              Reference
}

// Reference to the signed node.
type Reference struct {
	XMLName      xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# Reference"`
	URI          string   `xml:",attr,omitempty"`
	Transforms   Transforms
	DigestMethod Algorithm `xml:"http://www.w3.org/2000/09/xmldsig# DigestMethod"`
	DigestValue  string    `xml:"http://www.w3.org/2000/09/xmldsig# DigestValue"`
}

// Transforms applied that should be applied to the document prior to signature verification.
type Transforms struct {
	XMLName   xml.Name    `xml:"http://www.w3.org/2000/09/xmldsig# Transforms"`
	Transform []Algorithm `xml:"http://www.w3.org/2000/09/xmldsig# Transform"`
}

type KeyInfo struct {
	XMLName  xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
	X509Data X509Data
}

type X509Data struct {
	XMLName         xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# X509Data"`
	X509Certificate string   `xml:"http://www.w3.org/2000/09/xmldsig# X509Certificate"`
}

func digestBase64(data string) string {
    return base64.StdEncoding.EncodeToString(digest(data))
}

func digest(data string) []byte {
	h := sha256.New()
	h.Write([]byte(data))
	return h.Sum(nil)
}

func ParseAndCanonicalizeXml(xmlstring string) (string, string, string, string, error) {

	// write xml string to a buffer
	var buffer, out bytes.Buffer
	writer := bufio.NewWriter(&buffer)
    writer.Write([]byte(xmlstring))
    writer.Flush()

	// read from the buffer
	decoder := xml.NewDecoder(bytes.NewReader(buffer.Bytes()))
	outWriter := bufio.NewWriter(&out)

    charData := ""
    tagStart := false
	stack := &stack{}

    digestValue := ""
    signatureValue := ""
    signatureTagStart := -1
    signatureTagEnd := -1
    signedinfoTagStart := -1
    signedinfoTagEnd := -1

	writeStartElement := func(writer io.Writer, start xml.StartElement) {
		fmt.Fprintf(writer, "<%s", start.Name.Local)
		sort.Sort(canonAtt(start.Attr))
		currentNs, err := stack.Top()
		if err != nil {
			// No namespaces yet declare ours
			fmt.Fprintf(writer, " %s=\"%s\"", "xmlns", start.Name.Space)
		} else {
			// Different namespace declare ours
			if currentNs != start.Name.Space {
				fmt.Fprintf(writer, " %s=\"%s\"", "xmlns", start.Name.Space)
			}
            // inhiret tag Signature's namespace for SignedInfo
            // just for conveniance...
            if start.Name.Local == SIGNEDINFO_TAG {
                fmt.Fprintf(writer, " %s=\"%s\"", "xmlns", SIGNEDINFO_XMLNS)
            }
		}

		stack.Push(start.Name.Space)
		for i := range start.Attr {
			if "xmlns" != start.Attr[i].Name.Local {
				fmt.Fprintf(writer, " %s=\"%s\"", start.Attr[i].Name.Local, start.Attr[i].Value)
			}
		}
		fmt.Fprint(writer, ">")
	}

    // parse xml token
	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}

		switch t := token.(type) {
		case xml.StartElement:
            if t.Name.Local == SIGNATURE_TAG {
                // .<Signature
                outWriter.Flush()
                signatureTagStart = out.Len()
            } else if t.Name.Local == SIGNEDINFO_TAG {
                // .<SignedInfo
                outWriter.Flush()
                signedinfoTagStart = out.Len()
            }
			writeStartElement(outWriter, t)
            charData = ""
            tagStart = true

		case xml.EndElement:
            if charData != "" {
                outWriter.Write([]byte(charData))
                if t.Name.Local == DIGEST_VALUE_TAG {
                    digestValue = charData
                }
                if t.Name.Local == SIGNATURE_VALUE_TAG {
                    signatureValue = charData
                }
            }
            charData = ""
            tagStart = false

			stack.Pop()
			fmt.Fprintf(outWriter, "</%s>", t.Name.Local)

            if t.Name.Local == SIGNATURE_TAG {
                // </Signature>.
                outWriter.Flush()
                signatureTagEnd = out.Len()
            } else if t.Name.Local == SIGNEDINFO_TAG {
                // </SignedInfo>.
                outWriter.Flush()
                signedinfoTagEnd = out.Len()
            }

		case xml.CharData:
            if tagStart {
                charData = string(t)
            }
		}
	}

    // the whole xml
	outWriter.Flush()
    canonicalizeXmlBytes := out.Bytes()

    // ...<Signatrue><SignInfo>...</SignInfo></Signature>
    if signatureTagStart == -1 || signatureTagEnd == -1 || signedinfoTagStart == -1 || signedinfoTagEnd == -1 {
        return "", "", "", "", errors.New(fmt.Sprintf("can't find tag %s or %s", SIGNATURE_TAG, SIGNEDINFO_TAG))
    }
    if digestValue == "" {
        return "", "", "", "", errors.New("can't find digest value")
    }
    if signatureValue == "" {
        return "", "", "", "", errors.New("can't find signature value")
    }

    // extract SignInfo node
    signinfoNodeStr := string(canonicalizeXmlBytes[signedinfoTagStart:signedinfoTagEnd])
    // remove Signature node
    dataNodeStr := string(canonicalizeXmlBytes[:signatureTagStart]) + string(canonicalizeXmlBytes[signatureTagEnd:])

    return dataNodeStr, signinfoNodeStr, digestValue, signatureValue, nil
}

func main() {
    dataStr, signInfoStr, digestStr, signatureStr, err := ParseAndCanonicalizeXml(xmlstring)
    if err != nil {
        fmt.Printf("ParseAndCanonicalizeXml %s failed: %s\n", xmlstring, err.Error())
        return
    }
    fmt.Printf("--data: \n%s\n--signInfo:\n%s\n--digest:\n%s\n--signature:\n%s\n",
        dataStr, signInfoStr, digestStr, signatureStr)
    fmt.Printf("\n--calculated base64 digest: \n%s\n", digestBase64(dataStr))

    bytes, err := ioutil.ReadFile(certFile)
    if err != nil {
        fmt.Printf("read cert file failed: %s\n", err.Error())
        return
    }

    cert, err := MyParseCertificate(bytes)
    if err != nil {
        fmt.Printf("parse certificate failed: %s, cert: %v\n", err.Error(), cert)
        return
    }

    publickey := cert.PublicKey
    pub, ok := publickey.(*rsa.PublicKey)
    if !ok {
        fmt.Printf("invalid rsa publickey: %#v\n", publickey)
        return
    }

    signatureBytes, err := base64.StdEncoding.DecodeString(signatureStr)
    if err != nil {
        fmt.Printf("base64 decode signature failed: %s\n", err.Error())
        return
    }

    err = rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest(signInfoStr), signatureBytes)
    if err != nil {
        fmt.Printf("rsa.VerifyPKCS1v15 failed: %s\n", err.Error())
        return
    }
    fmt.Printf("\nrsa verification passed!\n")
}

const certFile = "IapReceiptProduction.cer"

const xmlstring string =`
<?xml version="1.0"?>
<Receipt Version="1.0" CertificateId="A656B9B1B3AA509EEA30222E6D5E7DBDA9822DCD" xmlns="http://schemas.microsoft.com/windows/2012/store/receipt">
  <ProductReceipt PurchasePrice="$20.89" PurchaseDate="2012-11-30T21:32:07.096Z" Id="2f9c5c8f-3e1d-4fc7-a871-ac58f7e78053" AppId="3ec6cd9a-ca82-4d38-bfdf-ecafdb35a738" ProductId="Test" ProductType="Consumable" PublisherDeviceId="Test" MicrosoftProductId="59ef70aa-7099-4679-889e-f21919bfd2c6" />
  <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
    <SignedInfo>
      <CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315" />
      <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" />
      <Reference URI="">
        <Transforms>
          <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
        </Transforms>
        <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />
        <DigestValue>FyFb1HGm+yeOIjt18M6TPD4Qzeu469vwDbQs7w72mdA=</DigestValue>
      </Reference>
    </SignedInfo>
    <SignatureValue>noct5CYBtRwBxVxkUeZIzeDyruLGVBqBMuFuBytpouPLACnQ5dbzdRvWX4XN67IUo0J2FW8DoYcMbf3sAS+PeKKV8SLnU+l8K1hWEbbbugHZezStTzwwkYcZuCTnAk7BYO0aiZWuXm9GiZGT9iyXsYtU1/u87L+llnVibU/m7gV8tD3vG0tVkjzV20C8666mHUsY/jxeq3ed7YY9CT0SDrh5PeL4ESaopBLcncHo/e6lcjyoKbO3e6YuIpsi8DVueeKNhpTlwa5yc0O3qzc5SGnT4Kbhj9NBEXf15/oTaLlg7lJhnQZ0mY+yR8vc4D0SkqD6e5Uc4u64hnu+g3Hphg==</SignatureValue>
  </Signature>
</Receipt>
`
