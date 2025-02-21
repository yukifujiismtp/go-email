// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package email

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"strings"

	"golang.org/x/net/html/charset"
)

// ParseMessage parses and returns a Message from an io.Reader
// containing the raw text of an email message.
// (If the raw email is a string or []byte, use strings.NewReader()
// or bytes.NewReader() to create a reader.)
// Any "quoted-printable" or "base64" encoded bodies will be decoded.
func ParseMessage(r io.Reader) (*Message, error) {
	return ParseMessageWithCID(r, false)
}

// ParseMessageWithCID parses and returns a Message from an io.Reader
// containing the raw text of an email message.
// (If the raw email is a string or []byte, use strings.NewReader()
// or bytes.NewReader() to create a reader.)
// Any "quoted-printable" or "base64" encoded bodies will be decoded.
// If keepCID is true then any base64 CID parts will NOT be decoded.
func ParseMessageWithCID(r io.Reader, keepCID bool) (*Message, error) {
	msg, err := mail.ReadMessage(&leftTrimReader{r: bufioReader(r)})
	if err != nil {
		return nil, err
	}
	
	// decode any Q-encoded values
	for _, values := range msg.Header {
		for idx, val := range values {
			values[idx] = decodeRFC2047(val)
		}
	}
	return parseMessageWithHeaderWithCID(Header(msg.Header), msg.Body, keepCID)
}

// parseMessageWithHeader parses and returns a Message from an already filled
// Header, and an io.Reader containing the raw text of the body/payload.
// (If the raw body is a string or []byte, use strings.NewReader()
// or bytes.NewReader() to create a reader.)
// Any "quoted-printable" or "base64" encoded bodies will be decoded.
func parseMessageWithHeader(headers Header, bodyReader io.Reader) (*Message, error) {
	return parseMessageWithHeaderWithCID(headers, bodyReader, false)
}

// parseMessageWithHeaderWithCID parses and returns a Message from an already filled
// Header, and an io.Reader containing the raw text of the body/payload.
// (If the raw body is a string or []byte, use strings.NewReader()
// or bytes.NewReader() to create a reader.)
// Any "quoted-printable" or "base64" encoded bodies will be decoded.
// If keepCID is true then any base64 CID parts will NOT be decoded.
func parseMessageWithHeaderWithCID(headers Header, bodyReader io.Reader, keepCID bool) (*Message, error) {
	bufferedReader := contentReader(headers, bodyReader, keepCID)

	var err error
	var mediaType string
	var mediaTypeParams map[string]string
	var preamble []byte
	var epilogue []byte
	var body []byte
	var parts []*Message
	var subMessage *Message

	if contentType := headers.Get("Content-Type"); len(contentType) > 0 {
		mediaType, mediaTypeParams, err = mime.ParseMediaType(contentType)
		if err != nil {
			return nil, err
		}
	} // Lack of contentType is not a problem

	// Can only have one of the following: Parts, SubMessage, or Body
	if strings.HasPrefix(mediaType, "multipart") {
		boundary := mediaTypeParams["boundary"]
		preamble, err = readPreamble(bufferedReader, boundary)
		if err == nil {
			parts, err = readParts(bufferedReader, boundary)
			if err == nil {
				epilogue, err = readEpilogue(bufferedReader)
			}
		}

	} else if strings.HasPrefix(mediaType, "message") {
		subMessage, err = ParseMessage(bufferedReader)

	} else {
		body, err = ioutil.ReadAll(bufferedReader)
	}
	if err != nil {
		return nil, err
	}

	return &Message{
		Header:     headers,
		Preamble:   preamble,
		Epilogue:   epilogue,
		Body:       body,
		SubMessage: subMessage,
		Parts:      parts,
	}, nil
}

// readParts parses out the parts of a multipart body, including the preamble and epilogue.
func readParts(bodyReader io.Reader, boundary string) ([]*Message, error) {

	parts := make([]*Message, 0, 1)
	multipartReader := multipart.NewReader(bodyReader, boundary)

	for {

		part, partErr := multipartReader.NextPart()

		// fmt.Println("\n\n----------------------------------------------------------------------------------------")
		// fmt.Printf("READ PART: %s, %s\n", part, partErr)
		// fmt.Println("----------------------------------------------------------------------------------------\\n")

		// break on error, parsing broken stuff is bad
		// but don't want to lose all the parts we have parsed
		if partErr == io.EOF || partErr != nil {
			break
		}

		// if there's no error give parsing a go
		newEmailPart, msgErr := parseMessageWithHeader(Header(part.Header), part)
		part.Close()
		if msgErr != nil {
			continue
		}
		parts = append(parts, newEmailPart)
	}

	return parts, nil
}

// readEpilogue ...
func readEpilogue(r io.Reader) ([]byte, error) {
	epilogue, err := ioutil.ReadAll(r)
	for len(epilogue) > 0 && isASCIISpace(epilogue[len(epilogue)-1]) {
		epilogue = epilogue[:len(epilogue)-1]
	}
	if len(epilogue) > 0 {
		return epilogue, err
	}
	return nil, err
}

// readPreamble ...
func readPreamble(r *bufio.Reader, boundary string) ([]byte, error) {
	preamble, err := ioutil.ReadAll(&preambleReader{r: r, boundary: []byte("--" + boundary)})
	if len(preamble) > 0 {
		return preamble, err
	}
	return nil, err
}

// preambleReader ...
type preambleReader struct {
	r        *bufio.Reader
	boundary []byte
}

// Read ...
func (r *preambleReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	// Peek and read up to the --boundary, then EOF
	peek, err := r.r.Peek(len(p))
	if err != nil && err != io.EOF {
		return 0, fmt.Errorf("Preamble Read: %v", err)
	}

	idx := bytes.Index(peek, r.boundary)

	if idx < 0 {
		// Couldn't find the boundary, so read all the bytes we can,
		// but leave room for a new-line + boundary that got cut in half by the buffer,
		// that way it can be matched against on the next read
		return r.r.Read(p[:max(1, len(peek)-(len(r.boundary)+2))])
	}

	// Account for possible new-line / whitespace at start of the boundary, which shouldn't be removed
	for idx > 0 && isASCIISpace(peek[idx-1]) {
		idx--
	}

	if idx == 0 {
		// The boundary (or new-line + boundary) is at the start of the reader, so there is no preamble
		return 0, io.EOF
	}

	n, err := r.r.Read(p[:idx])
	if err != nil && err != io.EOF {
		return n, err
	}
	return n, io.EOF
}

/**
 * Create a charset reader based on content type and return
 * either a wrap reader or the base reader
 */
func create_charset_reader(headers Header, baseReader io.Reader) io.Reader {

	// check to see if the content-type headers have != charset=utf-8
	var encReader io.Reader
	_, ct_headers, err := headers.ContentType()
	if err != nil {
		return baseReader
	}

	// check if charset is found and isn't utf-8
	cset, found := ct_headers["charset"]
	if found && cset != "utf-8" {
		encReader, err = charset.NewReaderLabel(cset, baseReader)
		if err != nil {
			return baseReader
		}
		return encReader
	}
	return baseReader
}

// contentReader ...
func contentReader(headers Header, bodyReader io.Reader, keepCID bool) *bufio.Reader {

	// clone the bodyReader data off, bufio.NewReader seems to mutate the underlying io.Reader
	encoded_bytes, _ := ioutil.ReadAll(bodyReader)
	var decoded_bytes []byte
	var err error

	// if quote-printable - attempt to create a decode reader and test it by peeking
	if headers.Get("Content-Transfer-Encoding") == "quoted-printable" {
		headers.Del("Content-Transfer-Encoding")
		decReader := quotedprintable.NewReader(bytes.NewReader(encoded_bytes))
		decoded_bytes, err = ioutil.ReadAll(decReader)
		if err != nil {
			return bufioReader(create_charset_reader(headers, bytes.NewReader(encoded_bytes)))
		}
		return bufioReader(create_charset_reader(headers, bytes.NewReader(decoded_bytes)))
	}

	// if base64 - attempt to create a decode reader and test it by peeking
	// Email main content shouldn't be decoded.
	// https://app.asana.com/0/180260827951492/1182014187881601/f
	// https://app.asana.com/0/180260827951492/1203347566199487/f
	if headers.Get("Content-Transfer-Encoding") == "base64" &&
		!strings.Contains(headers.Get("Content-Type"), "text/plain") &&
		!strings.Contains(headers.Get("Content-Type"), "text/html") &&
		!keepCID {
		headers.Del("Content-Transfer-Encoding")
		decReader := base64.NewDecoder(base64.StdEncoding, bytes.NewReader(encoded_bytes))
		decoded_bytes, err = ioutil.ReadAll(decReader)
		if err != nil {
			return bufioReader(create_charset_reader(headers, bytes.NewReader(encoded_bytes)))
		}
		return bufioReader(create_charset_reader(headers, bytes.NewReader(decoded_bytes)))
	}

	// just wrap the reader in a charset_decoder
	return bufioReader(create_charset_reader(headers, bytes.NewReader(encoded_bytes)))
}

// decodeRFC2047 ...
func decodeRFC2047(header string) (out string) {

	var err error
	dec := new(mime.WordDecoder)
	dec.CharsetReader = func(cset string, input io.Reader) (io.Reader, error) {
		encReader, err := charset.NewReaderLabel(cset, input)
		if err != nil {
			return input, nil
		}
		return encReader, nil
	}
	out, err = dec.DecodeHeader(header)
	if err != nil {
		return header
	}
	return
}
