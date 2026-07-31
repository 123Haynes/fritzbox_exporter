// Package lua_client implementes client for fritzbox lua UI API
package lua_client

// Copyright 2020 Andreas Krebs
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

// SessionInfo XML from login_sid.lua
type SessionInfo struct {
	SID       string `xml:"SID"`
	Challenge string `xml:"Challenge"`
	BlockTime int    `xml:"BlockTime"`
	Rights    string `xml:"Rights"`
}

// LuaSession for storing connection data and SID
type LuaSession struct {
	BaseURL     string
	Username    string
	Password    string
	SID         string
	ApiVer      string
	Client      http.Client
	SessionInfo SessionInfo
}

// LuaPage identified by path and params
type LuaPage struct {
	Path   string
	Params string
}

// LuaMetricValueDefinition definition for a single metric
type LuaMetricValueDefinition struct {
	Path    string
	Key     string
	OkValue string
	Labels  []string
}

// LuaMetricValue single value retrieved from lua page
type LuaMetricValue struct {
	Name   string
	Value  float64
	Labels map[string]string
}

// LabelRename regex to replace labels to get rid of translations
type LabelRename struct {
	Pattern regexp.Regexp
	Name    string
}

// regex to remove leading/trailing characters from numbers
var (
	regexNonNumberEnd = regexp.MustCompile(`\D+$`)
)

func (lua *LuaSession) v2Login(response string) error {
	logrus.Debugln("using LoginApi v2")
	res := url.Values{}
	res.Set("username", lua.Username)
	res.Set("response", response)
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/login_sid.lua?version=2", lua.BaseURL), strings.NewReader(res.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	if err != nil {
		return fmt.Errorf("error forming request: %s", err.Error())
	}

	return lua.doLogin(req)
}

func (lua *LuaSession) v1Login(response string) error {
	logrus.Debugln("using LoginApi v1")
	urlParams := fmt.Sprintf("?response=%s&user=%s", response, lua.Username)
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/login_sid.lua%s", lua.BaseURL, urlParams), nil)
	if err != nil {
		return fmt.Errorf("error forming request: %s", err.Error())
	}

	return lua.doLogin(req)
}

func (lua *LuaSession) doLogin(req *http.Request) error {
	resp, err := lua.Client.Do(req)
	if err != nil {
		return fmt.Errorf("error calling login_sid.lua: %s", err.Error())
	}

	defer resp.Body.Close()
	dec := xml.NewDecoder(resp.Body)

	err = dec.Decode(&lua.SessionInfo)
	if err != nil {
		return fmt.Errorf("error decoding SessionInfo: %s", err.Error())
	}

	if lua.SessionInfo.BlockTime > 0 {
		return fmt.Errorf("too many failed logins, login blocked for %d seconds", lua.SessionInfo.BlockTime)
	}
	return nil
}

func (lua *LuaSession) initLogin() error {
	var version string
	switch lua.ApiVer {
	case "v1":
		version = ""
	case "v2":
		version = "?version=2"
	}

	resp, err := http.Get(fmt.Sprintf("%s/login_sid.lua%s", lua.BaseURL, version))
	if err != nil {
		return fmt.Errorf("error calling login_sid.lua: %s", err.Error())
	}
	defer resp.Body.Close()
	dec := xml.NewDecoder(resp.Body)

	err = dec.Decode(&lua.SessionInfo)
	if err != nil {
		return fmt.Errorf("error decoding SessionInfo: %s", err.Error())
	}

	if lua.SessionInfo.BlockTime > 0 {
		return fmt.Errorf("too many failed logins, login blocked for %d seconds", lua.SessionInfo.BlockTime)
	}
	return nil
}

func (lmvDef *LuaMetricValueDefinition) createValue(name string, value float64) LuaMetricValue {
	lmv := LuaMetricValue{
		Name:   name,
		Value:  value,
		Labels: make(map[string]string),
	}

	return lmv
}

// Login perform loing and get SID
func (lua *LuaSession) Login() error {
	err := lua.initLogin()
	if err != nil {
		return err
	}

	challenge := lua.SessionInfo.Challenge
	if lua.SessionInfo.SID == "0000000000000000" && challenge != "" {
		switch lua.ApiVer {
		case "v1":
			// no SID, but challenge so calc response
			hash := utf16leMd5(fmt.Sprintf("%s-%s", challenge, lua.Password))
			response := fmt.Sprintf("%s-%x", challenge, hash)
			err := lua.v1Login(response)
			if err != nil {
				return err
			}
		case "v2":
			response := calculatePbkdf2Response(challenge, lua.Password)
			err := lua.v2Login(response)
			if err != nil {
				return err
			}
		}
	}

	sid := lua.SessionInfo.SID
	if sid == "0000000000000000" || sid == "" {
		return errors.New("LUA login failed - no SID received - check username and password")
	}

	lua.SID = sid

	return nil
}

// LoadData load a lua bage and return content
func (lua *LuaSession) LoadData(page LuaPage) ([]byte, error) {
	method := "POST"
	path := page.Path

	// handle method prefix
	pathParts := strings.SplitN(path, ":", 2)
	if len(pathParts) > 1 {
		method = pathParts[0]
		path = pathParts[1]
	}

	dataURL := fmt.Sprintf("%s/%s", lua.BaseURL, path)

	callDone := false
	var resp *http.Response
	var err error
	retries := 0
	for !callDone {
		// perform login if no SID or previous call failed with (403)
		if lua.SID == "" || resp != nil {
			err = lua.Login()
			callDone = true // consider call done, since we tried login

			if err != nil {
				return nil, err
			}
		}

		// send by UI for data.lua: xhr=1&sid=xxxxxxx&lang=de&page=energy&xhrId=all&no_sidrenew=
		// but SID and page seem to be enough
		params := "sid=" + lua.SID
		if page.Params != "" {
			params += "&" + page.Params
		}

		if method == "POST" {
			resp, err = http.Post(dataURL, "application/x-www-form-urlencoded", bytes.NewBuffer([]byte(params)))
		} else if method == "GET" {
			resp, err = http.Get(dataURL + "?" + params)
		} else {
			err = fmt.Errorf("method %s is unsupported in path %s", method, page.Path)
		}

		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			callDone = true
		} else if resp.StatusCode == http.StatusForbidden && !callDone {
			// we assume SID is expired, so retry login
		} else if retries < 1 {
			// unexpected error let's retry (reboot issue ?)
		} else {
			return nil, fmt.Errorf("%s failed: %s", page.Path, resp.Status)
		}

		retries++
	}

	body, err := io.ReadAll(resp.Body)

	if err != nil {
		return nil, err
	}

	return body, nil
}

// ParseJSON generic parser for unmarshalling into map
func ParseJSON(jsonData []byte) (map[string]interface{}, error) {
	var data map[string]interface{}

	// Unmarshal or Decode the JSON to the interface.
	json.Unmarshal(jsonData, &data)

	return data, nil
}

func getRenamedLabel(labelRenames *[]LabelRename, label string) string {
	if labelRenames != nil {
		for _, lblRen := range *labelRenames {
			if lblRen.Pattern.MatchString(label) {
				return lblRen.Name
			}
		}
	}

	return label
}

func getValueFromHashOrArray(mapOrArray interface{}, key string, path string) (interface{}, error) {
	var value interface{}

	switch moa := mapOrArray.(type) {
	case map[string]interface{}:
		var exists bool
		value, exists = moa[key]
		if !exists {
			return nil, fmt.Errorf("hash '%s' has no element '%s'", path, key)
		}
	case []interface{}:
		// since type is array there can't be any labels to differentiate values, so only one value supported !
		index, err := strconv.Atoi(key)
		if err != nil {
			return nil, fmt.Errorf("item '%s' is an array, but index '%s' is not a number", path, key)
		}

		if index < 0 {
			// this is an index from the end of the values
			index += len(moa)
		}

		if index < 0 || index >= len(moa) {
			return nil, fmt.Errorf("index %d is invalid for array '%s' with length %d", index, path, len(moa))
		}
		value = moa[index]
	default:
		return nil, fmt.Errorf("item '%s' is not a hash or array, can't get value %s", path, key)
	}

	return value, nil
}

// GetMetrics get metrics from parsed lua page for definition and rename labels
func GetMetrics(labelRenames *[]LabelRename, data map[string]interface{}, metricDef LuaMetricValueDefinition) ([]LuaMetricValue, error) {

	var values []interface{}
	var err error
	if metricDef.Path != "" {
		pathItems := strings.Split(metricDef.Path, ".")
		values, err = _getValues(data, pathItems, "")
		if err != nil {
			return nil, err
		}
	} else {
		values = make([]interface{}, 1)
		values[0] = data
	}

	metrics := make([]LuaMetricValue, 0)
	keyItems := strings.Split(metricDef.Key, ".")

VALUE:
	for _, pathVal := range values {
		valUntyped := pathVal
		path := metricDef.Path

		// now handle if key is also splitted
		for _, key := range keyItems {
			valUntyped, err = getValueFromHashOrArray(valUntyped, key, path)
			if err != nil {
				// since we may have other values, we simply continue (should we report it?)
				continue VALUE
			}

			if path != "" {
				path += "."
			}
			path += key
		}

		var sVal = toString(valUntyped)
		var floatVal float64
		if metricDef.OkValue != "" {
			if metricDef.OkValue == sVal {
				floatVal = 1
			} else {
				floatVal = 0
			}
		} else {
			// convert value to float, but first remove all non numbers from begin or end of value
			// needed if value contains unit
			sNum := regexNonNumberEnd.ReplaceAllString(sVal, "")

			floatVal, err = strconv.ParseFloat(sNum, 64)
			if err != nil {
				continue VALUE
			}
		}

		// create metric value
		lmv := metricDef.createValue(path, floatVal)

		// add labels if pathVal is a hash
		valMap, isType := pathVal.(map[string]interface{})
		if isType {
			for _, l := range metricDef.Labels {
				lv, exists := valMap[l]
				if exists {
					lmv.Labels[l] = getRenamedLabel(labelRenames, toString(lv))
				}
			}
		}

		metrics = append(metrics, lmv)
	}

	if len(metrics) == 0 {
		if err == nil {
			// normal we should already have an error, this is just a fallback
			err = fmt.Errorf("no value found for item '%s' with key '%s'", metricDef.Path, metricDef.Key)
		}
		return nil, err
	}

	return metrics, nil
}

// from https://stackoverflow.com/questions/33710672/golang-encode-string-utf16-little-endian-and-hash-with-md5
func utf16leMd5(s string) []byte {
	enc := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder()
	hasher := md5.New()
	t := transform.NewWriter(hasher, enc)
	t.Write([]byte(s))
	return hasher.Sum(nil)
}

// v2 authentication according to https://avm.de/fileadmin/user_upload/Global/Service/Schnittstellen/AVM_Technical_Note_-_Session_ID_english_2021-05-03.pdf
func calculatePbkdf2Response(challenge, password string) string {
	challengeParts := strings.Split(challenge, "$")
	iter1, _ := strconv.Atoi(challengeParts[1])
	iter2, _ := strconv.Atoi(challengeParts[3])
	salt1, _ := hex.DecodeString(challengeParts[2])
	salt2, _ := hex.DecodeString(challengeParts[4])
	hash1_raw := pbkdf2.Key([]byte(password), salt1, iter1, 32, sha256.New)
	hash2_raw := pbkdf2.Key(hash1_raw, salt2, iter2, 32, sha256.New)
	hash2 := hex.EncodeToString(hash2_raw)
	raw := fmt.Sprintf("%s$%s", challengeParts[4], hash2)
	return raw
}

// helper for retrieving values from parsed JSON
func _getValues(data interface{}, pathItems []string, parentPath string) ([]interface{}, error) {

	var err error
	values := make([]interface{}, 0)
	value := data
	curPath := parentPath

	for i, p := range pathItems {
		if p == "*" {
			// handle * case to get all values
			var subvals []interface{}
			switch vv := value.(type) {
			case []interface{}:
				for index, u := range vv {
					subvals, err = _getValues(u, pathItems[i+1:], fmt.Sprintf("%s.%d", curPath, index))

					if subvals != nil {
						values = append(values, subvals...)
					}
				}
			case map[string]interface{}:
				for subK, subV := range vv {
					subvals, err = _getValues(subV, pathItems[i+1:], fmt.Sprintf("%s.%s", curPath, subK))

					if subvals != nil {
						values = append(values, subvals...)
					}
				}
			default:
				err = fmt.Errorf("item '%s' is neither a hash or array", curPath)
			}

			if len(values) == 0 {
				if err == nil {
					err = fmt.Errorf("item '%s.*' has no values", curPath)
				}

				return nil, err
			}

			return values, nil
		}

		// this is a single value
		value, err = getValueFromHashOrArray(value, p, curPath)
		if err != nil {
			return nil, err
		}

		if curPath == "" {
			curPath = p
		} else {
			curPath += "." + p
		}
	}

	values = append(values, value)

	return values, nil
}

func toString(value interface{}) string {
	// should we better check or simple convert everything ????
	return fmt.Sprintf("%v", value)
}
