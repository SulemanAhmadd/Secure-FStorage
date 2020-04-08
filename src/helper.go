package main

import (
	"os"
	"io"
	"fmt"
	"bytes"
	"regexp"
	"errors"
	"unicode"
	"strings"
	"net/http"
	"io/ioutil"
	"crypto/cipher"
	"crypto/aes"
	"crypto/rand"
	"database/sql"
)

/* * * * * * * * * * * * * GLOBAL VARIABLES AND STRUCTS * * * * * * * * * * * * */
const UPLOAD_PATH string = "Data"
const MAX_UPLOAD_SIZE = 5 * 1024 * 1024 // 5 MB

const UNAUTHORIZED int = 0
const BAD_REQUEST int = 1
const SERVER_ERR int = 2
const VALID_SESS int = 3

type JSON_Auth struct {
	Password string
	Username string
	RepeatPW string
}

type DB_Auth struct {
	Password string `db:"password"`
	Username string `db:"username"`
	Keysalt string `db:"key_salt"`
	Filnames string `db:"filepaths"`
}

const PW_REQ = `Error: Passwords must satisfy the following criteria:
		   * Must have minimum length of 7 charatcers;
		   * Must have atleast one upper case character;
		   * Must have atleast one lower case character;
		   * Must have atleast one numeric;`

const NAME_REQ = `Error: Username can only have alphanumeric characters`
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */



/* * * * * * * * * * * * USER INPUT VALIDATION METHODS * * * * * * * * * * * * */

// Validate if username format is correct
func validate_username(s string) (bool, string) {
	match_str, _ := regexp.MatchString("^[a-zA-Z0-9_]*$", s)
	result := (len(s) > 0) && match_str

	if result {
		return true, ""
	} else {
		return false, NAME_REQ
	}
}

// Validate password policy criteria is met
func validate_password(s string) (bool, string) {
    var (
        hasMinLen  = false
        hasUpper   = false
        hasLower   = false
        hasNumber  = false
    )
    if len(s) >= 7 {
        hasMinLen = true
    }
    for _, char := range s {
        switch {
        case unicode.IsUpper(char):
            hasUpper = true
        case unicode.IsLower(char):
            hasLower = true
        case unicode.IsNumber(char):
            hasNumber = true
        }
    }
    result := hasMinLen && hasUpper && hasLower && hasNumber

    if result {
    	return true, ""
    } else {
    	return false, PW_REQ
    }
}

// Validate if filename format is correct
func validate_filename(s string) (bool, string) {
	match_str, _ := regexp.MatchString(`^[a-zA-Z0-9_\-.(),]+$`, s)
	result := (len(s) > 0) && match_str

	if result {
		return true, ""
	} else {
		return false, "Error: INVALID FILENAME FORMAT!"
	}
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */



/* * * * * * * * * * * HELPERS FOR FETCHING POSTFRES ARRAYS * * * * * * * * * * * */

// Constructing REGEX for parsing postgres arrays
var (
	// unquoted array values must not contain: (" , \ { } whitespace NULL)
	// and must be at least one char
	unquotedChar  = `[^",\\{}\s(NULL)]`
	unquotedValue = fmt.Sprintf("(%s)+", unquotedChar)

	// quoted array values are surrounded by double quotes, can be any
	// character except " or \, which must be backslash escaped:
	quotedChar  = `[^"\\]|\\"|\\\\`
	quotedValue = fmt.Sprintf("\"(%s)*\"", quotedChar)

	// an array value may be either quoted or unquoted:
	arrayValue = fmt.Sprintf("(?P<value>(%s|%s))", unquotedValue, quotedValue)

	// Array values are separated with a comma IF there is more than one value:
	arrayExp = regexp.MustCompile(fmt.Sprintf("((%s)(,)?)", arrayValue))

	valueIndex int
)

// New type declaration
type StringSlice []string

// Implements sql.Scanner for the string slice type
func (s *StringSlice) Scan(src interface{}) error {
	asBytes, ok := src.([]byte)
	if !ok {
		return error(errors.New("Scan source was not []bytes"))
	}

	asString := string(asBytes)
	parsed := parseArray(asString)
	(*s) = StringSlice(parsed)

	return nil
}

// Parse the output string from the array type
func parseArray(array string) []string {

	results := make([]string, 0)
	matches := arrayExp.FindAllStringSubmatch(array, -1)
	for _, match := range matches {
		s := match[valueIndex]
		s = strings.Trim(s, "\"")
		s = strings.Trim(s, ",")
		results = append(results, s)
	}
	return results
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */



/* * * * * * * * * * * DATABASE MODIFIER METHODS * * * * * * * * * * * * * * * */

// Insert a new filename in DB for a particular user
func append_filename_db(db *sql.DB, username string, filename string) (error) {
	_, err := db.Exec("update users set filepaths = ARRAY_APPEND(filepaths, $1) where username=$2", filename, username)
	if err != nil {
		return err
	}

	return nil
}

// Get all the file names of the user from DB
func get_filenames(db *sql.DB, username string) (StringSlice, error) {
	row := db.QueryRow("select filepaths from users where username=$1", username)
	var asSlice StringSlice
	err := row.Scan(&asSlice)
	if err != nil {
		return asSlice, err
	}

	return asSlice, nil
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */



/* * * * * * * * * * * ENCRYPT/DECRYPT HANDLERS * * * * * * * * * * * * * * * */

// Encrypts a file and stores on filesystem
func encrypt_and_store(filename string, data []byte, encryption_key string) (error) {

	encrypted_data, enc_err := encrypt(data, []byte(encryption_key))
	if enc_err != nil {
		return enc_err
	}

	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	f.Write(encrypted_data)

	return nil
}

// Encrypts input byte data stream
func encrypt(data []byte, encryption_key []byte) ([]byte, error) {
	block, _ := aes.NewCipher(encryption_key)
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return []byte(""), err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return []byte(""), err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// Decrypts a file and returns io.Reader handler
func decrypt_and_retrieve(filename string, encryption_key string) (*bytes.Reader, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	return decrypt(data, []byte(encryption_key))
}

// Decrypts input byte data stream
func decrypt(data []byte, encryption_key []byte) (*bytes.Reader, error) {

	block, err := aes.NewCipher(encryption_key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(plaintext), nil
}
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */



/* * * * * * * * * * * * * * * * MISC. HELPERS  * * * * * * * * * * * * * * * */

// Check if string is in slice
func stringInSlice(a string, list []string) bool {
    for _, b := range list {
        if b == a {
            return true
        }
    }
    return false
}

func read_file_data(file io.Reader) ([]byte ,error) {
	return ioutil.ReadAll(file)
}

// Check for session token validity
func check_session_token(r *http.Request) (int) {
	token, err := r.Cookie("session_token")
	if err != nil {
		if err == http.ErrNoCookie {
			return 0 // Unauthorized access
		}
		return 1 // Bad Request
	}

	sessionToken := token.Value
	// Determine session validity
	response, err := cache.Do("GET", sessionToken)
	if err != nil {
		return 2 // Server Error
	}
	if response == nil {
		return 0 // Unauthorized access
	}

	return 3 // Valid Session
}

// Verify session token validity
func verify_session_token(w http.ResponseWriter, r *http.Request) (bool) {

	switch val := check_session_token(r); val {
		case UNAUTHORIZED:
			w.WriteHeader(http.StatusUnauthorized)
			return false
		case BAD_REQUEST:
			w.WriteHeader(http.StatusBadRequest)
			return false
		case SERVER_ERR:
			w.WriteHeader(http.StatusInternalServerError)
			return false
		case VALID_SESS:
	}
	return true
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */