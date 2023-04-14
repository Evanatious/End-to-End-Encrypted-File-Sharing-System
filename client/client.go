package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	username string
	password string
	SignKey  userlib.DSSignKey
	DecKey   userlib.PKEDecKey

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

// This is the type definition for the User struct which is stored in the DataStore.
type UserDS struct {
	EncryptedUserStruct []byte
	HMACsignature       []byte
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {

	var ok bool
	// Check if username already exists
	_, ok = userlib.KeystoreGet(username + "RSA") // TODO: Check if this is correct
	if ok {
		return nil, errors.New("Username already exists")
	}
	// Check if empty username is provided
	if username == "" {
		return nil, errors.New("Username cannot be empty")
	}

	// Create a user instance with username and password
	var userdata User
	userdata.username = username
	userdata.password = password

	// Generate a random RSA keypair
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	// userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)
	userdata.DecKey = sk
	// Publish the public key into KeyStore
	userlib.KeystoreSet(username+"RSA", pk)

	// Generate a random DS keypair
	var ds_pk userlib.DSVerifyKey
	var ds_sk userlib.DSSignKey
	ds_sk, ds_pk, _ = userlib.DSKeyGen()
	// userlib.DebugMsg("DS Key Pair: (%v, %v)", dsa_pk, dsa_sk)
	userdata.SignKey = ds_sk
	// Publish the public key into KeyStore
	userlib.KeystoreSet(username+"DSA", ds_pk)

	// Generate SourceKey with username as salt
	// Use Argon2Key(password []byte, salt []byte, keyLen uint32) (result []byte)
	var SourceKey []byte
	SourceKey = userlib.Argon2Key([]byte(password), []byte(username), 16)
	// userlib.DebugMsg("SourceKey: %v", SourceKey)

	// Generate a 16 byte AES key from the SourceKey
	// Use HashKDF(sourceKey []byte, purpose []byte) (derivedKey []byte, err error)
	var AESKey []byte
	AESKey, err = userlib.HashKDF(SourceKey, []byte("AESKey"))
	if err != nil {
		return nil, err
	}
	AESKey = AESKey[:16]

	// Encrypt the userdata struct with AESKey
	// Use SymEnc(key []byte, iv []byte, plaintext []byte) (ciphertext []byte)
	var userdataBytes []byte
	userdataBytes, err = json.Marshal(userdata)
	if err != nil {
		return nil, err
	}
	var iv []byte
	iv = userlib.RandomBytes(16)
	var encryptedUserStruct []byte
	encryptedUserStruct = userlib.SymEnc(AESKey, iv, userdataBytes)

	// Generate a 16 byte HMAC key from the SourceKey
	// Use HashKDF(sourceKey []byte, purpose []byte) (derivedKey []byte, err error)
	var HMACKey []byte
	HMACKey, err = userlib.HashKDF(SourceKey, []byte("HMACKey"))
	if err != nil {
		return nil, err
	}
	HMACKey = HMACKey[:16]

	// Generate HMAC of encryptedUserStruct
	// Use HMACEval(key []byte, msg []byte) (sum []byte, err error)
	var HMAC []byte
	HMAC, err = userlib.HMACEval(HMACKey, encryptedUserStruct)
	if err != nil {
		return nil, err
	}

	// Create a UserDS struct
	userds := UserDS{encryptedUserStruct, HMAC}

	// Creates a UUID deterministically, from the hash of the username + password + delimiter
	hash := userlib.Hash([]byte(username + password + "||"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	// userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Store the UserDS struct in DataStore
	// Use DatastoreSet(key string, value []byte)
	var userdsBytes []byte
	userdsBytes, err = json.Marshal(userds)
	if err != nil {
		return nil, err
	}
	userlib.DatastoreSet(deterministicUUID, userdsBytes)

	// Return the user instance
	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User

	// Generates the UUID deterministically, from the hash of the username + password + delimiter
	hash := userlib.Hash([]byte(username + password + "||"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	// userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Retrieve the UserDS struct from DataStore
	// Use DatastoreGet(key string) (value []byte, ok bool)
	var userdsBytes []byte
	userdsBytes, ok := userlib.DatastoreGet(deterministicUUID)

	// Check if the user credentials are valid
	if !ok {
		return nil, errors.New("User not found")
	}

	// Unmarshal the UserDS struct
	var userds UserDS
	err = json.Unmarshal(userdsBytes, &userds)
	if err != nil {
		return nil, err
	}

	// Extract the encryptedUserStruct and HMAC from UserDS struct
	encryptedUserStruct := userds.EncryptedUserStruct
	HMAC := userds.HMACsignature

	// Generate SourceKey with username as salt
	// Use Argon2Key(password []byte, salt []byte, keyLen uint32) (result []byte)
	var SourceKey []byte
	SourceKey = userlib.Argon2Key([]byte(password), []byte(username), 16)
	// userlib.DebugMsg("SourceKey: %v", SourceKey)

	// Generate the 16 byte HMAC key from the SourceKey
	// Use HashKDF(sourceKey []byte, purpose []byte) (derivedKey []byte, err error)
	var HMACKey []byte
	HMACKey, err = userlib.HashKDF(SourceKey, []byte("HMACKey"))
	if err != nil {
		return nil, err
	}
	HMACKey = HMACKey[:16]

	// Verify HMAC of encryptedUserStruct
	// Use HMACEval(key []byte, msg []byte) (sum []byte, err error)
	var HMACverify []byte
	HMACverify, err = userlib.HMACEval(HMACKey, encryptedUserStruct)
	if err != nil {
		return nil, err
	}
	// Check if the user struct has been tampered with
	if !userlib.HMACEqual(HMAC, HMACverify) {
		return nil, errors.New("HMAC verification failed")
	}

	// Generate the 16 byte AESKey from the SourceKey
	// Use HashKDF(sourceKey []byte, purpose []byte) (derivedKey []byte, err error)
	var AESKey []byte
	AESKey, err = userlib.HashKDF(SourceKey, []byte("AESKey"))
	if err != nil {
		return nil, err
	}
	AESKey = AESKey[:16]

	// Decrypt the encryptedUserStruct
	// Use SymDec(key []byte, ciphertext []byte) (plaintext []byte)
	var userStructBytes []byte
	userStructBytes = userlib.SymDec(AESKey, encryptedUserStruct)

	// Unmarshal the User struct
	err = json.Unmarshal(userStructBytes, &userdata)
	if err != nil {
		return nil, err
	}

	// Return the user instance
	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.username))[:16])
	if err != nil {
		return err
	}
	contentBytes, err := json.Marshal(content)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(storageKey, contentBytes)
	return
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.username))[:16])
	if err != nil {
		return nil, err
	}
	dataJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil, errors.New(strings.ToTitle("file not found"))
	}
	err = json.Unmarshal(dataJSON, &content)
	return content, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	return
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	return nil
}
