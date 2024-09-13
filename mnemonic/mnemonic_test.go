package mnemonic

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var (
	wordListsPath              = filepath.Join(os.Getenv("PWD"), "..", "word_lists")
	testVectorMnemonicFilePath = filepath.Join(os.Getenv("PWD"), "..", "tests_vectors", "mnemonic.json")
	testVectorsMnemonic        map[string][][4]string
)

func init() {
	// Load test vectors from the JSON file
	data, err := ioutil.ReadFile(testVectorMnemonicFilePath)
	if err != nil {
		panic(fmt.Sprintf("Failed to load test vectors: %v", err))
	}

	err = json.Unmarshal(data, &testVectorsMnemonic)
	if err != nil {
		panic(fmt.Sprintf("Failed to parse test vectors: %v", err))
	}
}

func TestBip39(t *testing.T) {
	for language, languageTestVectors := range testVectorsMnemonic {
		for _, test := range languageTestVectors {
			t.Run(fmt.Sprintf("Language: %s", language), func(t *testing.T) {
				testEntropy, err := hex.DecodeString(test[0])
				if err != nil {
					t.Fatalf("Failed to decode test entropy: %v", err)
				}
				testMnemonic := test[1]
				testSeed, err := hex.DecodeString(test[2])
				if err != nil {
					t.Fatalf("Failed to decode test seed: %v", err)
				}

				// Test the mnemonic generation from entropy
				mnemonic, err := GetMnemonic(language, wordListsPath, testEntropy)
				if err != nil {
					t.Fatalf("Failed to generate mnemonic: %v", err)
				}
				if mnemonic != testMnemonic {
					t.Errorf("Expected mnemonic %s, got %s", testMnemonic, mnemonic)
				}

				// Test the seed generation from mnemonic and password
				seed, err := GetSeed(testMnemonic, "TREZOR")
				if err != nil {
					t.Fatalf("Failed to generate seed: %v", err)
				}

				assert.Equal(t, testSeed, seed)
			})
		}
	}
}

// TestReconstructMnemonic checks if reconstructing a mnemonic succeeds
func TestReconstructMnemonic(t *testing.T) {
	for _, languageTestVectors := range testVectorsMnemonic {
		for _, testMnemonic := range languageTestVectors {
			mnemonic := testMnemonic[1] // Extract the mnemonic from the test vector

			t.Run(fmt.Sprintf("Testing mnemonic: %s", mnemonic), func(t *testing.T) {
				reconstructedMnemonic, err := ReconstructMnemonic(mnemonic, wordListsPath)
				if err != nil {
					t.Fatalf("Failed to reconstruct mnemonic: %v", err)
				}
				if reconstructedMnemonic == "" {
					t.Errorf("Reconstructed mnemonic should not be empty for: %s", mnemonic)
				}
			})
		}
	}
}

// abbreviateMnemonic abbreviates each word in the mnemonic to a maximum of 4 characters.
func abbreviateMnemonic(mnemonic string) string {
	words := strings.Split(mnemonic, " ")
	words = AbbreviateWords(words)
	for _, word := range words {
		if len([]rune(word)) > 4 {
			panic("Word length exceeds 4 characters")
		}
	}
	return strings.Join(words, " ")
}

// TestReconstructAbbreviatedMnemonic tests the reconstruction of abbreviated mnemonics.
func TestReconstructAbbreviatedMnemonic(t *testing.T) {
	for _, languageTestVectors := range testVectorsMnemonic {
		for _, testMnemonic := range languageTestVectors {
			abbreviatedMnemonic := abbreviateMnemonic(testMnemonic[1])
			result, err := ReconstructMnemonic(abbreviatedMnemonic, wordListsPath)
			assert.NoError(t, err)
			if result == "" {
				t.Errorf("Failed to reconstruct mnemonic: %s", abbreviatedMnemonic)
			}
		}
	}
}

// TestGetWord tests the indexToWord function with various indices.
func TestGetWord(t *testing.T) {
	language := "english"

	// Get the word list for the specified language
	wordList, err := getWordList(language, wordListsPath)
	if err != nil {
		t.Fatalf("Failed to get word list for language %s: %v", language, err)
	}

	// Define test cases
	testCases := []struct {
		index int
		valid bool
	}{
		{index: 0, valid: true},
		{index: 2047, valid: true},
		{index: 2048, valid: false},
	}

	// Iterate over test cases
	for _, tc := range testCases {
		if tc.valid {
			// Expecting a valid word retrieval
			_, err := indexToWord(wordList, tc.index)
			if err != nil {
				t.Errorf("Expected no error for index %d, but got: %v", tc.index, err)
			}
		} else {
			// Expecting an error due to invalid index
			_, err := indexToWord(wordList, tc.index)
			assert.Error(t, err)
		}
	}
}
