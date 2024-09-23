package mnemonic

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"crypto/sha512"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/text/unicode/norm"
)

// getWordList reads the BIP39 wordlist for the given language from a file.
//
// Parameters:
//   - language (string): The language of the wordlist.
//   - path (string): The path to the directory containing the wordlist file.
//
// Returns:
//   - []string: A slice of words from the wordlist.
//   - error: An error object if the wordlist file cannot be read.
func getWordList(language, path string) ([]string, error) {
	cleanLanguageFileName := filepath.Clean(fmt.Sprintf("%s.txt", language))
	filePath := filepath.Join(path, cleanLanguageFileName)

	cleanFilePath := filepath.Clean(filePath)
	file, err := os.Open(cleanFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open wordlist file: %v", err)
	}
	defer file.Close()

	var wordList []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		wordList = append(wordList, word)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading wordlist: %v", err)
	}
	return wordList, nil
}

// indexToWord returns the corresponding word for the given index in the word list.
//
// Parameters:
//   - wordList ([]string): The word list.
//   - index (int): The index of the word in the word list.
//
// Returns:
//   - string: The word corresponding to the given index.
//   - error: An error object if the index is out of range.
func indexToWord(wordList []string, index int) (string, error) {
	if index >= 2048 {
		return "", fmt.Errorf("index should be less than 2048. Got %d", index)
	}
	return wordList[index], nil
}

// wordToIndex returns the index of the given word in the word list.
//
// Parameters:
//   - wordList ([]string): The word list.
//   - word (string): The word to find in the word list.
//
// Returns:
//   - int: The index of the word in the word list.
//   - error: An error object if the word is not found in the word list.
func wordToIndex(wordList []string, word string) (int, error) {
	for i, w := range wordList {
		if w == word {
			return i, nil
		}
	}
	return 0, fmt.Errorf("word %s not found in BIP39 wordlist", word)
}

// uint11ArrayToUint converts a uint11 array to a single integer.
//
// Parameters:
//   - uint11Array ([]int): The array of 11-bit integers.
//
// Returns:
//   - *big.Int: The resulting big integer.
func uint11ArrayToUint(uint11Array []int) *big.Int {
	result := new(big.Int) // Initialize a new big.Int to hold the result
	for i, x := range uint11Array {
		// Convert x to a big.Int and shift it by 11 * position
		part := new(big.Int).Lsh(big.NewInt(int64(x)), uint(11*(len(uint11Array)-1-i)))
		// Add this part to the result
		result.Add(result, part)
	}
	return result
}

// GetSeed generates the seed for the mnemonic using PBKDF2 as per BIP39.
//
// Parameters:
//   - mnemonic (string): The mnemonic phrase.
//   - password (string): The password used in conjunction with the mnemonic.
//
// Returns:
//   - []byte: The generated seed.
//   - error: An error object if the seed generation fails.
func GetSeed(mnemonic, password string) ([]byte, error) {
	encodedMnemonic := norm.NFKD.String(mnemonic)
	salt := norm.NFKD.String("mnemonic" + password)
	return pbkdf2.Key([]byte(encodedMnemonic), []byte(salt), 2048, 64, sha512.New), nil
}

// determineMnemonicLanguage determines the language of the mnemonic based on the BIP39 word_lists.
//
// Parameters:
//   - mnemonic (string): The mnemonic phrase.
//   - wordsPath (string): The path to the directory containing the wordlist files.
//
// Returns:
//   - []string: A slice of detected languages.
//   - error: An error object if the language determination fails.
func determineMnemonicLanguage(mnemonic, wordsPath string) ([]string, error) {
	languages := []string{
		"english",
		"italian",
		"portuguese",
		"czech",
		"spanish",
		"chinese_simplified",
		"chinese_traditional",
		"korean",
	}
	wordLanguageMap := make(map[string]string)

	for _, lang := range languages {
		wordList, err := getWordList(lang, wordsPath)
		if err != nil {
			return nil, fmt.Errorf("failed to get wordlist for language %s: %v", lang, err)
		}
		for _, word := range wordList {
			wordLanguageMap[word] = lang
		}
	}

	var words []string
	var detectedLanguages []string

	for _, each := range strings.Split(strings.ToLower(mnemonic), " ") {
		abbrev := norm.NFKC.String(each)
		if len(norm.NFKC.String(each)) > 4 {
			abbrev = norm.NFKC.String(each)[:4]
		}
		words = append(words, abbrev)
	}

	for _, word := range words {

		found := false
		for wordLangMapWord, lang := range wordLanguageMap {
			normWord := norm.NFKC.String(wordLangMapWord)
			if len(norm.NFKC.String(wordLangMapWord)) > 4 {
				normWord = norm.NFKC.String(wordLangMapWord)[:4]
			}
			if word == normWord {
				detectedLanguages = append(detectedLanguages, lang)
				found = true
			}
		}

		if !found {
			return nil, fmt.Errorf("word %s not found in any wordlist", word)
		}
	}
	slices.Sort(detectedLanguages)
	return slices.Compact(detectedLanguages), nil
}

// getChecksum returns the checksum for the given entropy.
//
// Parameters:
//   - entropy ([]byte): The entropy bytes.
//
// Returns:
//   - *big.Int: The checksum as a big integer.
func getChecksum(entropy []byte) *big.Int {
	hash := sha256.Sum256(entropy)
	checksumLength := len(entropy) * 8 / 32 // Calculate the number of bits for the checksum

	// Convert the first byte of the hash to an integer and shift to get only the checksum bits
	hashInt := new(big.Int).SetBytes([]byte{hash[0]})
	checksum := new(big.Int).Rsh(hashInt, uint(8-checksumLength))

	return checksum
}

// AbbreviateWords returns a list of words abbreviated to the first 4 runes after NFKC normalization.
//
// Parameters:
//   - words ([]string): The list of words to abbreviate.
//
// Returns:
//   - []string: The list of abbreviated words.
func AbbreviateWords(words []string) []string {
	abbreviated := make([]string, len(words))
	for i, word := range words {
		// Normalize the word to NFKC form
		normalized := norm.NFKC.String(word)

		// Convert the normalized string to a slice of runes (Unicode characters)
		runes := []rune(normalized)

		// If the number of runes is <= 3, keep the whole word, otherwise slice the first 4 runes
		if len(runes) <= 3 {
			abbreviated[i] = string(runes)
		} else {
			abbreviated[i] = string(runes[:4])
		}
	}
	return abbreviated
}

// Reconstructs a mnemonic from word indices and a full word list.
//
// Parameters:
//   - wordList ([]string): The full word list.
//   - wordIndices ([]int): The list of word indices.
//
// Returns:
//   - string: The reconstructed mnemonic.
func reconstructFromWordIndices(wordList []string, wordIndices []int) string {
	words := make([]string, len(wordIndices))
	for i, index := range wordIndices {
		words[i] = wordList[index]
	}
	return strings.Join(words, " ")
}

// ReconstructMnemonic attempts to reconstruct a full mnemonic from an abbreviated version and verify its checksum.
//
// Parameters:
//   - mnemonic (string): The abbreviated mnemonic phrase.
//   - wordsPath (string): The path to the directory containing the wordlist files.
//
// Returns:
//   - string: The reconstructed mnemonic.
//   - error: An error object if the reconstruction fails.
func ReconstructMnemonic(mnemonic, wordsPath string) (string, error) {
	// Determine the language of the mnemonic
	languages, err := determineMnemonicLanguage(mnemonic, wordsPath)
	if err != nil {
		return "", err
	}

	var reconstructedMnemonic string
	for _, language := range languages {
		// Get the abbreviated word list and the full word list for the language
		wordList, err := getWordList(language, wordsPath)
		if err != nil {
			return "", err
		}
		abbrevWordList := AbbreviateWords(wordList)
		abbrevMnemonicList := AbbreviateWords(strings.Split(strings.ToLower(mnemonic), " "))

		// Validate the length of the mnemonic (BIP-39 mnemonics are usually between 12 and 24 words)
		if len(abbrevMnemonicList) < 12 || len(abbrevMnemonicList) > 24 || len(abbrevMnemonicList)%3 != 0 {
			return "", errors.New("invalid mnemonic length")
		}

		// Convert abbreviated mnemonic to word indices
		var wordIndices []int
		for _, abbrevWord := range abbrevMnemonicList {
			index, err := wordToIndex(abbrevWordList, abbrevWord)
			if err != nil {
				continue
			}
			wordIndices = append(wordIndices, index)
		}

		if len(wordIndices) != len(abbrevMnemonicList) {
			continue
		}

		// Convert word indices to a 11-bit integer array
		mnemonicInt := uint11ArrayToUint(wordIndices)
		checksumLength := len(abbrevMnemonicList) / 3

		// Create a mask for extracting the checksum (1 << checksumLength - 1)
		checksumMask := new(big.Int).Lsh(big.NewInt(1), uint(checksumLength))
		checksumMask.Sub(checksumMask, big.NewInt(1))

		checksum := new(big.Int).And(mnemonicInt, checksumMask)

		// Extract the entropy by right-shifting the mnemonic by checksumLength bits
		entropy := new(big.Int).Rsh(mnemonicInt, uint(checksumLength))

		// Convert entropy to bytes
		entropyBytes := entropy.FillBytes(make([]byte, checksumLength*4))

		// Get the full word list for the language
		fullWordList, err := getWordList(language, wordsPath)
		if err != nil {
			return "", err
		}

		calculatedChecksum := getChecksum(entropyBytes)

		// Check if the checksum is valid
		if calculatedChecksum.Cmp(checksum) == 0 {
			if reconstructedMnemonic != "" {
				return "", errors.New("ambiguous mnemonic, valid in multiple languages")
			}
			// Reconstruct the full mnemonic from the word indices
			reconstructedMnemonic = reconstructFromWordIndices(fullWordList, wordIndices)
		}
	}

	if reconstructedMnemonic == "" {
		return "", errors.New("failed to reconstruct mnemonic")
	}

	return reconstructedMnemonic, nil
}

// GetMnemonic generates a BIP-39 mnemonic from entropy and language.
//
// Parameters:
//   - language (string): The language of the wordlist.
//   - wordsPath (string): The path to the directory containing the wordlist files.
//   - entropy ([]byte): The entropy bytes. If nil, random entropy will be generated.
//
// Returns:
//   - string: The generated mnemonic phrase.
//   - error: An error object if the mnemonic generation fails.
func GetMnemonic(language, wordsPath string, entropy []byte) (string, error) {
	// Generate random entropy if not provided
	if entropy == nil {
		entropy = make([]byte, 32) // 256 bits
		_, err := rand.Read(entropy)
		if err != nil {
			return "", fmt.Errorf("failed to generate random entropy: %v", err)
		}
	}

	entropyLength := len(entropy) * 8 // Length in bits
	checksumLength := entropyLength / 32

	// Calculate the checksum
	checksum := getChecksum(entropy)

	// Convert entropy to a big.Int and append checksum
	entropyBits := new(big.Int).SetBytes(entropy)
	entropyBits.Lsh(entropyBits, uint(checksumLength)) // Shift left to append checksum
	entropyBits.Or(entropyBits, checksum)

	// Load the word list for the specified language
	wordList, err := getWordList(language, wordsPath)
	if err != nil {
		return "", fmt.Errorf("failed to load word list: %v", err)
	}

	// Generate the mnemonic
	entropyPlusChecksumLength := entropyLength + checksumLength
	mnemonic := make([]string, entropyPlusChecksumLength/11)
	for i := entropyPlusChecksumLength/11 - 1; i >= 0; i-- {
		index := new(big.Int).And(entropyBits, big.NewInt((1<<11)-1)).Int64() // Extract the lowest 11 bits
		mnemonic[i], err = indexToWord(wordList, int(index))
		if err != nil {
			return "", fmt.Errorf("failed to convert index to word: %v", err)
		}
		entropyBits.Rsh(entropyBits, 11) // Shift right by 11 bits for next word
	}

	return strings.Join(mnemonic, " "), nil
}
