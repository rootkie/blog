package main

import (
    "crypto/aes"
    "crypto/cipher"
    "fmt"
    "io/ioutil"
    "os"
    "net/url"
)

func decrypt(key []byte, iv []byte, filename string) {

	// Load your secret key from a safe place and reuse it across multiple

	// NewCipher calls. (Obviously don't use this example key for anything

	// real.) If you want to convert a passphrase to a key, use a suitable

	// package like bcrypt or scrypt.

    ctx, _ := ioutil.ReadFile(filename)


	block, err := aes.NewCipher(key)

	if err != nil {

		panic(err)

	}


	// The IV needs to be unique, but not secure. Therefore it's common to

	// include it at the beginning of the ciphertext.

	ptx := make([]byte, aes.BlockSize+len(ctx))



	stream := cipher.NewCTR(block, iv)

	stream.XORKeyStream(ptx[aes.BlockSize:], ctx)


	fmt.Printf("%s\n", ptx)

    ioutil.WriteFile(filename+".decrypted", ptx[aes.BlockSize:], 0644)
}



func main() {
    queryStr := "City=Singapore&EncIV=%1C%9F%A4%9B%2C%9EN%AF%04%9CA%AE%02%86%03%81&EncKey=%99z%11%12%7FjD%22%93%D2%A8%EB%1D2u%04&IP=112.199.210.119&MachineId=6d8da77f503c9a5560073c13122a903b"
    params,_ := url.ParseQuery(queryStr)

    fmt.Println("Query Params:")
    for key, value := range params {
        fmt.Printf(" %v = %v\n", key, value)
    }
    key := []byte(params["EncKey"][0])
    iv  := []byte(params["EncIV"][0])

    filename := os.Args[1]

    fmt.Println(filename)
    iv[0] = []byte(filename)[0]
    iv[1] = []byte(filename)[1]

    decrypt(key, iv, filename)
}
