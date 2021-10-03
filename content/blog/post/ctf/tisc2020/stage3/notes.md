Similar to stage 2, I am looking for relevant APIs from golang.

Since this is asking me to decrypt an encrypted db file, the ransomware must read/write the files. So looking into golang documentation, we find ioutil_WriteFile and ioutil_Readfile

And with xrefs, I find that the funciton main_visit_func1 calls both of them. Looking through the function, I also found crypto_aes_NewCipher which initializes the aes object to encrypt stuff.

This is most likely the function that handles the encryption of the files.

Reading through the function, we find out that
