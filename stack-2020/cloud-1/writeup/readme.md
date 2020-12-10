# STACK the Flags 2020 - Find the leaking bucket!

>It was made known to us that agents of COViD are exfiltrating data to a hidden S3 bucket in AWS! We do not know the bucket name! One tip from our experienced officers is that bucket naming often uses common words related to the company’s business.
>
>Do what you can! Find that hidden S3 bucket (in the format “**word1-word2-s4fet3ch**”) and find out what was exfiltrated!



## Introduction

The company website is a simple page with a word cloud and an image of a quote from Steve Jobs.

The challenge description hints towards the two words used in the S3 bucket name to be somewhere on the website, so we can scrape all the words from the word cloud. Although the image of Steve Jobs is deeply inspirational and brought a tear to my eye, this feels like [Chekhov's gun](https://tvtropes.org/pmwiki/pmwiki.php/Main/ChekhovsGun) at play here -- better scrape keywords from that too.

Our final wordlist stands at 30 words. This is only 30*29 = **870** possible permutations so we can just check every single permutation by sending a GET request. If the URL from a pair of words returns a non-404 status code, that's our bucket.

Running a simple script yields our bucket URL: http://think-innovation-s4fet3ch.s3.amazonaws.com/

### Cracking

Visiting the bucket, we download a zip file containing two files:

-  `flag.txt`
- `STACK the Flags Consent and Indemnity Form.docx`

The flag is right there behind a password, but the existence of the other file is curious. It's a tad late to be giving participants the consent form in the middle of the competition isn't it?

At the rate we're going, Chekhov will have amassed enough guns to fill an armoury before we're done with this writeup.

Searching for the filename, we can download (presumably) the exact file from the [CTF website](https://ctf.tech.gov.sg/files/STACK%20the%20Flags%20Consent%20and%20Indemnity%20Form.docx). Instead of running John the Ripper on the zip, we can use a known plaintext attack on the zip file. The idea is that we supply an unencrypted file that is present in the zip, and let [pkcrack](https://github.com/keyunluo/pkcrack) do its magic.

To save your eyes from backslashes for escaped spaces, I have renamed the documents in both zips to `form.docx`.

```bash
# Zip the file
zip plaintext.zip form.docx
# Crack the file and output to out.zip
pkcrack -C secret-files.zip -c form.docx -P plaintext.zip -c form.docx -d out.zip -a
```

The output zip file is not password-protected and can be unzipped for the flag.

#### Pitfalls

Since this is a known plaintext attack, the compression method has to be the same for the encrypted and plaintext zips. Originally I had zipped the form using WinRAR's zip compression on Windows, which uses a slightly different version:

```bash
❯ zipinfo test.zip
Archive:  test.zip
Zip file size: 273462 bytes, number of entries: 1
-rw-a--     3.1 fat   275299 bx defN 20-Dec-06 05:37 form.docx
1 file, 275299 bytes uncompressed, 273310 bytes compressed:  0.7%
```

Compare this to:

```bash
❯ zipinfo secret-files.zip 
Archive:  secret-files.zip
Zip file size: 273728 bytes, number of entries: 2
-rw-r--r--  3.0 unx       50 TX stor 20-Nov-17 14:59 flag.txt
-rw-r--r--  3.0 unx   275299 BX defN 20-Nov-17 10:15 form.docx
2 files, 275349 bytes uncompressed, 273360 bytes compressed:  0.7%

❯ zipinfo plaintext.zip   
Archive:  plaintext.zip
Zip file size: 273478 bytes, number of entries: 1
-rw-r--r--  3.0 unx   275299 bx defN 20-Dec-05 21:37 form.docx
1 file, 275299 bytes uncompressed, 273310 bytes compressed:  0.7%
```

