# WebM CENC (Common Encryption) Decryptor in Go


### Build Steps

```shell
go build -o webmdec_cli.exe cmd/webmdec/main.go
```

## Usage Instructions

### Decrypt the Provided Test Sample
The project includes a pre-packaged encrypted WebM file (`encrypted_video.webm`). You can decrypt it out-of-the-box by running:

```shell
.\webmdec_cli.exe -key 0123456789abcdef0123456789abcdef:abcdef0123456789abcdef0123456789 -input encrypted_video.webm -output decrypted_video.webm
```
*(Or use the compiled executable `.\webmdec_cli.exe`)*

### Decrypt webm encrypted with multiple keys

```shell
.\webmdec_cli.exe -key "kid1:key1|kid2:key2|kid3:key3" -input encrypted_video.webm -output decrypted_video.webm
```


### Command Line Flags
- `-key`: One or more `kid:key` pairs separated by `|`. Each `kid` and `key` must be a 32-character Hex-encoded string (16 bytes). Default: `0123456789abcdef0123456789abcdef:abcdef0123456789abcdef0123456789`
- `-input`: Path to the raw WebM file. Default: `encrypted_video.webm`
- `-output`: Path to write the decrypted WebM file. Default: `decrypted_video.webm`
- `-simulate`: Force run the built-in simulation suite.


### What's the point of this project as i can use shaka-packager to decrypt webm file?
This project didnt write a tempfile as large as the original encrypted webm file like shaka-packager which is dumb as fuck. 
