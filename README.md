

使用範例:
```powershell
# 指定輸入與輸出資料夾
.\tools\packer.exe --in .\hello.exe --outdir .\output

# 指定輸出檔名
.\tools\packer.exe --in .\hello.exe --out .\output\hello_protected.exe


# 使用固定金鑰（64 hex = 32 bytes）
.\tools\packer.exe --in .\hello.exe --outdir .\output --keyhex 00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF


```

