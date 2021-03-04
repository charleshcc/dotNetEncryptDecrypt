# dotNetEncryptDecrypt

dot Net core Encrypt/Decrypt RSA and AES
In ReactJS RSA encrypt:
sa = (str) => {
    var encryptor = new JSEncrypt()
    var pubKey = process.env.REACT_APP_TEXT_SA;
    encryptor.setPublicKey(pubKey)
    return encryptor.encrypt(str);
  }
