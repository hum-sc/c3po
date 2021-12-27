import {createPublicKey, generateKeyPair, generateKeyPairSync, privateDecrypt, publicEncrypt} from 'node:crypto'


export function generateKeys (pPassphrase){
    const {publicKey, privateKey} = generateKeyPairSync('rsa', {
        modulusLength: 4090,
        publicKeyEncoding: {
            type: 'pkcs1',
            format: 'pem',
        },
        privateKeyEncoding: {
            type: 'pkcs1',
            format: 'pem',
            cipher:'aes-256-cbc',
            passphrase: pPassphrase,
        }
    });

    return {publicKey, privateKey};
}

export function generatePublicKey(privateKey, pPassphrase){
    const publicKey = createPublicKey({
        type: 'pkcs1',
        format:'pem',
        key: privateKey,
        passphrase: pPassphrase
    });
    return publicKey.export({
        format: 'pem',
        type: 'pkcs1'
    });
}

export function enCrypt(publicKey, data){
    return publicEncrypt(publicKey, data);
}

export function deCrypt(privateKey, pPassphrase, data){
    return privateDecrypt({
        key: privateKey,
        passphrase: pPassphrase,
    }, data).toString();
}