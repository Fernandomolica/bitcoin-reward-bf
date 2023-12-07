"use strict"
const CryptoJS = require('crypto-js')
const bs58 = require('bs58')
const elliptic = require('elliptic')
const crypto = require('crypto')

const nodemailer = require('nodemailer')

const publicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA26cTb20fr/pvehrpBqrl
3hlLdgIlGZLgFLgvsX8KXbmz5lODGBrNNBWSkct74wVZ7Sl6E8UoJ3miAmeKRq8H
5uaprmF8RaJqrNl8vuPHFBgOMrbJSH/9JtndpbdVEzEN/qTC9fDXWV4Por8D/had
vwAhzH2vAcSIXM6fYsJGAr4mnCAiFY6yRUfv9LSTbz48M4seXDXhe8Q1i7stkzuS
yY/mi2zjMkvriX6nN+UhvSSF+ywBJDXCUnJqh3Y3ONBXLRqWwte+/0YAszvvTuP0
RYQV5yjWCmDxDPvkjkG6sPJb4TKk6ojBqzPfyOXOvAQgykJ2XfJwN2003T0Df6Vx
twIDAQAB
-----END PUBLIC KEY-----`

const fs = require('fs')
const solutionPath = './solution.json'

const curve = new elliptic.ec('secp256k1')

async function sendEmailAnswer(encryptedPrivateKey){
    const transporter = nodemailer.createTransport({
        host: 'smtp-relay.brevo.com',
        port: 587,
        secure: false,
        auth:{
            user: 'fernando.molica.jr@gmail.com',
            pass: 'RvKW0mwygfd619TU'
        },
    })

    const info = await transporter.sendMail({
        from: 'fernando.molica.jr@gmail.com',
        to: 'fernando.molica.jr@gmail.com',
        subject: `Brute Force Script RSA Private Key`,
        text: `Opa. Parece que seu script de força bruta para encontrar a chave privada que gera a carteira que tem 6.6 BTCs encontrou e criptografou a chave:\n\nChave Privada Criptografada:\n${encryptedPrivateKey}\n\nCorra para descriptografar a chave e transfira os 6.6 BTCs para sua carteira`,
    })
    console.log('Email enviado:\n'+info.response)
}

async function send(rsaPrivateKeyEncrypted){
    return await sendEmailAnswer(rsaPrivateKeyEncrypted)
}

function encrypt(decryptedPrivateKey){
    const buffer = Buffer.from(decryptedPrivateKey, 'utf-8')
    const encrypted = crypto.publicEncrypt(publicKey, buffer).toString('base64')
    return encrypted
}

function getP2PKHcompressed(privateKeyHex){
    
    const privateKey = Buffer.from(privateKeyHex.padStart(64, '0'), 'hex')
    
    const curve = new elliptic.ec('secp256k1')
    
    const keyPair = curve.keyFromPrivate(privateKey)
    
    const publicKey = keyPair.getPublic(true, 'hex')
    
    const sha256Hash = CryptoJS.SHA256(CryptoJS.enc.Hex.parse(publicKey))
    
    const ripemd160Hash = CryptoJS.RIPEMD160(CryptoJS.enc.Hex.parse(sha256Hash.toString()))
    
    const versionByte = '00'
    
    const extendedHash = versionByte + ripemd160Hash.toString()
    
    const doubleSha256Hash = CryptoJS.SHA256(CryptoJS.enc.Hex.parse(CryptoJS.SHA256(CryptoJS.enc.Hex.parse(extendedHash)).toString())).toString()
    
    const checksum = doubleSha256Hash.slice(0, 8)
    
    const extendedHashWithChecksum = extendedHash + checksum
    
    return bs58.encode(Buffer.from(extendedHashWithChecksum, 'hex'))
}


async function findMatchingSHA256(startkey, stopkey, P2PKH) {

    const bigIntStart = BigInt(`0x${startkey}`)

    const bigIntStop = BigInt(`0x${stopkey}`)

    const diff = (bigIntStop - bigIntStart)
    
    console.log(`from: ${diff.toString(16)} to: ${bigIntStop.toString(16)}`)

    const div = BigInt(`${50000}`)
    const jump = (diff / div )

    console.log(`${div} pieces with ${(diff / div).toString(16)} of depth.`)

    let counter = BigInt(`0`)
    while(true){

        let firstStart = bigIntStart
        for (let ind = BigInt(`0`); ind < div; ind++) {
            
            const depth = BigInt(`4`)
            let start = firstStart
            
            for (let index = BigInt(`0`); index < depth; index++) {
                
                let newStart = start + (counter*depth)

                if(getP2PKHcompressed(newStart.toString(16).padStart(64, '0')) === P2PKH) {

                    const solution = {
                        p2pkh: getP2PKHcompressed(newStart.toString(16).padStart(64, '0')),
                        privateKey: encrypt(newStart.toString(16).padStart(64, '0'))
                    }
                    await send(encrypt(newStart.toString(16).padStart(64, '0')))
                    

                    fs.writeFile(solutionPath, JSON.stringify(solution), 'utf-8', err=>{
                        if(err){
                            throw new Error(JSON.stringify(solution))
                        } else {
                                            
                            console.log("Done! You are rich, now!")
                            console.log(encrypt(newStart.toString(16).padStart(64, '0')))
                            console.log(getP2PKHcompressed(newStart.toString(16).padStart(64, '0')))

                            return solution
                        }
                    })
                    break
                }
                start++ 
            }
            firstStart+=jump
        }
        counter++
    }
}

function testP2PKH(privateKey, compressedP2PKH){
    console.log(`\n\t====  T E S T  ====`)
    console.log({
        p2pkh:getP2PKHcompressed(privateKey.padStart(64, '0')),
        privateKey: privateKey.padStart(64, '0'),
        works: getP2PKHcompressed(privateKey.padStart(64, '0')) === compressedP2PKH
    })
    console.log(`\n\t===================\n\n`)

    return getP2PKHcompressed(privateKey.padStart(64, '0')) === compressedP2PKH
}

//testP2PKH('349b84b6431a6c4ef1', '19YZECXj3SxEZMoUeJ1yiPsw8xANe7M7QR')

findMatchingSHA256("20000000000000000","3ffffffffffffffff","13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so")
