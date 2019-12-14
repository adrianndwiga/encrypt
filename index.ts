import * as crypto from 'crypto'

export interface Config {
    secret: string
    algorithm: {
        hash: string,
        cipher: string
    },
    encoding: string
}

// references: 
//          https://github.com/nodejs/node/issues/16746
//          https://medium.com/@anned20/encrypting-files-with-nodejs-a54a0736a50a
export class Encrypt {
    constructor(private config: Config, private key: string) {
    }

    encrypt(buffer: Buffer): Buffer {
        const initializationVector = crypto.randomBytes(16)
        const cipher = crypto.createCipheriv(this.config.algorithm.cipher, this.key, initializationVector)
        
        return Buffer.concat([initializationVector, cipher.update(buffer), cipher.final()])
    }
    
    decrypt(encrypted: Buffer): Buffer {
        const initializationVector = encrypted.slice(0, 16)
    
        encrypted = encrypted.slice(16)
        const decipher = crypto.createDecipheriv('aes-256-ctr', this.key, initializationVector)
        return Buffer.concat([decipher.update(encrypted), decipher.final()])
    }
}