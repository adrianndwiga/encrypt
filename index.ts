import * as crypto from 'crypto'
import { HexBase64Latin1Encoding } from 'crypto'

export interface Config {
    secret: string
    algorithm: {
        hash: string,
        cipher: string
    },
    encoding: HexBase64Latin1Encoding
}

// references: 
//          https://github.com/nodejs/node/issues/16746
//          https://medium.com/@anned20/encrypting-files-with-nodejs-a54a0736a50a
export class Encrypt {
    constructor(private config: Config) {
    }

    encrypt(buffer: Buffer): Buffer {
        const initializationVector = crypto.randomBytes(16)
        const key = crypto.createHash(this.config.algorithm.hash).update(this.config.secret).digest(this.config.encoding).substr(0, 32)
        const cipher = crypto.createCipheriv(this.config.algorithm.cipher, key, initializationVector)
        
        return Buffer.concat([initializationVector, cipher.update(buffer), cipher.final()])
    }
    
    decrypt(encrypted: Buffer): Buffer {
        const initializationVector = encrypted.slice(0, 16)
        const key = crypto.createHash(this.config.algorithm.hash).update(this.config.secret).digest(this.config.encoding).substr(0, 32)
    
        encrypted = encrypted.slice(16)
        const decipher = crypto.createDecipheriv(this.config.algorithm.cipher, key, initializationVector)
        return Buffer.concat([decipher.update(encrypted), decipher.final()])
    }
}
