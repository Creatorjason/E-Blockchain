const sha256 = require("crypto-js/sha256")
const elliptic = require("elliptic").ec

const ec = new elliptic('secp256k1')
 
// create your key pair to use
const keyPair = ec.genKeyPair()


class Block{
    constructor(transactions, timestamp, prev_hash = " "){
        this.transactions = transactions,
        this.timestamp = timestamp
        this.prev_hash = prev_hash,
        this.hash = this.calHash()
        this.nonce = 0
    }
    calHash(){
        return sha256(this.prev_hash+JSON.stringify(this.transactions)+this.timestamp+this.nonce).toString()
    }
    mineBlock(difficulty){
        while(this.calHash().substring(0, difficulty) !== Array(difficulty + 1).join("0")){
            this.nonce++
            this.hash = this.calHash()
        }
        console.log("Block mined:", this.hash)
    }
    hasValidTransaction(){
        for(tx of this.transactions){
            if(!tx.isValidTrx()){
                return false
            }
        }
        return true
    }
}

class Blockchain{
    constructor(difficulty){
        this.chain = [this.createGenesis()]
        this.difficulty = difficulty
        this.reward = 100
        this.pendingTransactions = []
    }
    createGenesis(){
        return new Block([{amount:2}], Date.now())
    }
    getLatestBlock(){
        return this.chain[(this.chain.length) - 1]
    }
    addNewBlock(minerAddress){
        let block = new Block(this.pendingTransactions , Date.now(), this.getLatestBlock().hash)
        block.mineBlock(this.difficulty)
        this.chain.push(block)
        this.pendingTransactions = [
            new Transaction(null, minerAddress, this.reward)
        ]


    }
    createTransaction(from, to, amount){
        const transaction = new Transaction(from, to, amount)
        if(!from || !to){
            console.log("Addresses cannot be empty")
        }
        if(!transaction.isValidTrx()){
            console.log("Transaction is invalid")
        }
        this.pendingTransactions.push(transaction)
    }
    trackUTXO(address){
        let balance = 0
        for(const block of this.chain){
            for(const trx of block.transactions){
                if( trx.from === address){
                    balance -= trx.amount
                }
                if (trx.to === address){
                    balance += trx.amount
                }
            }
        }
        return balance
    }
     isValid(){
        for(let i=1; i < this.chain.length; i++){
            let currBlock = this.chain[i]
            let prevBlock = this.chain[i - 1]

            if(currBlock.hash !== currBlock.calHash()){
                return false
            }
            if(!currBlock.hasValidTransaction()){
                return false
            }
            if(currBlock.prev_hash !== prevBlock.hash){
                return false
            }   
            return true
        }
    }
}

class Transaction{
    constructor(from, to, amount){
        this.from = from
        this.to = to
        this.amount = amount
    }
    calTrxHash(){
        return sha256(this.from+this.to+this.amount).toString()
    }
    signTransaction(signingKey){
        // check if user has the right to sign this transaction
        if(signingKey.getPublic('hex') !== this.from){
            console.log("Sorry you are unable to sign this transaction, as your address doesn't match the pub key")
        }
        const txHash = this.calTrxHash()
        const sig  = signingKey.sign(txHash, 'base64')
        this.signature = sig.toDER('hex')
    }
    isValidTrx(){
        if(this.from === null){
            return true
        }
        // check if signature is present
        if(this.signature || this.signature.length === 0){
            console.log("This transaction isn't signed")
        }
        const pubKey = ec.keyFromPublic(this.from, "hex")
        return pubKey.verify(this.calTrxHash(), this.signature)

    }

}
