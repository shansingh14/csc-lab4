import hashlib
import sys, time, json, os
from ecdsa import VerifyingKey, SigningKey
from p2pnetwork.node import Node
from Crypto.Cipher import AES
from Crypto import Random

SERVER_ADDR = "zachcoin.net"
SERVER_PORT = 9067

class ZachCoinClient (Node):
    
    #ZachCoin Constants
    BLOCK = 0
    TRANSACTION = 1
    BLOCKCHAIN = 2
    UTXPOOL = 3
    COINBASE = 50
    DIFFICULTY = 0x0000007FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

    #Hardcoded gensis block
    blockchain = [
        {
            "type": BLOCK,
            "id": "b4b9b8f78ab3dc70833a19bf7f2a0226885ae2416d41f4f0f798762560b81b60",
            "nonce": "1950b006f9203221515467fe14765720",
            "pow": "00000027e2eb250f341b05ffe24f43adae3b8181739cd976ea263a4ae0ff8eb7",
            "prev": "b4b9b8f78ab3dc70833a19bf7f2a0226885ae2416d41f4f0f798762560b81b60",
            "tx": {
                "type": TRANSACTION,
                "input": {
                    "id": "0000000000000000000000000000000000000000000000000000000000000000",
                    "n": 0
                },
                "sig": "adf494f10d30814fd26c6f0e1b2893d0fb3d037b341210bf23ef9705479c7e90879f794a29960d3ff13b50ecd780c872",
                "output": [
                    {
                        "value": 50,
                        "pub_key": "c26cfef538dd15b6f52593262403de16fa2dc7acb21284d71bf0a28f5792581b4a6be89d2a7ec1d4f7849832fe7b4daa"
                    }
                ]
            }
        }
    ]
    utx = []
  
    def __init__(self, host, port, id=None, callback=None, max_connections=0):
        super(ZachCoinClient, self).__init__(host, port, id, callback, max_connections)

    def outbound_node_connected(self, connected_node):
        print("outbound_node_connected: " + connected_node.id)
        
    def inbound_node_connected(self, connected_node):
        print("inbound_node_connected: " + connected_node.id)

    def inbound_node_disconnected(self, connected_node):
        print("inbound_node_disconnected: " + connected_node.id)

    def outbound_node_disconnected(self, connected_node):
        print("outbound_node_disconnected: " + connected_node.id)

    def node_message(self, connected_node, data):
        #print("node_message from " + connected_node.id + ": " + json.dumps(data,indent=2))
        print("node_message from " + connected_node.id)

        if data != None:
            if 'type' in data:
                if data['type'] == self.TRANSACTION:
                    self.utx.append(data)
                elif data['type'] == self.BLOCKCHAIN:
                    self.blockchain = data['blockchain']
                elif data['type'] == self.UTXPOOL:
                    self.utx = data['utxpool']
                elif data['type'] == self.BLOCK:
                    if self.validate_block(data):
                        print("Successfully added block to the blockchain - Block ID: ", data['id'])
                        # remove the validated transactions we just did
                        def remove_transactions(x : dict):
                            if x['input']['id'] != data['tx']['input']['id']:
                                return x
                            
                        self.utx = list(map(remove_transactions, self.utx))
                        self.blockchain.append(data)
                    else:
                        print("Unable to add block to blockchain, invalid block")



    def validate_block(self, block : dict) -> bool:
        # check type
        if  'type' not in block or  block['type'] != self.BLOCK:
            print("block type incorrect")
            return False

        # validate block ID and previous block
        if 'tx' not in block or 'id' not in block or 'prev' not in block:
            print("Missing field(s) in block")
            return False
        
        valid_id = hashlib.sha256(json.dumps(block['tx'], sort_keys=True).encode('utf8')).hexdigest()
        prev_id = self.blockchain[-1]['id'] 
        if block['id'] != valid_id and block['prev'] != prev_id:
            print("prev block or block id incorrect")
            return False

        if 'pow' not in block or int(block['pow'], 16) > self.DIFFICULTY:
            print("pow incorrect")
            return False
        
        return self.validate_tx(block['tx'], True)
    

    def validate_tx(self, block_tx : dict, valid_block : bool = False) -> bool:
        
        if not 'type' in block_tx or not 'input' in block_tx:
            return False
        if not 'id' in block_tx['input'] or not 'n' in block_tx['input']:
            return False
        for output in block_tx['output']:
            if not 'value' in output or not 'pub_key' in output:
                return False
        if block_tx['type'] != self.TRANSACTION:
            return False
        # check if input is in blockchain
        if block_tx['input']['id'] not in [block['id'] for block in self.blockchain]:
            print("given block doesnt exist on blockchain")
            return False
        

        input_block_id = block_tx['input']['id']
        input_block = next((block for block in self.blockchain if block["id"] == input_block_id), None)
        
        # check if n tag exists
        
        if 'output' not in block_tx:
            print("output line 137")
            return False
        
        for output in block_tx['output']:
            if not 'value' in output or not 'pub_key' in output:
                return False
        
        if 'n' not in block_tx['input'] \
            or len(block_tx['output']) <= block_tx["input"]["n"] \
             or 0 > block_tx["input"]["n"]:
            print("n failure at 143")
            return False
        
        input_n = block_tx["input"]["n"]

        # Check if the input is unspent
        for valid_block in self.blockchain:
            valid_block_id = valid_block["tx"]["input"]["id"] 
            valid_block_n = valid_block["tx"]["input"]["n"]
            if input_block_id == valid_block_id and input_n == valid_block_n:
                print("Given input has already been spent")
                return False

        # Verify outputs
        if valid_block:
            # check length of output dict is 2
            if len(block_tx["output"]) != 2 or \
              block_tx['output'][-1]['value'] != self.COINBASE:
                print("Malformed output or output length wrong")
                return False
            
            total_val = 0
            # check to see if all outputs are positive ints
            for output in block_tx['output']:
                if output['value'] < 0:
                    print("value negative 168")
                    return False
                total_val += output['value']

            if (total_val - self.COINBASE)  != input_block['tx']['output'][block_tx['input']['n']]['value']:
                print("math aint mathing 173")
                return False

        
        # Verifying the signature
        if 'pub_key' not in input_block['tx']['output'][input_n]:
            print("pubkey aint keying 179")
            return False
        
        public_key = input_block['tx']['output'][input_n]['pub_key']

        if 'sig' in block_tx:
            print("no signature found")
            return False

        vk = VerifyingKey.from_string(bytes.fromhex(public_key))
        try:
            vk.verify(bytes.fromhex(block_tx['sig']), json.dumps(block_tx['input'], sort_keys=True).encode('utf8'))
            print("key got verfied!")
        except:
            print("Signature validation has failed")
            return False
    
        return True
    
    def create_tx(self, skey : SigningKey, chosen_id, chosen_output, recipients, amounts):
        rec_amt_zip = zip(recipients, amounts)
        outputs = []
        for pair in rec_amt_zip:
            outputs.append({'value': pair[1], 'pub_key': pair[0]})
        print(outputs)
        input_json = {
            'id': chosen_id,
            'n': chosen_output
        }

        sign = skey.sign(json.dumps(input_json, sort_keys=True).encode("utf-8")).hex()
        print("here")
        utx_json = {
            'type': self.TRANSACTION,
            'input': input_json,
            'sig': sign,
            'output': outputs
        }
        print("here2")
        return utx_json

    def node_disconnect_with_outbound_node(self, connected_node):
        print("node wants to disconnect with oher outbound node: " + connected_node.id)
        
    def node_request_to_stop(self):
        print("node is requested to stop!")

def fetch_unspent_tx(client: ZachCoinClient, key : VerifyingKey):
    result = []
    for row, block in enumerate(client.blockchain):
        for col, output in enumerate(block['tx']['output']):
            if output['pub_key'] == key.to_string().hex():
                spent = False
                for blocks_spent in client.blockchain:
                    if blocks_spent['tx']['input']['id'] == block['id'] and blocks_spent['tx']['input']['n'] == col:
                        spent = True
                        break
                if not spent:
                    result.append((row, col))
    return result

def fetch_tx_choice(client: ZachCoinClient, key : VerifyingKey):
    unspent_txs = fetch_unspent_tx(client, key)
    # show user all available transaction blocks on the blockchain to pick
    print("All available transaction blocks in the blockchain")
    for idx, utx_block in enumerate(unspent_txs):
        # unravel each tuple
        block_idx, output_idx = utx_block
        # printing a formatted string to show user details of each unspent tx block
        print(f"(Transaction#: {idx})\nBlock Index: {block_idx}\nOutput Index: {output_idx}\nBlockData: {json.dumps(client.blockchain[block_idx]['tx']['output'][output_idx])}")
    client_choice = input("Enter number associated with transaction output: ")
    try:
        client_choice = int(client_choice)
    except:
        print("conversion error")
        raise Exception("Invalid choice")
    

    block_idx, output_idx = unspent_txs[client_choice]

    return client.blockchain[block_idx]['tx']['output'][output_idx]['value'], client.blockchain[block_idx]['id'], output_idx

def process_tx(client: ZachCoinClient, skey : SigningKey,key : VerifyingKey):
    try:
        total_val, chosen_id, chosen_n = fetch_tx_choice(client, key)
        print(f"\nChosen Block ID: {chosen_id}\nChosen Output Number: {chosen_n}")

        recipients = []
        quanities = []

        recipient = input("Enter recipient's public key: ")
        quantity = input ("Enter transaction quanity: ")
        print(total_val)
        
        recipient2 = input("(Optional, leave blank) Enter the second recipient's public key -> ")
        if recipient2:
            quantity2 = input("Enter the amount to send -> ")
        else:
            quantity2 = None

        try:
            quantity = int(quantity)
            if quantity <= 0:
                print("Transfer quantity must be greater than 0")
                raise Exception("Invalid transaction quantity")
            
            if quantity < total_val:
                selfrep = "c618eaea8d1dbb7c01f619c4f3a50347e1eacad9d1d2c08b43369311584ed1d45bde697a83ff5b4b05a66b2737acbb21"
                selfval = total_val - quantity
                recipients.append(selfrep)
                quanities.append(selfval)


            # quantity2 = int(quantity2) 
            # if quantity2 <= 0:
            #     print("Transfer quantity must be greater than 0")
            #     raise Exception("Invalid transaction quantity")
            recipients.append(recipient)
            
            # recipients.append(recipient2)
            quanities.append(quantity)
            # quanities.append(quantity2)
        except:
            raise Exception("Malformed data type for transaction quantity")
        
        utx_data = client.create_tx(skey, chosen_id, chosen_n, recipients, quanities)

        print(f"Creating transaction...{json.dumps(utx_data, indent=1)}")

        client.send_to_nodes(utx_data)
        return
    except:
        print("Failure to create/process transaction, try again")
        return

def mine_tx(client: ZachCoinClient, vk: VerifyingKey):
    if len(client.utx) == 0:
        print("Error: No unverified transactions in pool to mine.")
        return
    # prompt user to select a transaction to mine
    print("Select an unverified transaction from the UTX pool:")
    for i, utx in enumerate(client.utx):
        print("*****************************")
        print(f"Unverified Transaction Number: {i} \n{json.dumps(utx, indent=1)}")
        print("*****************************")
    choice = input("Enter the transaction number:  ")
    try:
        choice = int(choice)
    except:
        print("Error: Invalid transaction number.")
        return None

    # check if transaction number is valid
    if choice < 0 or choice >= len(client.utx):
        print("Error: Invalid transaction number.")
        return None
    utx =  client.utx[choice]

    # get previous block
    prev = client.blockchain[-1]['id']
    print(json.dumps(prev))

    utx['output'].append({
            "value": client.COINBASE,
            "pub_key": vk.to_string().hex()
        })

    # mine transaction
    print("Mining block with ID ", utx['input']['id'])

    # generate nonce until hash is less than difficulty
    nonce = Random.new().read(AES.block_size).hex()
    while int(hashlib.sha256(json.dumps(utx, sort_keys=True).encode('utf8') + prev.encode('utf-8') + nonce.encode('utf-8')).hexdigest(), 16) > client.DIFFICULTY:
        nonce = Random.new().read(AES.block_size).hex()

    pow = hashlib.sha256(json.dumps(utx, sort_keys=True).encode(
        'utf8') + prev.encode('utf-8') + nonce.encode('utf-8')).hexdigest()

    prev = client.blockchain[-1]['id']
    # create block
    block = {
        "type": client.BLOCK,
        "id": hashlib.sha256(json.dumps(utx, sort_keys=True).encode('utf8')).hexdigest(),
        "nonce": nonce,
        "pow": pow,
        "prev": prev,
        "tx": utx
    }
    print("Transaction successfully mined")
    print(json.dumps(block, indent=1))
    client.send_to_nodes(block)

def get_transaction_history(client: ZachCoinClient, vk: VerifyingKey):
    """
    Get the transaction history for a user
    """
    transaction_history = []
    for block in client.blockchain:
        for output in block['tx']['output']:
            if output['pub_key'] == vk.to_string().hex():
                transaction_history.append({
                    'block_id': block['id'],
                    'output_index': block['tx']['output'].index(output),
                    'value': output['value'],
                    'recipient': output['pub_key']
                })
    # print transaction history
    print("Transaction History:")
    for transaction in transaction_history:
        print("-" * 20)
        print(f"Block ID: {transaction['block_id']}")
        print(f"Output Index: {transaction['output_index']}")
        print(f"Value: {transaction['value']}")
        print(f"Recipient: {transaction['recipient']}")
        print("-" * 20)

def main():

    if len(sys.argv) < 3:
        print("Usage: python3", sys.argv[0], "CLIENTNAME PORT")
        quit()

    #Load keys, or create them if they do not yet exist
    keypath = './' + sys.argv[1] + '.key'
    if not os.path.exists(keypath):
        sk = SigningKey.generate()
        vk = sk.verifying_key
        with open(keypath, 'w') as f:
            f.write(sk.to_string().hex())
            f.close()
    else:
        with open(keypath) as f:
            try:
                sk = SigningKey.from_string(bytes.fromhex(f.read()))
                vk = sk.verifying_key
            except Exception as e:
                print("Couldn't read key file", e)

    #Create a client object
    client = ZachCoinClient("127.0.0.1", int(sys.argv[2]), sys.argv[1])
    client.debug = False

    time.sleep(1)

    client.start()

    time.sleep(1)

    #Connect to server 
    client.connect_with_node(SERVER_ADDR, SERVER_PORT)
    print("Starting ZachCoin™ Client:", sys.argv[1])
    time.sleep(2)

    while True:
        os.system('cls' if os.name=='nt' else 'clear')
        slogan = " You can't spell \"It's a Ponzi scheme!\" without \"ZachCoin\" "
        print("=" * (int(len(slogan)/2) - int(len(' ZachCoin™')/2)), 'ZachCoin™', "=" * (int(len(slogan)/2) - int(len('ZachCoin™ ')/2)))
        print(slogan)
        print("=" * len(slogan),'\n')
        x = input("\t0: Print keys \
                  \n\t1: Print blockchain \
                  \n\t2: Print UTX pool \
                  \n\t3: Make Transaction \
                  \n\t4: Mine Transactions \
                  \n\t5: Get History \
                  \n\t6: Stop Client \
                  \n\nEnter your choice -> ")
        try:
            x = int(x)
        except:
            print("Error: Invalid menu option.")
            input()
            continue
        if x == 0:
            print("sk: ", sk.to_string().hex())
            print("vk: ", vk.to_string().hex())
        elif x == 1:
            print(json.dumps(client.blockchain, indent=1))
        elif x == 2:
            print(json.dumps(client.utx, indent=1))
        elif x == 3:
            process_tx(client, sk, vk)
        elif x == 4:
            mine_tx(client, vk)
        elif x == 5:
            get_transaction_history(client, vk)
        elif x == 5:
            client.stop()
            break

        input()
        
if __name__ == "__main__":
    main()