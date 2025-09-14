
#[macro_use]
extern crate rocket;
use rocket::State;
use rocket::http::Status;
use rocket::response::content::RawJson;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use secp256k1::{Secp256k1, SecretKey, PublicKey};
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize, Clone)]
struct Transaction {
    from: String,
    to: String,
    amount: f64,
    signature: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct Block {
    index: u32,
    timestamp: u64,
    transactions: Vec<Transaction>,
    previous_hash: String,
    hash: String,
    validator: String,
}

impl Block {
    fn new(index: u32, transactions: Vec<Transaction>, previous_hash: String, validator: String) -> Block {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut block = Block {
            index,
            timestamp,
            transactions,
            previous_hash,
            hash: String::new(),
            validator,
        };
        block.hash = block.calculate_hash();
        block
    }

    fn calculate_hash(&self) -> String {
        let input = format!(
            "{}{}{}{}",
            self.index,
            self.timestamp,
            serde_json::to_string(&self.transactions).unwrap(),
            self.previous_hash
        );
        let mut hasher = Sha256::new();
        hasher.update(input);
        let result = hasher.finalize();
        hex::encode(result)
    }
}

#[derive(Serialize, Deserialize, Clone)]
struct Blockchain {
    chain: Vec<Block>,
    balances: HashMap<String, f64>,
    pending_transactions: Vec<Transaction>,
    validators: HashMap<String, f64>,
}

impl Blockchain {
    fn new() -> Blockchain {
        let mut blockchain = Blockchain {
            chain: vec![],
            balances: HashMap::new(),
            pending_transactions: vec![],
            validators: HashMap::new(),
        };
        blockchain.create_genesis_block();
        blockchain
    }

    fn create_genesis_block(&mut self) {
        let genesis_block = Block::new(0, vec![], "0".to_string(), "genesis_validator".to_string());
        self.chain.push(genesis_block);
        // Инициализация тестовых кошельков
        let alice_address = "alice_address_1234567890abcdef1234567890abcdef1234";
        let bob_address = "bob_address_abcdef1234567890abcdef1234567890ab";
        self.balances.insert(alice_address.to_string(), 100.0);
        self.balances.insert(bob_address.to_string(), 50.0);
        println!("Баланс Alice ({}): {}", alice_address, self.balances[alice_address]);
        println!("Баланс Bob ({}): {}", bob_address, self.balances[bob_address]);
    }

    fn add_block(&mut self, transactions: Vec<Transaction>, validator: String, test_mode: bool) -> Result<(), String> {
        if !test_mode {
            // Реальная проверка подписи (будет добавлена позже)
            return Err("Реальная проверка подписи не реализована".to_string());
        }

        let previous_block = self.chain.last().ok_or("Цепочка пуста".to_string())?;
        let index = previous_block.index + 1;
        let previous_hash = previous_block.hash.clone();
        let new_block = Block::new(index, transactions.clone(), previous_hash, validator.clone());

        // Обновление балансов
        for tx in &transactions {
            if !test_mode {
                // Реальная проверка подписи (будет добавлена позже)
            }
            let from_balance = self.balances.get(&tx.from).copied().unwrap_or(0.0);
            if from_balance < tx.amount {
                return Err(format!("Недостаточно средств у {}", tx.from));
            }
            *self.balances.entry(tx.from.clone()).or_insert(0.0) -= tx.amount;
            *self.balances.entry(tx.to.clone()).or_insert(0.0) += tx.amount;
        }

        // Награда валидатору
        *self.validators.entry(validator.clone()).or_insert(0.0) += 1.0;
        println!("Баланс валидатора {} после награды: {}", validator, self.get_balance(&validator));

        self.chain.push(new_block);
        self.pending_transactions.clear();
        Ok(())
    }

    fn add_transaction(&mut self, transaction: Transaction, test_mode: bool) -> Result<(), String> {
        if !test_mode {
            // Реальная проверка подписи (будет добавлена позже)
            return Err("Реальная проверка подписи не реализована".to_string());
        }
        self.pending_transactions.push(transaction);
        if self.pending_transactions.len() >= 2 {
            let transactions = self.pending_transactions.clone();
            let validator = self.choose_validator();
            self.add_block(transactions, validator, test_mode)?;
        }
        Ok(())
    }

    fn get_balance(&self, address: &str) -> f64 {
        *self.balances.get(address).unwrap_or(&0.0)
    }

    fn is_chain_valid(&self) -> bool {
        for i in 1..self.chain.len() {
            let current_block = &self.chain[i];
            let previous_block = &self.chain[i - 1];

            if current_block.hash != current_block.calculate_hash() {
                return false;
            }

            if current_block.previous_hash != previous_block.hash {
                return false;
            }
        }
        true
    }

    fn choose_validator(&self) -> String {
        let total_stake: f64 = self.validators.values().sum();
        if total_stake == 0.0 {
            return "default_validator".to_string();
        }
        let mut rng = OsRng;
        let rand_value = rand::Rng::gen_range(&mut rng, 0.0..total_stake);
        let mut cumulative = 0.0;
        for (address, stake) in &self.validators {
            cumulative += stake;
            if rand_value <= cumulative {
                return address.clone();
            }
        }
        self.validators.keys().next().unwrap().clone()
    }
}

#[derive(Serialize, Deserialize)]
struct Wallet {
    private_key: String,
    public_key: String,
    address: String,
}

#[post("/wallet")]
fn create_wallet() -> RawJson<String> {
    let secp = Secp256k1::new();
    let mut rng = OsRng;
    let (private_key, public_key) = secp.generate_keypair(&mut rng);
    let private_key_hex = hex::encode(private_key.secret_bytes());
    let public_key_hex = hex::encode(public_key.serialize());
    let address = {
        let mut hasher = Sha256::new();
        hasher.update(&public_key_hex);
        let result = hasher.finalize();
        hex::encode(&result[..20])
    };
    let wallet = Wallet {
        private_key: private_key_hex,
        public_key: public_key_hex,
        address,
    };
    println!("Адрес: {}", wallet.address);
    println!("Приватный ключ: {}", wallet.private_key);
    RawJson(json!(wallet).to_string())
}

#[get("/blocks")]
fn get_blocks(blockchain: &State<Mutex<Blockchain>>) -> Json<Vec<Block>> {
    let blockchain = blockchain.lock().unwrap();
    Json(blockchain.chain.clone())
}

#[get("/balance/<address>")]
fn get_balance(blockchain: &State<Mutex<Blockchain>>, address: String) -> Json<f64> {
    let blockchain = blockchain.lock().unwrap();
    let balance = blockchain.get_balance(&address);
    println!("Запрос баланса для {}: {}", address, balance);
    Json(balance)
}

#[get("/status")]
fn get_status(blockchain: &State<Mutex<Blockchain>>) -> Json<bool> {
    let blockchain = blockchain.lock().unwrap();
    Json(blockchain.is_chain_valid())
}

#[post("/transaction", data = "<transaction>")]
fn post_transaction(blockchain: &State<Mutex<Blockchain>>, transaction: Json<Transaction>) -> Result<String, Status> {
    let mut blockchain = blockchain.lock().unwrap();
    let test_mode = true; // Тестовый режим
    match blockchain.add_transaction(transaction.into_inner(), test_mode) {
        Ok(()) => {
            println!("Тестовый режим: проверка подписи пропущена для {}", transaction.from);
            Ok("Транзакция добавлена".to_string())
        }
        Err(e) => Err(Status::BadRequest),
    }
}

#[get("/transactions")]
fn get_transactions(blockchain: &State<Mutex<Blockchain>>) -> Json<Vec<Transaction>> {
    let blockchain = blockchain.lock().unwrap();
    Json(blockchain.pending_transactions.clone())
}

#[get("/validators")]
fn get_validators(blockchain: &State<Mutex<Blockchain>>) -> Json<HashMap<String, f64>> {
    let blockchain = blockchain.lock().unwrap();
    Json(blockchain.validators.clone())
}

#[launch]
fn rocket() -> _ {
    rocket::build()
        .manage(Mutex::new(Blockchain::new()))
        .mount("/", routes![get_blocks, get_balance, get_status, post_transaction, create_wallet, get_transactions, get_validators])
        .mount("/static", rocket::fs::FileServer::from("static"))
}
