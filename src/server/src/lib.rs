use candid::{CandidType, Decode, Deserialize, Encode, Principal};
use ic_cdk::api::msg_caller;
use ic_cdk::{export_candid, query, update};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::storable::Bound;
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap, StableCell, Storable};
// use jsonwebtoken::{
//     decode, encode, Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation,
// };
use serde::Serialize;
use std::borrow::Cow;
use std::cell::RefCell;
use std::hash::{DefaultHasher, Hash, Hasher};
type Memory = VirtualMemory<DefaultMemoryImpl>;
type NoteId = u128;

impl Storable for UserIdentity {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }
    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
    fn into_bytes(self) -> Vec<u8> {
        Encode!(&self).unwrap()
    }
    const BOUND: Bound = Bound::Unbounded;
}
#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq, PartialOrd, Ord)]
pub struct UserIdentity(u64);

#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub struct EncryptedNote {
    id: NoteId,
    encrypted_text: String,
    owner: UserIdentity,
}

impl EncryptedNote {
    pub fn is_authorized(&self, user: &UserIdentity) -> bool {
        user == &self.owner
    }
}

impl Storable for EncryptedNote {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }
    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
    fn into_bytes(self) -> Vec<u8> {
        Encode!(&self).unwrap()
    }
    const BOUND: Bound = Bound::Unbounded;
}

#[derive(CandidType, Deserialize, Default)]
pub struct NoteIds {
    ids: Vec<NoteId>,
}

impl NoteIds {
    pub fn iter(&self) -> impl std::iter::Iterator<Item = &NoteId> {
        self.ids.iter()
    }
}

impl Storable for NoteIds {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }
    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
    fn into_bytes(self) -> Vec<u8> {
        Encode!(&self).unwrap()
    }
    const BOUND: Bound = Bound::Unbounded;
}

#[derive(CandidType, Deserialize, Default)]
pub struct User {
    name: String,
    email: String,
    password: String,
    age: u32,
    bio: String,
    avatar: String,
}

impl Hash for User {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.email.hash(state);
        self.password.hash(state);
    }
}

impl User {
    fn register(register_data: RegisterData) -> Self {
        User {
            name: register_data.name,
            email: register_data.email,
            password: register_data.password,
            age: register_data.age,
            bio: register_data.bio,
            avatar: register_data.avatar,
        }
    }
    fn login(email: String, password: String) -> Self {
        User {
            email,
            password,
            ..Default::default()
        }
    }
    pub fn calculate_hash(&self) -> u64 {
        let hash = self.hash(&mut DEFAULT_HASHER.take());
        calculate_hash(&hash)
    }
}

fn calculate_hash<T: Hash>(t: &T) -> u64 {
    let mut s = DefaultHasher::new();
    t.hash(&mut s);
    s.finish()
}
impl Storable for User {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }
    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
    fn into_bytes(self) -> Vec<u8> {
        Encode!(&self).unwrap()
    }
    const BOUND: Bound = Bound::Unbounded;
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
    iat: usize,
    iss: String,
}

#[query]
pub fn get_health_data() -> String {
    "Health data".to_string()
}

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    static DEFAULT_HASHER: RefCell<DefaultHasher> =
        RefCell::new(DefaultHasher::new());

    static NEXT_NOTE_ID: RefCell<StableCell<NoteId, Memory>> = RefCell::new(
        StableCell::init(
            MEMORY_MANAGER.with_borrow(|m| m.get(MemoryId::new(0))),
            1
        )
    );

    static NOTES: RefCell<StableBTreeMap<NoteId, EncryptedNote, Memory>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with_borrow(|m| m.get(MemoryId::new(1))),
        )
    );

    static NOTE_OWNERS: RefCell<StableBTreeMap<UserIdentity, NoteIds, Memory>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with_borrow(|m| m.get(MemoryId::new(2))),
        )
    );

    static USERS: RefCell<StableBTreeMap<UserIdentity, User, Memory>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with_borrow(|m| m.get(MemoryId::new(4))),
        )
    );

    static ACTIVE_SESSIONS: RefCell<StableBTreeMap<u64, String, Memory>> = RefCell::new(
            StableBTreeMap::init(
                MEMORY_MANAGER.with_borrow(|m| m.get(MemoryId::new(5))),
            )
        );
}

#[query]
fn caller(token: Option<String>) -> Principal {
    let caller = msg_caller();
    if token.is_some() {
        if !validate_session(token.unwrap()) {
            panic!("cant verify")
        }
    } else if caller == Principal::anonymous() {
        panic!("Anonymous principal not allowed to make calls.")
    }
    caller
}

// fn generate_token(hash: u64) -> Result<String, jsonwebtoken::errors::Error> {
//     let secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
//     let key = EncodingKey::from_secret(secret.as_ref());

//     let claims = Claims {
//         sub: hash.to_string(),
//         exp: (chrono::Utc::now() + chrono::Duration::hours(24)).timestamp() as usize,
//         iat: chrono::Utc::now().timestamp() as usize,
//         iss: "healthchain".to_string(),
//     };

//     encode(&Header::default(), &claims, &key)
// }

// fn validate_token(token: String) -> Result<TokenData<Claims>, jsonwebtoken::errors::Error> {
//     let secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
//     let mut validation = Validation::new(Algorithm::HS256);
//     validation.set_issuer(&["your-app"]);
//     validation.validate_exp = true;
//     validation.validate_nbf = true;

//     let key = DecodingKey::from_secret(secret.as_ref());
//     decode::<Claims>(&token, &key, &validation)
// }

use ic_cdk::api::time;

fn generate_token(hash: u64) -> String {
    let timestamp = time();
    let token_data = format!("{}:{}:{}", hash, timestamp, "healthchain");
    let token_hash = calculate_hash(&token_data);
    let token = format!("hc_{}_{}", hash, token_hash);
    ACTIVE_SESSIONS.with_borrow_mut(|sessions| {
        sessions.insert(hash, token.clone());
    });
    token
}

#[update]
fn validate_session(token: String) -> bool {
    if let Some(hash_str) = token.strip_prefix("hc_").and_then(|s| s.split('_').next()) {
        if let Ok(hash) = hash_str.parse::<u64>() {
            return ACTIVE_SESSIONS.with(|sessions| {
                sessions
                    .borrow()
                    .get(&hash)
                    .map(|stored_token| stored_token == token)
                    .unwrap_or(false)
            });
        }
    }
    false
}

#[query]
fn whoami() -> String {
    msg_caller().to_string()
}

#[derive(CandidType, Deserialize)]
pub struct RegisterData {
    username: String,
    email: String,
    password: String,
    age: u32,
    bio: String,
    avatar: String,
    name: String,
}

#[update]
fn register_user(register_data: RegisterData) -> String {
    let user = User::register(register_data);
    let hash = user.calculate_hash();
    let user = USERS.with(|users| users.borrow_mut().insert(UserIdentity(hash), user));
    generate_token(hash)
}

#[update]
fn login_user(email: String, password: String) -> String {
    let user = User::login(email, password);
    let hash_calc = user.calculate_hash();
    let user = USERS.with(|users| users.borrow().get(&UserIdentity(hash_calc)));
    if user.is_some() {
        generate_token(hash_calc)
    } else {
        panic!("User not Found")
    }
}

// #[update]
// fn register_icp(register_data: RegisterData) {
//     let caller = caller();
//     USERS.with_borrow_mut(|users| {
//         users.insert(
//             UserIdentity::InternetIdentity(caller),
//             User::new(register_data),
//         );
//     });
// }

export_candid!();
