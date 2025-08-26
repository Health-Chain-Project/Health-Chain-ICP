use candid::{CandidType, Decode, Deserialize, Encode, Principal};
use ic_cdk::api::msg_caller;
use ic_cdk::api::time;
use ic_cdk::{export_candid, query, update};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::storable::Bound;
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap, StableCell, Storable};
use serde::Serialize;
use std::borrow::Cow;
use std::cell::RefCell;
use std::hash::{DefaultHasher, Hash, Hasher};
type Memory = VirtualMemory<DefaultMemoryImpl>;
type NoteId = u128;
type HashedEmail = String;

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

#[derive(CandidType, Deserialize, Default, Clone)]
pub struct HashedEmails {
    emails: Vec<HashedEmail>,
}

impl HashedEmails {
    pub fn new() -> Self {
        Self { emails: Vec::new() }
    }
    pub fn iter(&self) -> impl std::iter::Iterator<Item = &HashedEmail> {
        self.emails.iter()
    }
}

impl Storable for HashedEmails {
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

#[derive(CandidType, Deserialize, Default, Debug)]
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
    fn login(login_data: LoginrData) -> Self {
        User {
            email: login_data.email,
            password: login_data.password,
            ..Default::default()
        }
    }
    pub fn calculate_hash(&self) -> u64 {
        calculate_hash(&self)
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

    static REGISTERED_EMAILS: RefCell<StableCell<HashedEmails, Memory>> = RefCell::new(
        StableCell::init(
            MEMORY_MANAGER.with_borrow(|m| m.get(MemoryId::new(1))),
            HashedEmails::new()
        )
    );


    static NOTES: RefCell<StableBTreeMap<NoteId, EncryptedNote, Memory>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with_borrow(|m| m.get(MemoryId::new(2))),
        )
    );

    static NOTE_OWNERS: RefCell<StableBTreeMap<UserIdentity, NoteIds, Memory>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with_borrow(|m| m.get(MemoryId::new(3))),
        )
    );

    static USERS: RefCell<StableBTreeMap<u64, User, Memory>> = RefCell::new(
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
    if let Some(token) = token {
        if !validate_session(token) {
            panic!("cant verify")
        }
    } else if caller == Principal::anonymous() {
        panic!("Anonymous principal not allowed to make calls.")
    }
    caller
}

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

#[query]
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

#[query]
fn whoami_token(token: String) -> Option<User> {
    if let Some(hash_str) = token.strip_prefix("hc_").and_then(|s| s.split('_').next()) {
        if let Ok(hash) = hash_str.parse::<u64>() {
            return USERS.with(|sessions| Some(sessions.borrow().get(&hash).unwrap()));
        }
    }
    None
}

#[derive(CandidType, Deserialize)]
pub struct RegisterData {
    email: String,
    password: String,
    age: u32,
    bio: String,
    avatar: String,
    name: String,
}

#[derive(CandidType, Deserialize)]
pub struct LoginrData {
    email: String,
    password: String,
}

#[update]
fn register_user(register_data: RegisterData) -> String {
    let email = register_data.email.clone();
    if REGISTERED_EMAILS.with_borrow(|emails| emails.get().emails.contains(&email)) {
        panic!("Nope")
    }
    let user = User::register(register_data);
    let hash = user.calculate_hash();
    USERS.with(|users| users.borrow_mut().insert(hash, user));
    REGISTERED_EMAILS.with_borrow_mut(|emails| {
        let mut current_emails = emails.get().clone();
        current_emails.emails.push(email);
        emails.set(current_emails)
    });
    generate_token(hash)
}

#[update]
fn login_user(login_data: LoginrData) -> String {
    let user = User::login(login_data);
    let hash_calc = user.calculate_hash();
    let user = USERS.with(|users| users.borrow().get(&hash_calc));
    if user.is_some() {
        generate_token(hash_calc)
    } else {
        panic!("User not Found")
    }
}

export_candid!();
