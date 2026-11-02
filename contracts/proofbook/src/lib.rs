#![no_std]
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, symbol_short, Address, BytesN, Env,
};

const TTL_THRESHOLD: u32 = 518_400;   // ~30 days at ~5s ledgers
const TTL_EXTEND_TO: u32 = 3_110_400; // ~180 days; clamp to network max

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    OrgAlreadyRegistered = 1,
    OrgNotRegistered = 2,
    CountDecreased = 3,
    PeriodRegression = 4,
    CheckpointNotFound = 5,
    AuditorNotAuthorized = 6,
    RootMismatch = 7,
    AlreadyWitnessed = 8,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Checkpoint {
    pub id: u32,
    pub root: BytesN<32>,
    pub prev_root: BytesN<32>,
    pub record_count: u64, // cumulative total records anchored to date
    pub period_start: u64,
    pub period_end: u64,
    pub ledger: u32,
    pub timestamp: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataKey {
    Org(Address),
    Latest(Address),                 // latest checkpoint id
    Checkpoint(Address, u32),
    Auditor(Address, Address),       // (org, auditor) -> bool
    Witness(Address, u32, Address),  // (org, checkpoint, auditor) -> ledger seq
}

#[contract]
pub struct Proofbook;

#[contractimpl]
impl Proofbook {
    pub fn register_org(env: Env, org: Address) -> Result<(), Error> {
        org.require_auth();
        let key = DataKey::Org(org.clone());
        if env.storage().persistent().has(&key) {
            return Err(Error::OrgAlreadyRegistered);
        }
        env.storage().persistent().set(&key, &true);
        Self::bump(&env, &key);
        env.events().publish((symbol_short!("org_reg"), org), ());
        Ok(())
    }

    pub fn anchor_checkpoint(
        env: Env,
        org: Address,
        root: BytesN<32>,
        record_count: u64,
        period_start: u64,
        period_end: u64,
    ) -> Result<u32, Error> {
        org.require_auth();
        let org_key = DataKey::Org(org.clone());
        if !env.storage().persistent().has(&org_key) {
            return Err(Error::OrgNotRegistered);
        }
        if period_end < period_start {
            return Err(Error::PeriodRegression);
        }

        let latest_key = DataKey::Latest(org.clone());
        let (id, prev_root) = match env.storage().persistent().get::<_, u32>(&latest_key) {
            Some(last_id) => {
                let prev: Checkpoint = env
                    .storage()
                    .persistent()
                    .get(&DataKey::Checkpoint(org.clone(), last_id))
                    .ok_or(Error::CheckpointNotFound)?;
                if record_count < prev.record_count {
                    return Err(Error::CountDecreased);
                }
                if period_start < prev.period_end {
                    return Err(Error::PeriodRegression);
                }
                (last_id + 1, prev.root)
            }
            None => (1, BytesN::from_array(&env, &[0u8; 32])),
        };

        let cp = Checkpoint {
            id,
            root: root.clone(),
            prev_root,
            record_count,
            period_start,
            period_end,
            ledger: env.ledger().sequence(),
            timestamp: env.ledger().timestamp(),
        };

        let cp_key = DataKey::Checkpoint(org.clone(), id);
        env.storage().persistent().set(&cp_key, &cp);
        env.storage().persistent().set(&latest_key, &id);

        Self::bump(&env, &org_key);
        Self::bump(&env, &cp_key);
        Self::bump(&env, &latest_key);

        env.events().publish((symbol_short!("anchor"), org, id), root);
        Ok(id)
    }

    pub fn authorize_auditor(env: Env, org: Address, auditor: Address) -> Result<(), Error> {
        org.require_auth();
        let org_key = DataKey::Org(org.clone());
        if !env.storage().persistent().has(&org_key) {
            return Err(Error::OrgNotRegistered);
        }
        let key = DataKey::Auditor(org.clone(), auditor);
        env.storage().persistent().set(&key, &true);
        Self::bump(&env, &org_key);
        Self::bump(&env, &key);
        Ok(())
    }

    pub fn revoke_auditor(env: Env, org: Address, auditor: Address) -> Result<(), Error> {
        org.require_auth();
        let org_key = DataKey::Org(org.clone());
        if !env.storage().persistent().has(&org_key) {
            return Err(Error::OrgNotRegistered);
        }
        let key = DataKey::Auditor(org.clone(), auditor);
        if !env.storage().persistent().has(&key) {
            return Err(Error::AuditorNotAuthorized);
        }
        env.storage().persistent().set(&key, &false);
        Self::bump(&env, &org_key);
        Self::bump(&env, &key);
        Ok(())
    }

    pub fn witness_checkpoint(
        env: Env,
        org: Address,
        checkpoint_id: u32,
        auditor: Address,
        root_seen: BytesN<32>,
    ) -> Result<(), Error> {
        auditor.require_auth();
        let authorized: bool = env
            .storage()
            .persistent()
            .get(&DataKey::Auditor(org.clone(), auditor.clone()))
            .unwrap_or(false);
        if !authorized {
            return Err(Error::AuditorNotAuthorized);
        }
        let cp: Checkpoint = env
            .storage()
            .persistent()
            .get(&DataKey::Checkpoint(org.clone(), checkpoint_id))
            .ok_or(Error::CheckpointNotFound)?;
        if cp.root != root_seen {
            return Err(Error::RootMismatch);
        }
        let wkey = DataKey::Witness(org.clone(), checkpoint_id, auditor.clone());
        if env.storage().persistent().has(&wkey) {
            return Err(Error::AlreadyWitnessed);
        }
        env.storage().persistent().set(&wkey, &env.ledger().sequence());
        Self::bump(&env, &wkey);
        env.events().publish((symbol_short!("witness"), org, checkpoint_id), auditor);
        Ok(())
    }

    pub fn get_checkpoint(env: Env, org: Address, id: u32) -> Result<Checkpoint, Error> {
        env.storage()
            .persistent()
            .get(&DataKey::Checkpoint(org, id))
            .ok_or(Error::CheckpointNotFound)
    }

    pub fn latest_checkpoint(env: Env, org: Address) -> Result<Checkpoint, Error> {
        let latest_key = DataKey::Latest(org.clone());
        let last_id: u32 = env
            .storage()
            .persistent()
            .get(&latest_key)
            .ok_or(Error::CheckpointNotFound)?;
        Self::get_checkpoint(env, org, last_id)
    }

    pub fn is_witnessed_by(env: Env, org: Address, id: u32, auditor: Address) -> bool {
        env.storage()
            .persistent()
            .has(&DataKey::Witness(org, id, auditor))
    }

    fn bump(env: &Env, key: &DataKey) {
        env.storage().persistent().extend_ttl(key, TTL_THRESHOLD, TTL_EXTEND_TO);
    }
}

#[cfg(test)]
mod test;
