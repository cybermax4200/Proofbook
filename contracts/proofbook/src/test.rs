#![cfg(test)]

use super::*;
use soroban_sdk::{testutils::Address as _, BytesN, Env};

#[test]
fn test_register_org_and_duplicate() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(Proofbook, ());
    let client = ProofbookClient::new(&env, &contract_id);

    let org = Address::generate(&env);

    // First registration succeeds
    client.register_org(&org);

    // Second registration fails with OrgAlreadyRegistered
    let res = client.try_register_org(&org);
    assert_eq!(res, Err(Ok(Error::OrgAlreadyRegistered)));
}

#[test]
fn test_anchor_requires_registration() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(Proofbook, ());
    let client = ProofbookClient::new(&env, &contract_id);

    let org = Address::generate(&env);
    let root = BytesN::from_array(&env, &[1u8; 32]);

    let res = client.try_anchor_checkpoint(&org, &root, &10, &100, &200);
    assert_eq!(res, Err(Ok(Error::OrgNotRegistered)));
}

#[test]
fn test_anchor_period_regression() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(Proofbook, ());
    let client = ProofbookClient::new(&env, &contract_id);

    let org = Address::generate(&env);
    client.register_org(&org);

    let root = BytesN::from_array(&env, &[1u8; 32]);

    // period_end < period_start fails immediately
    let res = client.try_anchor_checkpoint(&org, &root, &10, &300, &200);
    assert_eq!(res, Err(Ok(Error::PeriodRegression)));
}

#[test]
fn test_anchor_chain_and_count_decreased() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(Proofbook, ());
    let client = ProofbookClient::new(&env, &contract_id);

    let org = Address::generate(&env);
    client.register_org(&org);

    let root1 = BytesN::from_array(&env, &[1u8; 32]);
    let root2 = BytesN::from_array(&env, &[2u8; 32]);

    // Checkpoint 1
    let id1 = client.anchor_checkpoint(&org, &root1, &10, &1000, &2000);
    assert_eq!(id1, 1);

    let cp1 = client.get_checkpoint(&org, &1);
    assert_eq!(cp1.id, 1);
    assert_eq!(cp1.root, root1);
    assert_eq!(cp1.prev_root, BytesN::from_array(&env, &[0u8; 32]));
    assert_eq!(cp1.record_count, 10);
    assert_eq!(cp1.period_start, 1000);
    assert_eq!(cp1.period_end, 2000);

    // Checkpoint 2 with decreased count fails
    let res = client.try_anchor_checkpoint(&org, &root2, &9, &2000, &3000);
    assert_eq!(res, Err(Ok(Error::CountDecreased)));

    // Checkpoint 2 with period before cp1 period_end fails
    let res2 = client.try_anchor_checkpoint(&org, &root2, &15, &1999, &3000);
    assert_eq!(res2, Err(Ok(Error::PeriodRegression)));

    // Valid Checkpoint 2 succeeds
    let id2 = client.anchor_checkpoint(&org, &root2, &15, &2000, &3000);
    assert_eq!(id2, 2);

    let cp2 = client.get_checkpoint(&org, &2);
    assert_eq!(cp2.id, 2);
    assert_eq!(cp2.root, root2);
    assert_eq!(cp2.prev_root, root1); // Chain linkage verified!
    assert_eq!(cp2.record_count, 15);

    // Latest checkpoint getter
    let latest = client.latest_checkpoint(&org);
    assert_eq!(latest.id, 2);
    assert_eq!(latest.root, root2);
}

#[test]
fn test_auditor_witnessing_flow() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(Proofbook, ());
    let client = ProofbookClient::new(&env, &contract_id);

    let org = Address::generate(&env);
    let auditor = Address::generate(&env);
    let root = BytesN::from_array(&env, &[42u8; 32]);
    let wrong_root = BytesN::from_array(&env, &[99u8; 32]);

    client.register_org(&org);
    let cp_id = client.anchor_checkpoint(&org, &root, &5, &100, &200);

    // Witnessing before authorization fails
    let res = client.try_witness_checkpoint(&org, &cp_id, &auditor, &root);
    assert_eq!(res, Err(Ok(Error::AuditorNotAuthorized)));

    // Authorize auditor
    client.authorize_auditor(&org, &auditor);

    // Witnessing with mismatched root fails
    let res_mismatch = client.try_witness_checkpoint(&org, &cp_id, &auditor, &wrong_root);
    assert_eq!(res_mismatch, Err(Ok(Error::RootMismatch)));

    // Successful witness
    assert!(!client.is_witnessed_by(&org, &cp_id, &auditor));
    client.witness_checkpoint(&org, &cp_id, &auditor, &root);
    assert!(client.is_witnessed_by(&org, &cp_id, &auditor));

    // Duplicate witness fails
    let res_dup = client.try_witness_checkpoint(&org, &cp_id, &auditor, &root);
    assert_eq!(res_dup, Err(Ok(Error::AlreadyWitnessed)));

    // Revoke auditor
    client.revoke_auditor(&org, &auditor);

    // Future witness on another checkpoint fails because revoked
    let root_b = BytesN::from_array(&env, &[43u8; 32]);
    let cp_b = client.anchor_checkpoint(&org, &root_b, &6, &200, &300);
    let res_revoked = client.try_witness_checkpoint(&org, &cp_b, &auditor, &root_b);
    assert_eq!(res_revoked, Err(Ok(Error::AuditorNotAuthorized)));
}
