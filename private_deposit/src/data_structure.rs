use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use mpc_core::protocols::rep3::{self, Rep3PrimeFieldShare, Rep3State};
use std::collections::HashMap;

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct DepositValue<F: PrimeField> {
    pub amount: Rep3PrimeFieldShare<F>,
    pub blinding: Rep3PrimeFieldShare<F>,
}

impl<F: PrimeField> DepositValue<F> {
    pub fn new(amount: Rep3PrimeFieldShare<F>, blinding: Rep3PrimeFieldShare<F>) -> Self {
        Self { amount, blinding }
    }
}

#[derive(Clone, Debug)]
#[repr(transparent)]
pub struct PrivateDeposit<K, V> {
    inner: HashMap<K, V>,
}

impl<K, V> Default for PrivateDeposit<K, V>
where
    K: std::hash::Hash + Eq,
{
    fn default() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }
}

impl<K, V> PrivateDeposit<K, V>
where
    K: std::hash::Hash + Eq,
{
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        self.inner.insert(key, value)
    }

    pub fn get(&self, key: &K) -> Option<&V> {
        self.inner.get(key)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.inner.iter()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn clear(&mut self) {
        self.inner.clear();
    }

    pub fn remove(&mut self, key: &K) -> Option<V> {
        self.inner.remove(key)
    }

    pub fn contains_key(&self, key: &K) -> bool {
        self.inner.contains_key(key)
    }

    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.inner.keys()
    }

    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.inner.values()
    }
}

impl<K, F: PrimeField> PrivateDeposit<K, DepositValue<F>>
where
    K: std::hash::Hash + Eq,
{
    // Returns the current deposit value for the given key
    pub fn read(&self, key: &K) -> Option<&DepositValue<F>> {
        self.get(key)
    }

    // Returns the old and the new deposit value for the given key
    pub fn deposit(
        &mut self,
        key: K,
        amount: Rep3PrimeFieldShare<F>,
        rep3_state: &mut Rep3State,
    ) -> (Option<DepositValue<F>>, DepositValue<F>) {
        let old = self.read(&key).cloned();
        let new_blinding = rep3::arithmetic::rand(rep3_state);
        let new_value = if let Some(old_value) = &old {
            old_value.amount + amount
        } else {
            amount
        };
        let new = DepositValue::new(new_value, new_blinding);
        self.insert(key, new.clone());
        (old, new)
    }

    // Returns the old and the new balance value for the given key
    pub fn withdraw(
        &mut self,
        key: K,
        amount: Rep3PrimeFieldShare<F>,
        rep3_state: &mut Rep3State,
    ) -> eyre::Result<(DepositValue<F>, DepositValue<F>)> {
        let old = self.get(&key);
        if old.is_none() {
            return Err(eyre::eyre!("Key not found in HashMap"));
        }
        let old = old.unwrap().clone();
        let new_amount = old.amount - amount;
        let new_blinding = rep3::arithmetic::rand(rep3_state);
        let new = DepositValue::new(new_amount, new_blinding);
        self.insert(key, new.clone());
        Ok((old, new))
    }

    #[expect(clippy::type_complexity)]
    // Returns (sender_old, sender_new, receiver_old, receiver_new) which are the old and new deposit values for sender and receiver
    pub fn transaction(
        &mut self,
        sender: K,
        receiver: K,
        amount: Rep3PrimeFieldShare<F>,
        rep3_state: &mut Rep3State,
    ) -> eyre::Result<(
        DepositValue<F>,
        DepositValue<F>,
        Option<DepositValue<F>>,
        DepositValue<F>,
    )> {
        let (sender_old, sender_new) = self.withdraw(sender, amount, rep3_state)?;
        let (receiver_old, receiver_new) = self.deposit(receiver, amount, rep3_state);

        Ok((sender_old, sender_new, receiver_old, receiver_new))
    }
}
