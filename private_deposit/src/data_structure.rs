use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use mpc_core::protocols::rep3::{self, Rep3PrimeFieldShare, Rep3State};
use rand::{CryptoRng, Rng};
use std::collections::{BTreeMap, HashMap};

pub type DepositValuePlain<F> = DepositValue<F>;
pub type DepositValueShare<F> = DepositValue<Rep3PrimeFieldShare<F>>;

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct DepositValue<V: CanonicalDeserialize + CanonicalSerialize + Clone> {
    pub amount: V,
    pub blinding: V,
}

impl<V: CanonicalDeserialize + CanonicalSerialize + Clone> DepositValue<V> {
    pub fn new(amount: V, blinding: V) -> Self {
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

impl<K, V> IntoIterator for PrivateDeposit<K, V> {
    type Item = (K, V);
    type IntoIter = std::collections::hash_map::IntoIter<K, V>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

impl<K, V> PrivateDeposit<K, V>
where
    K: std::hash::Hash + Eq,
{
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: HashMap::with_capacity(capacity),
        }
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

    pub fn into_inner(self) -> HashMap<K, V> {
        self.inner
    }

    pub fn inner(&self) -> &HashMap<K, V> {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut HashMap<K, V> {
        &mut self.inner
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

impl<K, F: PrimeField> PrivateDeposit<K, DepositValuePlain<F>>
where
    K: std::hash::Hash + Eq + Clone + Ord,
{
    pub fn share<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> [PrivateDeposit<K, DepositValueShare<F>>; 3] {
        let mut shares = [
            PrivateDeposit::<K, DepositValueShare<F>>::with_capacity(self.len()),
            PrivateDeposit::<K, DepositValueShare<F>>::with_capacity(self.len()),
            PrivateDeposit::<K, DepositValueShare<F>>::with_capacity(self.len()),
        ];
        let ordered_map = BTreeMap::from_iter(self.iter());
        for (key, values) in ordered_map.iter() {
            let [a1, a2, a3] = rep3::share_field_element(values.amount, rng);
            let [b1, b2, b3] = rep3::share_field_element(values.blinding, rng);
            shares[0].insert(key.to_owned().to_owned(), DepositValue::new(a1, b1));
            shares[1].insert(key.to_owned().to_owned(), DepositValue::new(a2, b2));
            shares[2].insert(key.to_owned().to_owned(), DepositValue::new(a3, b3));
        }
        shares
    }
}

impl<K, F: PrimeField> PrivateDeposit<K, DepositValueShare<F>>
where
    K: std::hash::Hash + Eq,
{
    // Returns the old and the new deposit value for the given key
    pub fn deposit(
        &mut self,
        key: K,
        amount: Rep3PrimeFieldShare<F>,
        rep3_state: &mut Rep3State,
    ) -> (Option<DepositValueShare<F>>, DepositValueShare<F>) {
        let new_blinding = rep3::arithmetic::rand(rep3_state);
        self.deposit_with_blinding(key, amount, new_blinding)
    }

    // Returns the old and the new balance value for the given key
    pub fn withdraw(
        &mut self,
        key: K,
        amount: Rep3PrimeFieldShare<F>,
        rep3_state: &mut Rep3State,
    ) -> eyre::Result<(DepositValueShare<F>, DepositValueShare<F>)> {
        let new_blinding = rep3::arithmetic::rand(rep3_state);
        self.withdraw_with_blinding(key, amount, new_blinding)
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
        DepositValueShare<F>,
        DepositValueShare<F>,
        Option<DepositValueShare<F>>,
        DepositValueShare<F>,
    )> {
        let sender_new_blinding = rep3::arithmetic::rand(rep3_state);
        let receiver_new_blinding = rep3::arithmetic::rand(rep3_state);
        self.transaction_with_blinding(
            sender,
            receiver,
            amount,
            sender_new_blinding,
            receiver_new_blinding,
        )
    }
}

impl<K, V> PrivateDeposit<K, DepositValue<V>>
where
    K: std::hash::Hash + Eq,
    V: CanonicalDeserialize
        + CanonicalSerialize
        + Clone
        + std::ops::Add<V, Output = V>
        + std::ops::Sub<V, Output = V>,
{
    // Returns the current deposit value for the given key
    pub fn read(&self, key: &K) -> Option<&DepositValue<V>> {
        self.get(key)
    }

    // Returns the old and the new deposit value for the given key
    pub fn deposit_with_blinding(
        &mut self,
        key: K,
        amount: V,
        new_blinding: V,
    ) -> (Option<DepositValue<V>>, DepositValue<V>) {
        let old = self.read(&key).cloned();
        let new_value = if let Some(old_value) = &old {
            old_value.amount.to_owned() + amount
        } else {
            amount
        };
        let new = DepositValue::new(new_value, new_blinding);
        self.insert(key, new.clone());
        (old, new)
    }

    // Returns the old and the new balance value for the given key
    pub fn withdraw_with_blinding(
        &mut self,
        key: K,
        amount: V,
        new_blinding: V,
    ) -> eyre::Result<(DepositValue<V>, DepositValue<V>)> {
        let old = self.get(&key);
        if old.is_none() {
            return Err(eyre::eyre!("Key not found in HashMap"));
        }
        let old = old.unwrap().clone();
        let new_amount = old.amount.to_owned() - amount;
        let new = DepositValue::new(new_amount, new_blinding);
        self.insert(key, new.clone());
        Ok((old, new))
    }

    #[expect(clippy::type_complexity)]
    // Returns (sender_old, sender_new, receiver_old, receiver_new) which are the old and new deposit values for sender and receiver
    pub fn transaction_with_blinding(
        &mut self,
        sender: K,
        receiver: K,
        amount: V,
        sender_new_blinding: V,
        receiver_new_blinding: V,
    ) -> eyre::Result<(
        DepositValue<V>,
        DepositValue<V>,
        Option<DepositValue<V>>,
        DepositValue<V>,
    )> {
        let (sender_old, sender_new) =
            self.withdraw_with_blinding(sender, amount.to_owned(), sender_new_blinding)?;
        let (receiver_old, receiver_new) =
            self.deposit_with_blinding(receiver, amount, receiver_new_blinding);

        Ok((sender_old, sender_new, receiver_old, receiver_new))
    }
}
