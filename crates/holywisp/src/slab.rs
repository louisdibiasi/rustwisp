//! A generational slab. A token is `generation << 32 | index`, so an epoll event that arrives for
//! an entry released earlier in the same batch simply misses instead of hitting a reused slot.
//! A value can be `take`n out while it runs and `put` back after, with its token kept reserved.

#[derive(Debug)]
struct Slot<T> {
    generation: u32,
    live: bool,
    value: Option<T>,
}

#[derive(Debug)]
pub struct Slab<T> {
    slots: Vec<Slot<T>>,
    free: Vec<u32>,
    live: usize,
}

impl<T> Default for Slab<T> {
    fn default() -> Self {
        Slab {
            slots: Vec::new(),
            free: Vec::new(),
            live: 0,
        }
    }
}

fn split(token: u64) -> (usize, u32) {
    ((token & 0xFFFF_FFFF) as usize, (token >> 32) as u32)
}

impl<T> Slab<T> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.live
    }

    pub fn is_empty(&self) -> bool {
        self.live == 0
    }

    /// Reserve a token without a value yet; fill it with [`Slab::put`].
    pub fn reserve(&mut self) -> u64 {
        self.live += 1;
        if let Some(i) = self.free.pop() {
            let slot = &mut self.slots[i as usize];
            slot.live = true;
            return (u64::from(slot.generation) << 32) | u64::from(i);
        }
        let i = self.slots.len() as u32;
        self.slots.push(Slot {
            generation: 0,
            live: true,
            value: None,
        });
        u64::from(i)
    }

    pub fn insert(&mut self, value: T) -> u64 {
        let token = self.reserve();
        self.put(token, value);
        token
    }

    fn slot(&self, token: u64) -> Option<&Slot<T>> {
        let (i, generation) = split(token);
        self.slots
            .get(i)
            .filter(|s| s.live && s.generation == generation)
    }

    fn slot_mut(&mut self, token: u64) -> Option<&mut Slot<T>> {
        let (i, generation) = split(token);
        self.slots
            .get_mut(i)
            .filter(|s| s.live && s.generation == generation)
    }

    pub fn contains(&self, token: u64) -> bool {
        self.slot(token).is_some()
    }

    pub fn get(&self, token: u64) -> Option<&T> {
        self.slot(token)?.value.as_ref()
    }

    pub fn get_mut(&mut self, token: u64) -> Option<&mut T> {
        self.slot_mut(token)?.value.as_mut()
    }

    /// Move the value out and keep the token reserved.
    pub fn take(&mut self, token: u64) -> Option<T> {
        self.slot_mut(token)?.value.take()
    }

    pub fn put(&mut self, token: u64, value: T) {
        if let Some(slot) = self.slot_mut(token) {
            slot.value = Some(value);
        }
    }

    /// Free the token (whether or not its value is currently taken). Returns the value if present.
    pub fn release(&mut self, token: u64) -> Option<T> {
        let (i, _) = split(token);
        let slot = self.slot_mut(token)?;
        slot.live = false;
        slot.generation = slot.generation.wrapping_add(1);
        let value = slot.value.take();
        self.free.push(i as u32);
        self.live -= 1;
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_go_stale_after_release() {
        let mut s = Slab::new();
        let a = s.insert("a");
        assert_eq!(s.get(a), Some(&"a"));
        assert_eq!(s.release(a), Some("a"));
        assert!(s.get(a).is_none());
        let b = s.insert("b");
        assert_ne!(a, b, "a reused slot gets a new generation");
        assert!(s.get(a).is_none());
        assert_eq!(s.get(b), Some(&"b"));
    }

    #[test]
    fn take_keeps_the_token_reserved() {
        let mut s = Slab::new();
        let a = s.insert(1u32);
        assert_eq!(s.take(a), Some(1));
        assert!(s.get(a).is_none());
        assert!(s.contains(a));
        s.put(a, 2);
        assert_eq!(s.get(a), Some(&2));
        assert_eq!(s.len(), 1);
        assert_eq!(s.release(a), Some(2));
        assert!(s.is_empty());
    }

    #[test]
    fn release_while_taken_frees_the_slot() {
        let mut s = Slab::new();
        let a = s.insert(5u8);
        let _ = s.take(a);
        assert_eq!(s.release(a), None);
        assert!(!s.contains(a));
        s.put(a, 9);
        assert!(s.get(a).is_none(), "put on a dead token is ignored");
    }
}
