//! A byte queue: append at the tail, consume from the head, compact lazily.

#[derive(Debug, Default)]
pub struct Queue {
    data: Vec<u8>,
    head: usize,
}

impl Queue {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.data.len() - self.head
    }

    pub fn is_empty(&self) -> bool {
        self.head == self.data.len()
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data[self.head..]
    }

    pub fn push(&mut self, bytes: &[u8]) {
        if self.head > 0 && self.head >= self.data.len() / 2 && self.head >= 4096 {
            self.data.drain(..self.head);
            self.head = 0;
        }
        self.data.extend_from_slice(bytes);
    }

    /// Drop `n` bytes from the front.
    pub fn consume(&mut self, n: usize) {
        self.head = (self.head + n).min(self.data.len());
        if self.head == self.data.len() {
            self.data.clear();
            self.head = 0;
        }
    }

    pub fn clear(&mut self) {
        self.data.clear();
        self.head = 0;
    }

    /// Give back memory after a burst, once the queue is empty.
    pub fn shrink_if_idle(&mut self, keep: usize) {
        if self.is_empty() && self.data.capacity() > keep {
            self.data = Vec::new();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_consume_roundtrip() {
        let mut q = Queue::new();
        assert!(q.is_empty());
        q.push(b"hello ");
        q.push(b"world");
        assert_eq!(q.as_slice(), b"hello world");
        q.consume(6);
        assert_eq!(q.as_slice(), b"world");
        assert_eq!(q.len(), 5);
        q.consume(100);
        assert!(q.is_empty());
        assert_eq!(q.len(), 0);
    }

    #[test]
    fn compaction_keeps_order() {
        let mut q = Queue::new();
        let big: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
        q.push(&big);
        q.consume(15_000);
        q.push(b"tail");
        let mut expect = big[15_000..].to_vec();
        expect.extend_from_slice(b"tail");
        assert_eq!(q.as_slice(), &expect[..]);
    }
}
