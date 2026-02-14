use bytes::BytesMut;
use crossbeam::queue::ArrayQueue;
use lazy_static::lazy_static;

pub struct BufferPool {
    pool: ArrayQueue<BytesMut>,
    buffer_size: usize,
}

impl BufferPool {
    pub fn new(capacity: usize, buffer_size: usize) -> Self {
        let pool = ArrayQueue::new(capacity);
        
        // Pre-allocate buffers
        for _ in 0..capacity {
            let buf = BytesMut::with_capacity(buffer_size);
            let _ = pool.push(buf);
        }
        
        Self {
            pool,
            buffer_size,
        }
    }
    
    /// Get buffer from pool (or allocate new if pool empty)
    pub fn acquire(&self) -> BytesMut {
        self.pool.pop().unwrap_or_else(|| {
            // Pool exhausted, allocate new
            BytesMut::with_capacity(self.buffer_size)
        })
    }
    
    /// Return buffer to pool
    pub fn release(&self, mut buf: BytesMut) {
        buf.clear();  // Clear data
        
        // Return to pool if not full
        let _ = self.pool.push(buf);
        // If push fails (pool full), buffer is dropped
    }
}

// Global buffer pool
lazy_static! {
    pub static ref BUFFER_POOL: BufferPool = BufferPool::new(10_000, 64 * 1024);
}

pub fn get_buffer() -> BytesMut {
    BUFFER_POOL.acquire()
}

pub fn return_buffer(buf: BytesMut) {
    BUFFER_POOL.release(buf);
}
